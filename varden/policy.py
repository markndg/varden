from __future__ import annotations
import copy
import difflib
import json
import threading
import time
from .command_match import action_matches_command, validate_command_spec
from .db import connect

# Evaluation precedence, strongest to weakest. "require_approval" and
# "sanitise" are Web Shield additions (see docs/web-shield-policy.md):
# existing policies that never populate these buckets behave identically to
# before, since an empty/missing bucket is simply skipped.
MODES = ("block", "require_approval", "sanitise", "warn", "monitor", "allow")

# Decisions usable as a fallback when no rule matches (see docs/policy-engine.md).
DEFAULT_DECISIONS = ("block", "require_approval", "warn", "monitor", "allow")

# Rule keys that describe a rule rather than constrain it.
RULE_META_KEYS = frozenset({"enabled", "priority", "description", "reason", "title", "name", "id", "tags"})

# Action attributes a rule may reference directly or as ``field:<name>``.
ACTION_FIELDS = frozenset({
    "type", "tool", "method", "url", "domain", "args", "metadata", "classifiers",
    "risk_score", "risk_reasons", "agent_name", "workflow_id", "parent_event_id",
    "trace_id", "route_target", "tenant_id",
})

# Free-form nested paths (anything below these is caller-defined).
NESTED_PREFIXES = ("args.", "metadata.")

KNOWN_CLASSIFIERS = frozenset({
    # varden.classification.ClassifierEngine
    "pii", "credit_card", "financial", "secrets", "internal", "unsafe_keywords",
    "source_internal", "sensitive", "sql_query", "sql_dangerous", "sql_write",
    "sql_unbounded_write", "sql_privilege_change", "sql_schema_enumeration",
    "sql_select_star", "sql_missing_limit", "sql_union_access",
    "sql_comment_obfuscation", "sql_multi_statement", "sql_sensitive_table",
    "sql_suspect",
    # varden.provenance.engine
    "provenance_untrusted", "provenance_unknown", "authority_violation",
    "authority_escalation", "confused_deputy", "exfiltration_chain",
    "cross_server_flow", "untrusted_to_privileged",

    # varden.predictive_authority
    "credential_acquired",
    "untrusted_to_external_path",
    "cross_trust_domain_path",
    "irreversible_action_reachable",
    "authority_expands",
})

OPERATORS = frozenset({"exists", "eq", "contains", "startswith", "endswith", "in", "gte", "lte"})

KNOWN_ACTION_TYPES = frozenset({
    "tool_call", "http_request", "llm_call", "filesystem", "mcp_call",
    "webmcp.tool_registered", "webmcp.tool_invocation_requested", "webmcp.tool_output_scanned",
    "webmcp.extension_tamper_detected", "webmcp.tool_registration_changed",
    "webmcp.context_replaced", "webmcp.surface_changed", "webmcp.cross_origin_flow",
})

POLICY_TOP_LEVEL_KEYS = frozenset(MODES) | frozenset({
    "budget_rules", "default", "defaults", "version", "name", "description",
    "pack_name", "metadata", "id", "updated_at", "allow_vacuous_policy",
})


def _suggest(word: str, choices) -> str:
    match = difflib.get_close_matches(word, sorted(choices), n=1, cutoff=0.75)
    return f" (did you mean {match[0]!r}?)" if match else ""


def action_surface(action) -> str | None:
    """The runtime surface an action belongs to (subprocess, http, filesystem, ...)."""
    meta = getattr(action, "metadata", None) or {}
    if isinstance(meta, dict):
        runtime = meta.get("runtime")
        if isinstance(runtime, dict) and runtime.get("surface"):
            return str(runtime["surface"])
        if meta.get("execution_surface"):
            return str(meta["execution_surface"])
    return None


# Buckets that must be present on publish/replace so clients cannot omit keys
# and silently wipe rules (PUT is full-document replace, not PATCH).
PUBLISH_REQUIRED_BUCKETS = ("block", "warn", "monitor", "allow")


class PolicyEngine:
    def __init__(self, db_path: str, initial_policy: dict | None = None):
        self.db_path = db_path
        self._lock = threading.RLock()
        # Always store a private deep copy so callers cannot mutate live policy
        # via a retained get_policy()/update_policy argument reference.
        self.policy = copy.deepcopy(
            initial_policy or {"block": [], "warn": [], "monitor": [], "allow": []}
        )

    def get_policy(self):
        with self._lock:
            return copy.deepcopy(self.policy)

    def update_policy(self, policy):
        """Atomically replace the live policy with a deep copy of ``policy``.

        Rejects non-dict payloads. Callers that need validation must run
        ``validate()`` first (HTTP PUT /policy does). In-process updates from
        trusted control-plane code still go through a coherent snapshot so
        concurrent ``evaluate`` calls never observe a half-written document.
        """
        if not isinstance(policy, dict):
            raise TypeError("policy must be a dict")
        snapshot = copy.deepcopy(policy)
        with self._lock:
            self.policy = snapshot

    def validate(self, policy, *, for_publish: bool = False):
        """Validate a policy document.

        Errors make the policy unpublishable. The main job is to catch rules
        that would silently never fire: misspelled fields, unknown classifiers,
        unknown operators and misspelled bucket names all used to be accepted
        and then matched nothing.

        When ``for_publish=True`` (PUT /policy, import-pack, publish), also
        refuse missing core buckets and vacuous allow-all documents unless the
        operator sets ``allow_vacuous_policy: true``.
        """
        errors: list[str] = []
        warnings: list[str] = []
        if not isinstance(policy, dict):
            return {"valid": False, "errors": ["policy must be an object"], "warnings": []}
        for key in policy:
            if key in POLICY_TOP_LEVEL_KEYS:
                continue
            hint = _suggest(str(key), POLICY_TOP_LEVEL_KEYS)
            if hint:
                errors.append(f"unknown top-level key {key!r}{hint}")
            else:
                warnings.append(f"unknown top-level key {key!r} is ignored")
        for mode in MODES:
            rules = policy.get(mode, [])
            if mode in policy and not isinstance(rules, list):
                errors.append(f"{mode} must be a list")
                continue
            if not isinstance(rules, list):
                continue
            for idx, rule in enumerate(rules):
                where = f"{mode}[{idx}]"
                if not isinstance(rule, dict):
                    errors.append(f"{where} must be an object")
                    continue
                if not rule:
                    errors.append(f"{where} cannot be empty")
                    continue
                predicate_keys = [
                    key for key, expected in rule.items()
                    if key not in RULE_META_KEYS
                    and expected is not None
                    and expected != ""
                ]
                if not predicate_keys:
                    errors.append(f"{where} must include at least one match condition")
                    continue
                for key in predicate_keys:
                    errors.extend(self._validate_predicate(where, key, rule[key], warnings))
        errors.extend(self._validate_defaults(policy))
        from .rules.registry import validate_budget_rules

        errors.extend(validate_budget_rules(policy))
        if for_publish:
            errors.extend(self._validate_publish_integrity(policy))
        return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings}

    @staticmethod
    def _validate_publish_integrity(policy: dict) -> list[str]:
        """Extra checks for live replace paths (not simulate/startup soft paths)."""
        errors: list[str] = []
        for bucket in PUBLISH_REQUIRED_BUCKETS:
            if bucket not in policy:
                errors.append(
                    f"missing required top-level key {bucket!r}; "
                    "PUT replaces the full document — send an explicit empty list if intentional"
                )
            elif not isinstance(policy.get(bucket), list):
                errors.append(f"{bucket} must be a list")
        if PolicyEngine._is_vacuous_allow_all(policy):
            errors.append(
                "vacuous policy refused: no rules in any enforcement bucket and default "
                "decision is allow; set allow_vacuous_policy=true to confirm, or set "
                "default/defaults to a deny posture"
            )
        return errors

    @staticmethod
    def _is_vacuous_allow_all(policy: dict) -> bool:
        if policy.get("allow_vacuous_policy") is True:
            return False
        meta = policy.get("metadata")
        if isinstance(meta, dict) and meta.get("allow_vacuous_policy") is True:
            return False
        has_rules = any(
            isinstance(policy.get(mode), list) and len(policy.get(mode) or []) > 0
            for mode in MODES
        )
        if has_rules:
            return False
        default = policy.get("default")
        if default in DEFAULT_DECISIONS and default != "allow":
            return False
        defaults = policy.get("defaults") if isinstance(policy.get("defaults"), dict) else {}
        for value in defaults.values():
            if value in DEFAULT_DECISIONS and value != "allow":
                return False
        # No rules and no deny-by-default → silent allow-all wipe.
        return True

    @staticmethod
    def _field_problem(key: str) -> str | None:
        """Return an error message if ``key`` can never resolve on an Action."""
        if key in ("min_risk_score", "command"):
            return None
        if key.startswith("classifier:"):
            name = key.split(":", 1)[1]
            if name in KNOWN_CLASSIFIERS:
                return None
            return f"unknown classifier {name!r}{_suggest(name, KNOWN_CLASSIFIERS)}"
        path = key.split("field:", 1)[1] if key.startswith("field:") else key
        if path in ACTION_FIELDS:
            return None
        if any(path.startswith(prefix) and len(path) > len(prefix) for prefix in NESTED_PREFIXES):
            return None
        candidates = set(ACTION_FIELDS) | {"min_risk_score", "command"} | {f"classifier:{c}" for c in KNOWN_CLASSIFIERS}
        return f"unknown field {key!r}{_suggest(path, candidates)}; use an action field, 'args.<path>', 'metadata.<path>', 'classifier:<name>' or 'command'"

    def _validate_predicate(self, where: str, key: str, expected, warnings: list[str]) -> list[str]:
        errors: list[str] = []
        problem = self._field_problem(str(key))
        if problem:
            return [f"{where}: {problem}"]
        if key == "command":
            return validate_command_spec(expected, where)
        if key == "min_risk_score":
            try:
                float(expected)
            except (TypeError, ValueError):
                errors.append(f"{where}: min_risk_score must be a number")
            return errors
        if key in ("type", "field:type") and isinstance(expected, str) and expected not in KNOWN_ACTION_TYPES:
            warnings.append(f"{where}: action type {expected!r} is not one Varden emits{_suggest(expected, KNOWN_ACTION_TYPES)}")
        if isinstance(expected, dict):
            if not expected:
                errors.append(f"{where}.{key}: operator object cannot be empty")
            for op, value in expected.items():
                if op not in OPERATORS:
                    errors.append(f"{where}.{key}: unknown operator {op!r}{_suggest(str(op), OPERATORS)}; allowed {sorted(OPERATORS)}")
                    continue
                if op in ("gte", "lte"):
                    try:
                        float(value)
                    except (TypeError, ValueError):
                        errors.append(f"{where}.{key}: {op} needs a number")
                elif op == "exists":
                    if not isinstance(value, bool):
                        errors.append(f"{where}.{key}: exists needs true or false")
                elif op == "in":
                    values = value if isinstance(value, (list, tuple)) else [value]
                    if not [v for v in values if v not in (None, "")]:
                        errors.append(f"{where}.{key}: in needs at least one value")
                elif value in (None, ""):
                    errors.append(f"{where}.{key}: {op} needs a non-empty value")
        elif isinstance(expected, list):
            errors.append(f"{where}.{key}: lists are not matched directly; use {{\"in\": [...]}}")
        return errors

    @staticmethod
    def _validate_defaults(policy) -> list[str]:
        errors: list[str] = []
        if "default" in policy and policy["default"] not in DEFAULT_DECISIONS:
            errors.append(f"default must be one of {list(DEFAULT_DECISIONS)}")
        if "defaults" in policy:
            defaults = policy["defaults"]
            if not isinstance(defaults, dict):
                errors.append("defaults must be an object mapping surface or action type to a decision")
            else:
                for surface, decision in defaults.items():
                    if decision not in DEFAULT_DECISIONS:
                        errors.append(f"defaults.{surface} must be one of {list(DEFAULT_DECISIONS)}")
        return errors

    def templates(self):
        sql_tools = ["sql.query", "sql.execute", "db.query", "db.execute", "database.query", "database.execute", "postgres.query", "mysql.query", "sqlite.query", "psycopg.execute", "cursor.execute", "sqlalchemy.execute"]
        return {
            "block_destructive_commands": {"block": [
                {"type":"tool_call","tool":"subprocess.run","field:args.args":{"contains":"delete_database"}},
                {"type":"tool_call","tool":"subprocess.Popen","field:args.args":{"contains":"delete_database"}},
                {"type":"tool_call","tool":"subprocess.run","field:args.args":{"contains":"rm -rf"}},
                {"type":"tool_call","tool":"subprocess.Popen","field:args.args":{"contains":"terraform destroy"}},
                {"type":"tool_call","tool":"delete_database"},
                # Argv-aware equivalents: survive `rm -fr`, `rm -r -f`, `/bin/rm`, `sudo`, `sh -c`.
                {"type":"tool_call","command":{"program":"rm","flags_all":[["r","R","recursive"],["f","force"]]}},
                {"type":"tool_call","command":{"program":["terraform","tofu"],"subcommand":"destroy"}}
            ],"warn":[],"monitor":[],"allow":[]},
            "warn_internal_and_secret_data": {"block":[],"warn":[{"classifier:internal": True},{"classifier:secrets": True},{"classifier:source_internal": True}],"monitor":[],"allow":[]},
            "block_cardholder_data_exfiltration": {"block":[{"type":"http_request","classifier:credit_card": True},{"type":"llm_call","classifier:credit_card": True},{"type":"http_request","classifier:financial": True,"field:domain":{"exists": True}}],"warn":[],"monitor":[],"allow":[]},
            "warn_high_risk_llm": {"block":[],"warn":[{"type":"llm_call","field:risk_score":{"gte":60}}],"monitor":[],"allow":[]},
            "block_cloud_metadata_access": {"block":[{"type":"http_request","field:url":{"contains":"169.254.169.254"}},{"type":"http_request","field:url":{"contains":"metadata.google.internal"}},{"type":"http_request","field:url":{"contains":"latest/meta-data"}}],"warn":[],"monitor":[],"allow":[]},
            "warn_suspicious_sequences": {"block":[],"warn":[{"field:metadata.behavior.suspicious_sequence": True},{"field:metadata.behavior.previous_blocked": True,"type":"http_request"}],"monitor":[],"allow":[]},
            "block_dangerous_database_operations": {
                "block": [
                    {"type":"tool_call","field:tool":{"in": sql_tools},"classifier:sql_dangerous": True},
                    {"type":"tool_call","field:tool":{"in": sql_tools},"classifier:sql_unbounded_write": True},
                    {"type":"tool_call","field:tool":{"in": sql_tools},"classifier:sql_privilege_change": True},
                    {"type":"tool_call","field:tool":{"in": sql_tools},"classifier:sql_multi_statement": True}
                ],
                "warn": [
                    {"type":"tool_call","field:tool":{"in": sql_tools},"classifier:sql_schema_enumeration": True},
                    {"type":"tool_call","field:tool":{"in": sql_tools},"classifier:sql_sensitive_table": True},
                    {"type":"tool_call","field:tool":{"in": sql_tools},"classifier:sql_union_access": True},
                    {"type":"tool_call","field:tool":{"in": sql_tools},"classifier:sql_select_star": True},
                    {"type":"tool_call","field:tool":{"in": sql_tools},"classifier:sql_missing_limit": True}
                ],
                "monitor": [{"type":"tool_call","field:tool":{"in": sql_tools}}],
                "allow": []
            },
            "warn_suspect_sql_operations": {
                "block": [],
                "warn": [
                    {"classifier:sql_suspect": True},
                    {"classifier:sql_comment_obfuscation": True}
                ],
                "monitor": [{"classifier:sql_query": True}],
                "allow": []
            }
        }

    def snapshot(self, version_name: str, created_by: str = "system", status: str = "draft"):
        with connect(self.db_path) as conn:
            cur = conn.execute(
                "INSERT INTO policy_versions(created_at,created_by,version_name,policy_json,status) VALUES (?,?,?,?,?)",
                (time.time(), created_by, version_name, json.dumps(self.policy, ensure_ascii=False), status),
            )
            conn.commit()
            return int(cur.lastrowid)

    def list_versions(self, limit: int = 20):
        with connect(self.db_path) as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM policy_versions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]


    def requires_classifiers(self):
        for mode in MODES:
            for rule in self.policy.get(mode, []):
                if any(str(k).startswith("classifier:") for k in rule):
                    return True
        return False

    def requires_risk(self):
        risk_keys = {"min_risk_score", "field:risk_score", "field:metadata.scan.depth", "field:metadata.decision_latency_ms", "field:metadata.behavior.suspicious_sequence", "field:metadata.behavior.previous_blocked", "classifier:sql_query", "classifier:sql_dangerous", "classifier:sql_unbounded_write", "classifier:sql_privilege_change", "classifier:sql_schema_enumeration", "classifier:sql_sensitive_table", "classifier:sql_union_access", "classifier:sql_select_star", "classifier:sql_missing_limit", "classifier:sql_multi_statement", "classifier:sql_comment_obfuscation", "classifier:sql_suspect"}
        for mode in MODES:
            for rule in self.policy.get(mode, []):
                for key in rule:
                    if key in risk_keys or str(key).endswith("risk_score"):
                        return True
        return False

    def publish(self, version_id: int, policy_file: str | None = None):
        with connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT id, policy_json FROM policy_versions WHERE id = ?",
                (version_id,),
            ).fetchone()
            if not row:
                return {"published_version": None, "error": "version not found"}
            try:
                candidate = json.loads(row["policy_json"])
            except json.JSONDecodeError:
                return {"published_version": None, "error": "corrupt policy_json in version"}
            validation = self.validate(candidate, for_publish=True)
            if not validation["valid"]:
                return {"published_version": None, "error": "invalid policy", "validation": validation}
            if policy_file:
                from .fsutil import atomic_write_json

                try:
                    atomic_write_json(policy_file, candidate)
                except Exception as exc:
                    return {
                        "published_version": None,
                        "error": f"policy file write failed: {exc}",
                        "validation": validation,
                    }
            conn.execute("UPDATE policy_versions SET status = 'archived' WHERE status = 'published'")
            conn.execute("UPDATE policy_versions SET status = 'published' WHERE id = ?", (version_id,))
            conn.commit()
        self.update_policy(candidate)
        return {"published_version": version_id, "policy": candidate}

    def evaluate(self, action, *, policy_doc: dict | None = None):
        from .models import Decision

        if policy_doc is not None:
            policy = policy_doc
        else:
            with self._lock:
                # Hold a stable reference for the duration of matching so a concurrent
                # update_policy() cannot tear the rule lists mid-evaluation.
                policy = self.policy

        for mode in MODES:
            for rule in policy.get(mode, []) or []:
                if not isinstance(rule, dict) or rule.get("enabled") is False:
                    continue

                if self._matches(action, rule):
                    return Decision(
                        action=mode,
                        reason=_rule_match_reason(mode, rule),
                        matched_rule=rule,
                        effective_action=mode,
                    )

        fallback, scope = self.default_decision(action, policy)

        if fallback == "allow" and scope is None:
            return Decision(
                action="allow",
                reason="no matching rule",
                matched_rule=None,
                effective_action="allow",
            )

        return Decision(
            action=fallback,
            reason=f"no matching rule; default {fallback} for {scope}",
            matched_rule=None,
            effective_action=fallback,
        )

    @staticmethod
    def default_decision(action, policy) -> tuple[str, str | None]:
        """Fallback when no rule matches: defaults[surface] > defaults[type] > default > allow."""
        defaults = policy.get("defaults") if isinstance(policy.get("defaults"), dict) else {}

        surface = action_surface(action)
        if surface and defaults.get(surface) in DEFAULT_DECISIONS:
            return defaults[surface], f"surface {surface!r}"

        action_type = getattr(action, "type", None)
        if action_type and defaults.get(action_type) in DEFAULT_DECISIONS:
            return defaults[action_type], f"action type {action_type!r}"

        if policy.get("default") in DEFAULT_DECISIONS:
            return policy["default"], "policy"

        return "allow", None

    def _matches(self, action, rule):
        has_predicate = False
        for key, expected in rule.items():
            if key in RULE_META_KEYS:
                continue
            if expected is None or expected == "":
                continue
            has_predicate = True
            if key == "command":
                if not isinstance(expected, dict) or not action_matches_command(action, expected):
                    return False
                continue
            if key == "min_risk_score":
                # Threshold, not equality: {"min_risk_score": 60} matches 60..100.
                try:
                    if float(getattr(action, "risk_score", 0) or 0) < float(expected):
                        return False
                except (TypeError, ValueError):
                    return False
                continue
            actual = self._get_field(action, key)
            if isinstance(expected, dict):
                if not self._match_operator(actual, expected):
                    return False
                continue
            if actual is None:
                return False
            if isinstance(expected, bool):
                if bool(actual) is not expected:
                    return False
            else:
                if str(actual).lower() != str(expected).lower():
                    return False
        return has_predicate

    def _contains_deep(self, actual, needle):
        if actual is None:
            return False
        needle_s = str(needle).lower()
        if isinstance(actual, dict):
            return any(self._contains_deep(v, needle_s) for v in actual.values())
        if isinstance(actual, (list, tuple, set)):
            return any(self._contains_deep(v, needle_s) for v in actual)
        return needle_s in str(actual).lower()

    def _match_operator(self, actual, spec):
        matched_operator = False
        for operator, expected_value in spec.items():
            matched_operator = True
            if operator == 'exists':
                if (actual is not None) is not bool(expected_value):
                    return False
                continue
            if actual is None:
                return False
            if operator == 'eq':
                if expected_value is None or expected_value == "" or str(actual).lower() != str(expected_value).lower():
                    return False
                continue
            if operator == 'contains':
                if expected_value is None or expected_value == "" or not self._contains_deep(actual, expected_value):
                    return False
                continue
            if operator == 'startswith':
                if expected_value is None or expected_value == "" or not str(actual).lower().startswith(str(expected_value).lower()):
                    return False
                continue
            if operator == 'endswith':
                if expected_value is None or expected_value == "" or not str(actual).lower().endswith(str(expected_value).lower()):
                    return False
                continue
            if operator == 'in':
                values = expected_value if isinstance(expected_value, (list, tuple, set)) else [expected_value]
                expected = {str(v).lower() for v in values if v is not None and v != ""}
                if not expected:
                    return False
                if isinstance(actual, (list, tuple, set)):
                    if not any(str(v).lower() in expected for v in actual):
                        return False
                elif str(actual).lower() not in expected:
                    return False
                continue
            if operator == 'gte':
                try:
                    if float(actual) < float(expected_value):
                        return False
                except (TypeError, ValueError):
                    return False
                continue
            if operator == 'lte':
                try:
                    if float(actual) > float(expected_value):
                        return False
                except (TypeError, ValueError):
                    return False
                continue
            return False
        return matched_operator



    def explain_match(self, action, rule):
        matched = []
        for key, expected in (rule or {}).items():
            if key in RULE_META_KEYS:
                continue
            if key == "command":
                if isinstance(expected, dict) and action_matches_command(action, expected):
                    from .command_match import extract_commands
                    matched.append({"field": "command", "operator": "command", "expected": expected, "actual": extract_commands(action)})
                continue
            if key == "min_risk_score":
                actual = getattr(action, "risk_score", 0)
                try:
                    if float(actual or 0) >= float(expected):
                        matched.append({"field": key, "operator": "gte", "expected": expected, "actual": actual})
                except (TypeError, ValueError):
                    pass
                continue
            actual = self._get_field(action, key)
            if isinstance(expected, dict):
                if self._match_operator(actual, expected):
                    matched.append({"field": key, "operator": list(expected.keys())[0], "expected": list(expected.values())[0], "actual": actual})
                continue
            if isinstance(expected, bool):
                if bool(actual) is expected:
                    matched.append({"field": key, "operator": "eq", "expected": expected, "actual": actual})
            elif actual is not None and str(actual).lower() == str(expected).lower():
                matched.append({"field": key, "operator": "eq", "expected": expected, "actual": actual})
        return matched

    def simulate_trace(self, trace_events, candidate_policy):
        # Evaluate on a private engine. Swapping self.policy in place (as this
        # used to) let live /sdk/guard decisions on other threads run against
        # the unpublished candidate for the duration of the simulation.
        sim = PolicyEngine(self.db_path, candidate_policy)
        results = []
        counts = {"block": 0, "warn": 0, "allow": 0, "monitor": 0}
        def _normalize_status(value):
            text = str(value or "").strip().lower()
            if text in {"block", "blocked"}:
                return "blocked"
            if text in {"warn", "warned"}:
                return "warned"
            if text == "monitor":
                return "monitor"
            return "allowed"
        from .models import Action
        for row in trace_events:
            action_data = dict(row.get("action") or {})
            action = Action(
                type=action_data.get("type", "tool_call"),
                tool=action_data.get("tool"),
                method=action_data.get("method"),
                url=action_data.get("url"),
                domain=action_data.get("domain"),
                args=action_data.get("args") or {},
                metadata=action_data.get("metadata") or {},
                classifiers=action_data.get("classifiers") or {},
                risk_score=int(action_data.get("risk_score") or 0),
                risk_reasons=list(action_data.get("risk_reasons") or []),
                agent_name=action_data.get("agent_name"),
                workflow_id=action_data.get("workflow_id"),
                parent_event_id=action_data.get("parent_event_id"),
                trace_id=action_data.get("trace_id"),
                route_target=action_data.get("route_target"),
                tenant_id=action_data.get("tenant_id"),
            )
            decision = sim.evaluate(action)
            matched_rule = decision.matched_rule
            counts[decision.action] = counts.get(decision.action, 0) + 1
            simulated_status = _normalize_status(decision.action)
            original_status = _normalize_status(row.get("status"))
            results.append({
                "event_id": row.get("id"),
                "original_status": original_status,
                "simulated_status": simulated_status,
                "matched_rule": matched_rule,
                "explanations": sim.explain_match(action, matched_rule) if matched_rule else [],
                "changed": original_status != simulated_status,
            })
        return {"results": results, "summary": counts}

    def _get_field(self, action, key):
        if key.startswith('field:'):
            key = key.split('field:', 1)[1]
        if hasattr(action, key):
            return getattr(action, key)
        if key.startswith("classifier:"):
            return getattr(action, "classifiers", {}).get(key.split("classifier:", 1)[1])
        if key == "min_risk_score":
            return getattr(action, "risk_score", 0)
        if key.startswith('metadata.'):
            cur = getattr(action, 'metadata', {})
            for part in key.split('.')[1:]:
                if not isinstance(cur, dict):
                    return None
                cur = cur.get(part)
            return cur
        if key.startswith('args.'):
            cur = getattr(action, 'args', {})
            for part in key.split('.')[1:]:
                if isinstance(cur, dict):
                    cur = cur.get(part)
                else:
                    return None
            return cur
        return None


def _rule_match_reason(mode: str, rule: dict) -> str:
    """Prefer operator-facing rule copy over the opaque ``matched {mode} rule`` stub."""
    if not isinstance(rule, dict):
        return f"matched {mode} rule"
    for key in ("reason", "title", "description", "name", "id"):
        text = str(rule.get(key) or "").strip()
        if text:
            return text
    return f"matched {mode} rule"
