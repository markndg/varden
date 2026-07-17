from __future__ import annotations
import json, time
from .db import connect

# Evaluation precedence, strongest to weakest. "require_approval" and
# "sanitise" are Web Shield additions (see docs/web-shield-policy.md):
# existing policies that never populate these buckets behave identically to
# before, since an empty/missing bucket is simply skipped.
MODES = ("block", "require_approval", "sanitise", "warn", "monitor", "allow")


class PolicyEngine:
    def __init__(self, db_path: str, initial_policy: dict | None = None):
        self.db_path = db_path
        self.policy = initial_policy or {"block": [], "warn": [], "monitor": [], "allow": []}

    def get_policy(self): return self.policy
    def update_policy(self, policy): self.policy = policy

    def validate(self, policy):
        errors = []
        if not isinstance(policy, dict):
            return {"valid": False, "errors": ["policy must be an object"]}
        for mode in MODES:
            rules = policy.get(mode, [])
            if not isinstance(rules, list):
                errors.append(f"{mode} must be a list")
                continue
            for idx, rule in enumerate(rules):
                if not isinstance(rule, dict):
                    errors.append(f"{mode}[{idx}] must be an object")
                    continue
                if not rule:
                    errors.append(f"{mode}[{idx}] cannot be empty")
                    continue
                predicate_keys = [
                    key for key, expected in rule.items()
                    if key not in {"enabled", "priority", "description", "reason", "title", "name"}
                    and expected is not None
                    and expected != ""
                ]
                if not predicate_keys:
                    errors.append(f"{mode}[{idx}] must include at least one match condition")
        from .rules.registry import validate_budget_rules

        errors.extend(validate_budget_rules(policy))
        return {"valid": len(errors) == 0, "errors": errors}

    def templates(self):
        sql_tools = ["sql.query", "sql.execute", "db.query", "db.execute", "database.query", "database.execute", "postgres.query", "mysql.query", "sqlite.query", "psycopg.execute", "cursor.execute", "sqlalchemy.execute"]
        return {
            "block_destructive_commands": {"block": [
                {"type":"tool_call","tool":"subprocess.run","field:args.args":{"contains":"delete_database"}},
                {"type":"tool_call","tool":"subprocess.Popen","field:args.args":{"contains":"delete_database"}},
                {"type":"tool_call","tool":"subprocess.run","field:args.args":{"contains":"rm -rf"}},
                {"type":"tool_call","tool":"subprocess.Popen","field:args.args":{"contains":"terraform destroy"}},
                {"type":"tool_call","tool":"delete_database"}
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
            validation = self.validate(candidate)
            if not validation["valid"]:
                return {"published_version": None, "error": "invalid policy", "validation": validation}
            conn.execute("UPDATE policy_versions SET status = 'archived' WHERE status = 'published'")
            conn.execute("UPDATE policy_versions SET status = 'published' WHERE id = ?", (version_id,))
            conn.commit()
        self.update_policy(candidate)
        if policy_file:
            from .fsutil import atomic_write_json

            atomic_write_json(policy_file, candidate)
        return {"published_version": version_id, "policy": candidate}

    def evaluate(self, action):
        from .models import Decision
        for mode in MODES:
            for rule in self.policy.get(mode, []):
                if isinstance(rule, dict) and rule.get("enabled") is False:
                    continue
                if self._matches(action, rule):
                    return Decision(action=mode, reason=f"matched {mode} rule", matched_rule=rule, effective_action=mode)
        return Decision(action="allow", reason="no matching rule", matched_rule=None, effective_action="allow")

    def _matches(self, action, rule):
        has_predicate = False
        for key, expected in rule.items():
            if key in {"enabled", "priority", "description", "reason", "title", "name"}:
                continue
            if expected is None or expected == "":
                continue
            has_predicate = True
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
            if key in {"enabled", "priority", "description", "reason", "title", "name"}:
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
        original = self.policy
        self.policy = candidate_policy
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
        try:
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
                decision = self.evaluate(action)
                matched_rule = decision.matched_rule
                counts[decision.action] = counts.get(decision.action, 0) + 1
                simulated_status = _normalize_status(decision.action)
                original_status = _normalize_status(row.get("status"))
                results.append({
                    "event_id": row.get("id"),
                    "original_status": original_status,
                    "simulated_status": simulated_status,
                    "matched_rule": matched_rule,
                    "explanations": self.explain_match(action, matched_rule) if matched_rule else [],
                    "changed": original_status != simulated_status,
                })
            return {"results": results, "summary": counts}
        finally:
            self.policy = original

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
