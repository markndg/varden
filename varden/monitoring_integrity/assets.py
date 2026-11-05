"""Typed registry of security-critical monitoring assets.

Identity is canonical and inode-aware. A discovered path is not protected
unless the operator marks it protected. Symlinks, lexical traversal, and
replacement of the path itself are matches; a nearby temp file is not.
"""

from __future__ import annotations

import hashlib
import os
import sys
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from varden.runtime.filesystem import is_path_contained, resolve_filesystem_target

from .io_guard import internal_io

MAX_HASH_BYTES = 8 * 1024 * 1024


class AssetType(str, Enum):
    POLICY = "policy"
    ENFORCEMENT_CONFIG = "enforcement_config"
    CONTROL_PLANE_ENDPOINT = "control_plane_endpoint"
    AUDIT_STORAGE = "audit_storage"
    LOGGING_CONFIG = "logging_config"
    NOTIFICATION_DESTINATION = "notification_destination"
    MONITORING_INTEGRATION = "monitoring_integration"
    SECURITY_ENVIRONMENT = "security_environment"
    PROTECTED_EXECUTABLE = "protected_executable"
    COVERAGE_DECLARATION = "coverage_declaration"
    ATTESTATION_RECORD = "attestation_record"
    RUNTIME_INSTRUMENTATION = "runtime_instrumentation"
    APPLICATION = "application"


class VerificationState(str, Enum):
    VERIFIED = "verified"
    STALE = "stale"
    MISSING = "missing"
    MISMATCHED = "mismatched"
    UNKNOWN = "unknown"
    UNOBSERVABLE = "unobservable"
    UNPROTECTED = "unprotected"


KNOWN_ASSET_TYPES = frozenset(item.value for item in AssetType)

MUTATING_OPERATIONS = frozenset({
    "write",
    "append",
    "replace",
    "unlink",
    "rename",
    "symlink",
    "chmod",
    "exec",
    "env_set",
    "env_unset",
    "http_mutation",
    "mcp_call",
    "claim",
    "signal",
})


def path_key(path: str) -> str:
    """Comparison key. Case-folds where the platform filesystem does."""
    norm = os.path.normpath(path)
    if sys.platform == "darwin" or os.name == "nt":
        return norm.casefold()
    return norm


def file_digest(path: str) -> tuple[str | None, str | None]:
    """Return ``(sha256, error)``. Does not follow a final symlink component.

    The caller passes an already-resolved file path. A directory, a missing
    path, or a file above the hash cap is not hashed.
    """
    try:
        st = os.lstat(path)
    except OSError as exc:
        return None, f"unreadable:{exc.__class__.__name__}"
    if not os.path.isfile(path) or os.path.islink(path):
        # lstat + isfile follows. If the resolved path is a file, hash it.
        if not os.path.isfile(path):
            return None, "not_a_file"
    if st.st_size > MAX_HASH_BYTES:
        return None, "too_large"
    digest = hashlib.sha256()
    try:
        with internal_io():
            with open(path, "rb") as handle:
                while True:
                    block = handle.read(1024 * 1024)
                    if not block:
                        break
                    digest.update(block)
    except OSError as exc:
        return None, f"unreadable:{exc.__class__.__name__}"
    return digest.hexdigest(), None


@dataclass
class IntegrityField:
    """One structured property whose weakening is a monitoring failure."""

    path: str
    kind: str
    allow: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "kind": self.kind, "allow": list(self.allow)}


@dataclass
class Activation:
    """An executable prefix that applies a staged change to this asset.

    Compared as path-resolved argv prefixes, not as a free-text signature.
    """

    argv_prefix: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"argv_prefix": list(self.argv_prefix)}


@dataclass
class ToolGrant:
    id: str
    operations: tuple[str, ...]
    assets: tuple[str, ...]
    surface: str
    enforceable: bool = True
    sequence: int | None = None
    activation: bool = False
    authority_neutral: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "operations": list(self.operations),
            "assets": list(self.assets),
            "surface": self.surface,
            "enforceable": self.enforceable,
            "sequence": self.sequence,
            "activation": self.activation,
            "authority_neutral": self.authority_neutral,
        }


@dataclass
class MonitoringAsset:
    id: str
    asset_type: AssetType
    owner: str
    protected: bool
    permitted_operations: frozenset[str]
    evidence_source: str
    lexical_path: str | None = None
    effective_path: str | None = None
    device: int | None = None
    inode: int | None = None
    baseline_digest: str | None = None
    tree: bool = False
    env_keys: tuple[str, ...] = ()
    process_names: tuple[str, ...] = ()
    protected_pids: frozenset[int] = field(default_factory=frozenset)
    allowed_destinations: tuple[str, ...] = ()
    endpoint: str | None = None
    integrity_fields: tuple[IntegrityField, ...] = ()
    activations: tuple[Activation, ...] = ()
    exceptions: tuple[dict[str, Any], ...] = ()
    surfaces: tuple[str, ...] = ()
    required: bool = True
    verification: VerificationState = VerificationState.UNKNOWN
    verification_detail: str = ""
    notes: tuple[str, ...] = ()

    @property
    def identity(self) -> str:
        if self.effective_path:
            return f"fs:{path_key(self.effective_path)}"
        if self.lexical_path:
            return f"fs:{path_key(self.lexical_path)}"
        if self.env_keys:
            return "env:" + ",".join(sorted(self.env_keys))
        if self.endpoint:
            return f"url:{self.endpoint}"
        if self.process_names:
            return "process:" + ",".join(sorted(self.process_names))
        return f"asset:{self.id}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.asset_type.value,
            "owner": self.owner,
            "protected": self.protected,
            "identity": self.identity,
            "lexical_path": self.lexical_path,
            "effective_path": self.effective_path,
            "device": self.device,
            "inode": self.inode,
            "baseline_digest": self.baseline_digest,
            "tree": self.tree,
            "env_keys": list(self.env_keys),
            "process_names": list(self.process_names),
            "protected_pids": sorted(self.protected_pids),
            "allowed_destinations": list(self.allowed_destinations),
            "endpoint": self.endpoint,
            "integrity_fields": [item.to_dict() for item in self.integrity_fields],
            "activations": [item.to_dict() for item in self.activations],
            "exceptions": [dict(item) for item in self.exceptions],
            "permitted_operations": sorted(self.permitted_operations),
            "surfaces": list(self.surfaces),
            "evidence_source": self.evidence_source,
            "required": self.required,
            "verification": self.verification.value,
            "verification_detail": self.verification_detail,
            "notes": list(self.notes),
        }


@dataclass
class AssetMatch:
    asset: MonitoringAsset
    via: str
    supplied_path: str
    effective_path: str | None
    resolution: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset.id,
            "via": self.via,
            "supplied_path": self.supplied_path,
            "effective_path": self.effective_path,
            "resolution": self.resolution,
            "protected": self.asset.protected,
        }


def _stat_identity(path: str | None) -> tuple[int | None, int | None]:
    if not path:
        return None, None
    try:
        st = os.stat(path)
    except OSError:
        return None, None
    return st.st_dev, st.st_ino


def _capture_file(asset: MonitoringAsset) -> None:
    target_path = asset.lexical_path
    if not target_path:
        asset.verification = VerificationState.UNOBSERVABLE
        asset.verification_detail = "no path"
        return
    resolved = resolve_filesystem_target(target_path, operation="stat")
    asset.effective_path = resolved.effective_path
    if resolved.resolution == "resolution_failed" or not resolved.effective_path:
        asset.verification = VerificationState.UNOBSERVABLE
        asset.verification_detail = resolved.resolution_error or "resolution_failed"
        return
    dev, ino = _stat_identity(resolved.effective_path)
    asset.device, asset.inode = dev, ino
    if dev is None:
        asset.verification = VerificationState.MISSING
        asset.verification_detail = "path does not exist"
        asset.baseline_digest = None
        return
    if asset.tree or os.path.isdir(resolved.effective_path):
        asset.tree = True
        asset.verification = VerificationState.VERIFIED
        asset.verification_detail = "directory identity captured"
        return
    digest, error = file_digest(resolved.effective_path)
    if error:
        asset.verification = VerificationState.UNOBSERVABLE
        asset.verification_detail = error
        return
    asset.baseline_digest = digest
    asset.verification = VerificationState.VERIFIED
    asset.verification_detail = "baseline digest captured"


def _parse_fields(raw: Any) -> tuple[IntegrityField, ...]:
    fields: list[IntegrityField] = []
    if not isinstance(raw, list):
        return ()
    for item in raw:
        if isinstance(item, str):
            fields.append(IntegrityField(path=item, kind="equality"))
            continue
        if not isinstance(item, dict) or not item.get("path"):
            continue
        allow = item.get("allow") or item.get("allowed") or []
        fields.append(
            IntegrityField(
                path=str(item["path"]),
                kind=str(item.get("kind") or "equality"),
                allow=tuple(str(x) for x in allow),
            )
        )
    return tuple(fields)


def _parse_activations(raw: Any) -> tuple[Activation, ...]:
    found: list[Activation] = []
    if not isinstance(raw, list):
        return ()
    for item in raw:
        prefix = item.get("argv_prefix") if isinstance(item, dict) else item
        if isinstance(prefix, (list, tuple)) and prefix:
            found.append(Activation(tuple(str(part) for part in prefix)))
    return tuple(found)


def parse_asset(raw: dict[str, Any]) -> MonitoringAsset:
    if not isinstance(raw, dict):
        raise ValueError("asset must be an object")
    asset_id = str(raw.get("id") or "").strip()
    if not asset_id:
        raise ValueError("asset id is required")
    type_name = str(raw.get("type") or AssetType.APPLICATION.value)
    if type_name not in KNOWN_ASSET_TYPES:
        raise ValueError(f"unknown asset type {type_name!r}")
    permitted = raw.get("permitted_operations", ["read"])
    if not isinstance(permitted, list):
        raise ValueError(f"asset {asset_id} permitted_operations must be a list")
    path = raw.get("path")
    asset = MonitoringAsset(
        id=asset_id,
        asset_type=AssetType(type_name),
        owner=str(raw.get("owner") or "operator"),
        protected=bool(raw.get("protected", False)),
        permitted_operations=frozenset(str(item) for item in permitted),
        evidence_source=str(raw.get("evidence") or raw.get("evidence_source") or "operator_baseline"),
        lexical_path=str(path) if path else None,
        tree=bool(raw.get("tree", False)),
        env_keys=tuple(str(item) for item in (raw.get("env_keys") or [])),
        process_names=tuple(str(item) for item in (raw.get("process_names") or [])),
        protected_pids=frozenset(int(item) for item in (raw.get("protected_pids") or [])),
        allowed_destinations=tuple(str(item) for item in (raw.get("allowed_destinations") or [])),
        endpoint=str(raw["endpoint"]) if raw.get("endpoint") else None,
        integrity_fields=_parse_fields(raw.get("integrity_fields")),
        activations=_parse_activations(raw.get("activations")),
        exceptions=tuple(dict(item) for item in (raw.get("exceptions") or []) if isinstance(item, dict)),
        surfaces=tuple(str(item) for item in (raw.get("surfaces") or [])),
        required=bool(raw.get("required", True)),
        notes=tuple(str(item) for item in (raw.get("notes") or [])),
    )
    if not asset.protected:
        asset.verification = VerificationState.UNPROTECTED
        asset.verification_detail = "discovered or declared but not protected"
        return asset
    if asset.lexical_path:
        _capture_file(asset)
    elif asset.env_keys or asset.process_names or asset.endpoint or asset.protected_pids:
        asset.verification = VerificationState.VERIFIED
        asset.verification_detail = "identity declared by operator"
    else:
        asset.verification = VerificationState.UNOBSERVABLE
        asset.verification_detail = "protected asset has no path, endpoint, process, or environment identity"
    return asset


def parse_grant(raw: dict[str, Any]) -> ToolGrant:
    if not isinstance(raw, dict) or not raw.get("id"):
        raise ValueError("tool grant id is required")
    operations = tuple(str(item) for item in (raw.get("operations") or []))
    if not operations:
        raise ValueError(f"grant {raw['id']} needs operations")
    return ToolGrant(
        id=str(raw["id"]),
        operations=operations,
        assets=tuple(str(item) for item in (raw.get("assets") or ())),
        surface=str(raw.get("surface") or "unknown"),
        enforceable=bool(raw.get("enforceable", True)),
        sequence=int(raw["sequence"]) if raw.get("sequence") is not None else None,
        activation=bool(raw.get("activation", False)),
        authority_neutral=bool(raw.get("authority_neutral", False)),
    )


class AssetRegistry:
    """Process-local sealed catalogue. Not an OS security boundary."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.enabled = False
        self.mode = "off"
        self.fail_closed = True
        self.policy_version = ""
        self.protected_agents: frozenset[str] = frozenset()
        self.require_monitored_child = False
        self.attestation_max_age_s = 300.0
        self.invariants: tuple[str, ...] = ()
        self._assets: dict[str, MonitoringAsset] = {}
        self._grants: dict[str, ToolGrant] = {}
        self.generation = 0
        self._sealed = False
        self._seal_token: str | None = None
        self.evidence_path: str | None = None
        self.section_hash = ""

    def snapshot_config(self) -> dict[str, Any]:
        with self._lock:
            return {
                "enabled": self.enabled,
                "mode": self.mode,
                "fail_closed": self.fail_closed,
                "policy_version": self.policy_version,
                "protected_agents": set(self.protected_agents),
                "require_monitored_child": self.require_monitored_child,
                "attestation_max_age_s": self.attestation_max_age_s,
                "invariants": self.invariants,
                "assets": dict(self._assets),
                "grants": dict(self._grants),
                "generation": self.generation,
                "section_hash": self.section_hash,
            }

    def seal(self, token: str) -> None:
        with self._lock:
            self._sealed = True
            self._seal_token = token

    def _mutate(self, token: str | None) -> None:
        if self._sealed and token != self._seal_token:
            raise RuntimeError("monitoring integrity registry is sealed")
        self.generation += 1

    def load_section(self, section: dict[str, Any], *, token: str | None = None, section_hash: str = "") -> None:
        assets = [parse_asset(item) for item in (section.get("assets") or [])]
        grants = [parse_grant(item) for item in (section.get("grants") or section.get("tools") or [])]
        ids = [asset.id for asset in assets]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate monitoring asset id")
        mode = str(section.get("mode") or "guarded")
        with self._lock:
            self._mutate(token)
            self.enabled = bool(section.get("enabled", False)) and mode != "off"
            self.mode = mode
            self.fail_closed = bool(section.get("fail_closed", mode in {"guarded", "strict"}))
            self.policy_version = str(section.get("policy_version") or section.get("version") or section_hash[:16])
            agents = section.get("protected_agents") or section.get("protected_agent") or []
            if isinstance(agents, str):
                agents = [agents]
            self.protected_agents = frozenset(str(item) for item in agents)
            self.require_monitored_child = bool(section.get("require_monitored_child", False))
            self.attestation_max_age_s = float(section.get("attestation_max_age_s") or 300)
            requested = section.get("invariants")
            self.invariants = tuple(str(item) for item in requested) if requested else (
                "INV-001", "INV-002", "INV-003", "INV-004",
                "INV-005", "INV-006", "INV-007", "INV-008",
            )
            self._assets = {asset.id: asset for asset in assets}
            self._grants = {grant.id: grant for grant in grants}
            self.evidence_path = str(section["evidence_path"]) if section.get("evidence_path") else self.evidence_path
            self.section_hash = section_hash

    def assets(self) -> list[MonitoringAsset]:
        with self._lock:
            return list(self._assets.values())

    def grants(self) -> list[ToolGrant]:
        with self._lock:
            return list(self._grants.values())

    def get(self, asset_id: str) -> MonitoringAsset | None:
        with self._lock:
            return self._assets.get(asset_id)

    def refresh_verification(self, asset_id: str) -> VerificationState:
        """Re-read a file asset. Does not trust the agent."""
        with self._lock:
            asset = self._assets.get(asset_id)
            if asset is None:
                return VerificationState.UNKNOWN
            if not asset.protected:
                asset.verification = VerificationState.UNPROTECTED
                return asset.verification
            if not asset.lexical_path:
                return asset.verification
            resolved = resolve_filesystem_target(asset.lexical_path, operation="stat")
            if resolved.resolution == "resolution_failed" or not resolved.effective_path:
                asset.verification = VerificationState.UNOBSERVABLE
                asset.verification_detail = resolved.resolution_error or "resolution_failed"
                return asset.verification
            dev, ino = _stat_identity(resolved.effective_path)
            if dev is None:
                asset.verification = VerificationState.MISSING
                asset.verification_detail = "missing"
                return asset.verification
            if asset.device is not None and (dev != asset.device or ino != asset.inode):
                asset.verification = VerificationState.MISMATCHED
                asset.verification_detail = "inode changed since seal"
                return asset.verification
            if asset.tree:
                asset.verification = VerificationState.VERIFIED
                asset.verification_detail = "directory still present"
                return asset.verification
            digest, error = file_digest(resolved.effective_path)
            if error or digest is None:
                asset.verification = VerificationState.UNOBSERVABLE
                asset.verification_detail = error or "no digest"
                return asset.verification
            if asset.baseline_digest and digest != asset.baseline_digest:
                asset.verification = VerificationState.MISMATCHED
                asset.verification_detail = "content digest changed since seal"
                return asset.verification
            asset.verification = VerificationState.VERIFIED
            asset.verification_detail = "digest matches sealed baseline"
            return asset.verification

    def match_path(self, supplied: str) -> list[AssetMatch]:
        resolved = resolve_filesystem_target(supplied, operation="stat")
        lexical = path_key(resolved.absolute_lexical) if resolved.absolute_lexical else path_key(os.path.abspath(supplied))
        effective = path_key(resolved.effective_path) if resolved.effective_path else None
        dev, ino = _stat_identity(resolved.effective_path)
        matches: list[AssetMatch] = []
        with self._lock:
            assets = list(self._assets.values())
        for asset in assets:
            if not asset.lexical_path and not asset.effective_path:
                continue
            via = _path_via(asset, lexical=lexical, effective=effective, dev=dev, ino=ino, resolved_ok=resolved.resolution != "resolution_failed")
            if via is None:
                continue
            matches.append(
                AssetMatch(
                    asset=asset,
                    via=via,
                    supplied_path=supplied,
                    effective_path=resolved.effective_path,
                    resolution=resolved.resolution,
                )
            )
        return matches

    def match_env_key(self, key: str) -> list[MonitoringAsset]:
        text = str(key)
        with self._lock:
            return [asset for asset in self._assets.values() if text in asset.env_keys]

    def match_endpoint(self, canonical_url: str | None, host: str | None) -> list[MonitoringAsset]:
        found: list[MonitoringAsset] = []
        with self._lock:
            assets = list(self._assets.values())
        for asset in assets:
            if asset.endpoint and canonical_url and path_key(asset.endpoint.rstrip("/")) == path_key(canonical_url.rstrip("/")):
                found.append(asset)
                continue
            if asset.endpoint and host and asset.endpoint == host:
                found.append(asset)
        return found

    def match_process_name(self, name: str) -> list[MonitoringAsset]:
        base = os.path.basename(str(name))
        with self._lock:
            return [asset for asset in self._assets.values() if base in asset.process_names or str(name) in asset.process_names]

    def match_pid(self, pid: int) -> list[MonitoringAsset]:
        with self._lock:
            return [asset for asset in self._assets.values() if pid in asset.protected_pids]


def _path_via(
    asset: MonitoringAsset,
    *,
    lexical: str,
    effective: str | None,
    dev: int | None,
    ino: int | None,
    resolved_ok: bool,
) -> str | None:
    asset_lexical = path_key(asset.lexical_path) if asset.lexical_path else None
    asset_effective = path_key(asset.effective_path) if asset.effective_path else None
    if asset.device is not None and dev is not None and dev == asset.device and ino == asset.inode:
        if asset_lexical and lexical != asset_lexical:
            return "inode_via_other_path"
        return "inode"
    if asset_effective and effective and effective == asset_effective:
        if asset_lexical and lexical != asset_lexical:
            return "symlink_or_traversal"
        return "effective"
    if asset_lexical and lexical == asset_lexical:
        return "lexical"
    if asset.tree and resolved_ok:
        root = asset.effective_path or asset.lexical_path
        candidate = effective or lexical
        if root and candidate and (path_key(candidate) == path_key(root) or is_path_contained(candidate, root)):
            return "tree"
    if not resolved_ok and asset_lexical and lexical == asset_lexical:
        return "unresolved_lexical"
    return None
