from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import os

@dataclass
class AppConfig:
    env: str = "dev"
    db_path: str = "varden.db"
    auth_db_path: str = "varden_auth.db"
    policy_file: str = "policy.json"
    signing_secret: str = "change-me"
    host: str = "127.0.0.1"
    port: int = 8000
    queue_backend: str = "sqlite"
    redis_url: str = "redis://localhost:6379/0"
    worker_poll_interval: float = 1.0
    worker_concurrency: int = 1
    auth_mode: str = "local"
    oidc_issuer: str | None = None
    oidc_jwks_url: str | None = None
    oidc_audience: str | None = None
    oidc_introspection_url: str | None = None
    route_sensitive_to_local: bool = False
    blaze_command: list[str] | None = None
    rate_limit_per_minute: int = 600
    read_rate_limit_per_minute: int = 2400
    write_rate_limit_per_minute: int = 600
    ingest_rate_limit_per_minute: int = 12000
    stream_connect_rate_limit_per_minute: int = 120
    webhook_signing_secret: str = "change-me-webhook"
    public_base_url: str = "http://127.0.0.1:8000"
    backup_dir: str = "backups"
    enable_dev_bootstrap: bool = True
    scan_mode: str = "fast"
    max_request_body_bytes: int = 250_000
    max_output_body_bytes: int = 450_000

    @classmethod
    def from_env(cls) -> "AppConfig":

        host = os.getenv("VARDEN_HOST", "127.0.0.1")
        port = os.getenv("VARDEN_PORT", "8000")

        blaze = os.getenv("VARDEN_BLAZE_COMMAND", "").strip()
        blaze_cmd = blaze.split(" ") if blaze else None
        return cls(
            env=os.getenv("VARDEN_ENV", "dev"),
            db_path=os.getenv("VARDEN_DB_PATH", "varden.db"),
            auth_db_path=os.getenv("VARDEN_AUTH_DB_PATH", "varden_auth.db"),
            policy_file=os.getenv("VARDEN_POLICY_FILE", "policy.json"),
            signing_secret=os.getenv("VARDEN_SIGNING_SECRET", "change-me"),
            host=os.getenv("VARDEN_HOST", "127.0.0.1"),
            port=int(os.getenv("VARDEN_PORT", "8000")),
            queue_backend=os.getenv("VARDEN_QUEUE_BACKEND", "sqlite"),
            redis_url=os.getenv("VARDEN_REDIS_URL", "redis://localhost:6379/0"),
            worker_poll_interval=float(os.getenv("VARDEN_WORKER_POLL_INTERVAL", "1.0")),
            worker_concurrency=int(os.getenv("VARDEN_WORKER_CONCURRENCY", "1")),
            auth_mode=os.getenv("VARDEN_AUTH_MODE", "local"),
            oidc_issuer=os.getenv("VARDEN_OIDC_ISSUER"),
            oidc_jwks_url=os.getenv("VARDEN_OIDC_JWKS_URL"),
            oidc_audience=os.getenv("VARDEN_OIDC_AUDIENCE"),
            oidc_introspection_url=os.getenv("VARDEN_OIDC_INTROSPECTION_URL"),
            route_sensitive_to_local=os.getenv("VARDEN_ROUTE_SENSITIVE_LOCAL", "false").lower() == "true",
            blaze_command=blaze_cmd,
            rate_limit_per_minute=int(os.getenv("VARDEN_RATE_LIMIT_PER_MINUTE", "600")),
            read_rate_limit_per_minute=int(os.getenv("VARDEN_READ_RATE_LIMIT_PER_MINUTE", os.getenv("VARDEN_RATE_LIMIT_PER_MINUTE", "2400"))),
            write_rate_limit_per_minute=int(os.getenv("VARDEN_WRITE_RATE_LIMIT_PER_MINUTE", "600")),
            ingest_rate_limit_per_minute=int(os.getenv("VARDEN_INGEST_RATE_LIMIT_PER_MINUTE", "12000")),
            stream_connect_rate_limit_per_minute=int(os.getenv("VARDEN_STREAM_CONNECT_RATE_LIMIT_PER_MINUTE", "120")),
            webhook_signing_secret=os.getenv("VARDEN_WEBHOOK_SIGNING_SECRET", "change-me-webhook"),
            public_base_url = os.getenv("VARDEN_PUBLIC_BASE_URL",f"http://{host}:{port}"),
            backup_dir=os.getenv("VARDEN_BACKUP_DIR", "backups"),
            enable_dev_bootstrap=os.getenv("VARDEN_ENABLE_DEV_BOOTSTRAP", "true").lower() == "true",
            scan_mode=os.getenv("VARDEN_SCAN_MODE", "fast").lower(),
            max_request_body_bytes=int(os.getenv("VARDEN_MAX_REQUEST_BODY_BYTES", "250000")),
            max_output_body_bytes=int(os.getenv("VARDEN_MAX_OUTPUT_BODY_BYTES", "450000")),
        )

    @classmethod
    def from_env_file(cls, path: str | None) -> "AppConfig":
        if path:
            for line in Path(path).read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())
        return cls.from_env()

    def validate(self) -> list[str]:
        errors = []
        if self.queue_backend not in {"sqlite", "redis"}:
            errors.append("queue_backend must be sqlite or redis")
        if self.auth_mode not in {"local", "jwt", "oidc"}:
            errors.append("auth_mode must be local, jwt, or oidc")
        if self.auth_mode == "jwt" and not self.oidc_jwks_url:
            errors.append("jwt auth mode requires VARDEN_OIDC_JWKS_URL")
        if self.auth_mode == "oidc" and not self.oidc_introspection_url and not self.oidc_jwks_url:
            errors.append("oidc auth mode requires introspection or jwks url")
        if self.signing_secret == "change-me" and self.env != "dev":
            errors.append("change the signing_secret outside dev")
        if self.env != "dev" and self.enable_dev_bootstrap:
            errors.append("disable dev bootstrap outside dev")
        if self.scan_mode not in {"fast", "deep"}:
            errors.append("scan_mode must be fast or deep")
        if min(self.read_rate_limit_per_minute, self.write_rate_limit_per_minute, self.ingest_rate_limit_per_minute, self.stream_connect_rate_limit_per_minute) <= 0:
            errors.append("rate limits must be positive integers")
        if min(self.max_request_body_bytes, self.max_output_body_bytes) <= 0:
            errors.append("max request/output body byte limits must be positive integers")
        return errors
