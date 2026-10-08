from __future__ import annotations
import argparse
import asyncio
import logging
import os
import socket
import uvicorn
from .config import AppConfig
from .app_factory import create_app

logger = logging.getLogger("varden")

# Backstop only. Live streams are closed before this wait, so a normal
# SIGINT should finish well inside the limit. None would wait forever.
GRACEFUL_SHUTDOWN_SECONDS = 5.0


class GracefulServer(uvicorn.Server):
    """Close application streams before Uvicorn drops sockets.

    Uvicorn waits for open connections, then runs lifespan shutdown. The
    dashboard holds ``/stream/updates`` open, so that wait never ends and
    lifespan cleanup never runs. Closing the broker first lets those
    generators finish. The connection wait is then empty.
    """

    async def shutdown(self, sockets: list[socket.socket] | None = None) -> None:
        application = self.config.app
        closer = getattr(application, "request_shutdown", None)
        if callable(closer):
            closer()
            await asyncio.sleep(0.05)
        await super().shutdown(sockets)


def build_app(config_path: str | None = None):
    cfg = AppConfig.from_env_file(config_path)
    errors = cfg.validate()
    if errors:
        message = "; ".join(errors)
        if cfg.env != "dev":
            raise RuntimeError(f"invalid configuration: {message}")
        logger.warning("config validation warnings: %s", message)
    return create_app(cfg)

# ASGI entrypoint for `uvicorn varden.api:app`
app = build_app(os.environ.get("VARDEN_CONFIG"))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=None)
    args = parser.parse_args()
    cfg = AppConfig.from_env_file(args.config)
    application = build_app(args.config)
    config = uvicorn.Config(
        application,
        host=cfg.host,
        port=cfg.port,
        timeout_graceful_shutdown=GRACEFUL_SHUTDOWN_SECONDS,
    )
    try:
        GracefulServer(config).run()
    except KeyboardInterrupt:
        # Uvicorn has already closed listeners, streams, and the lifespan.
        # asyncio translates that signal into KeyboardInterrupt at the runner
        # boundary. Catching it here is the process exit, not request handling.
        return

if __name__ == "__main__":
    main()
