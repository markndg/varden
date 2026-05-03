from __future__ import annotations
import argparse
import os
import uvicorn
from .config import AppConfig
from .app_factory import create_app

def build_app(config_path: str | None = None):
    cfg = AppConfig.from_env_file(config_path)
    return create_app(cfg)

# ASGI entrypoint for `uvicorn varden.api:app`
app = build_app(os.environ.get("VARDEN_CONFIG"))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=None)
    args = parser.parse_args()
    cfg = AppConfig.from_env_file(args.config)
    uvicorn.run(build_app(args.config), host=cfg.host, port=cfg.port)

if __name__ == "__main__":
    main()
