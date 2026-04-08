from __future__ import annotations
import argparse
import uvicorn
from .config import AppConfig
from .app_factory import create_app

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=None)
    args = parser.parse_args()
    cfg = AppConfig.from_env_file(args.config)
    app = create_app(cfg)
    uvicorn.run(app, host=cfg.host, port=cfg.port)

if __name__ == "__main__":
    main()
