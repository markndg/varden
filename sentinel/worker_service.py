from __future__ import annotations
import argparse, time
from .config import AppConfig
from .queue import SQLiteQueue
from .worker_runtime import DistributedWorker

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=None)
    args = parser.parse_args()

    cfg = AppConfig.from_env_file(args.config)
    queue = SQLiteQueue(cfg.db_path)
    worker = DistributedWorker(queue, concurrency=cfg.worker_concurrency, poll_interval=cfg.worker_poll_interval)

    def webhook_delivery(job):
        print("processing webhook_delivery", job["id"])

    def generic(job):
        print("processing", job["job_type"], job["id"])

    worker.register("webhook_delivery", webhook_delivery)
    worker.register("generic", generic)
    worker.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        worker.stop()

if __name__ == "__main__":
    main()
