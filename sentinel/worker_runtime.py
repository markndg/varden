from __future__ import annotations
import socket, threading, time, uuid

class DistributedWorker:
    def __init__(self, queue_backend, concurrency: int = 1, poll_interval: float = 1.0):
        self.queue = queue_backend
        self.concurrency = concurrency
        self.poll_interval = poll_interval
        self.worker_id = f"{socket.gethostname()}-{uuid.uuid4()}"
        self.handlers = {}
        self.running = False
        self.threads = []

    def register(self, job_type: str, fn):
        self.handlers[job_type] = fn

    def start(self):
        if self.running:
            return
        self.running = True
        for _ in range(self.concurrency):
            t = threading.Thread(target=self._loop, daemon=True)
            t.start()
            self.threads.append(t)

    def stop(self):
        self.running = False
        for t in self.threads:
            t.join(timeout=1.0)

    def _loop(self):
        while self.running:
            job = self.queue.reserve(lease_seconds=30, worker_id=self.worker_id)
            if not job:
                time.sleep(self.poll_interval)
                continue
            try:
                handler = self.handlers.get(job["job_type"])
                if handler is None:
                    raise RuntimeError(f"no handler for {job['job_type']}")
                handler(job)
                self.queue.complete(job["id"])
            except Exception as exc:
                self.queue.fail(job["id"], str(exc))
