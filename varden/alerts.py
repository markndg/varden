from __future__ import annotations
import json, threading, time, urllib.request
from pathlib import Path

class ConsoleSink:
    name = "console"
    def send(self, alert: dict):
        print("[ALERT]", json.dumps(alert, ensure_ascii=False))

class FileSink:
    name = "file"
    def __init__(self, path: str): self.path = Path(path)
    def send(self, alert: dict):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(alert, ensure_ascii=False) + "\n")

class AlertEngine:
    def __init__(self, sinks=None): self.sinks = sinks or [ConsoleSink()]
    def derive_alerts(self, event: dict):
        alerts=[]; action=event.get("action",{}); decision=event.get("decision",{}); status=event.get("status")
        if status=="blocked": alerts.append({"severity":"high","title":"Blocked action","message":decision.get("reason","blocked"),"tenant_id":event.get("tenant_id"),"event_id":event.get("id")})
        if status=="warned": alerts.append({"severity":"medium","title":"Warned action","message":decision.get("reason","warned"),"tenant_id":event.get("tenant_id"),"event_id":event.get("id")})
        if action.get("route_target")=="local_blaze": alerts.append({"severity":"low","title":"Routed local","message":"Sensitive routed local","tenant_id":event.get("tenant_id"),"event_id":event.get("id")})
        return alerts
    def deliver(self, alert: dict):
        sinks=[]
        for sink in self.sinks:
            sink.send(alert); sinks.append(getattr(sink,"name","sink"))
        return sinks

class BackgroundWorker:
    def __init__(self, event_store, alert_engine, poll_interval: float = 2.0):
        self.event_store=event_store; self.alert_engine=alert_engine; self.poll_interval=poll_interval; self.running=False; self.thread=None; self.last_seen=0
    def start(self):
        if self.running: return
        self.running=True; self.thread=threading.Thread(target=self._loop, daemon=True); self.thread.start()
    def stop(self):
        self.running=False
        if self.thread: self.thread.join(timeout=1.0)
    def _loop(self):
        while self.running:
            events=self.event_store.list_events(limit=100)
            for event in reversed(events):
                eid=event.get("id",0)
                if eid <= self.last_seen: continue
                for alert in self.alert_engine.derive_alerts(event):
                    sinks=self.alert_engine.deliver(alert)
                    self.event_store.log_alert(alert, sinks)
                self.last_seen=max(self.last_seen,eid)
            time.sleep(self.poll_interval)
