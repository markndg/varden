from __future__ import annotations
class MetricsExporter:
    def __init__(self, event_store): self.event_store=event_store
    def render_prometheus(self, tenant_id: str | None = None)->str:
        m=self.event_store.metrics(tenant_id=tenant_id)
        lines=[
            "# HELP varden_total_events Total events",
            "# TYPE varden_total_events gauge",
            f"varden_total_events {m['total_events']}",
            "# HELP varden_blocked_events Blocked events",
            "# TYPE varden_blocked_events gauge",
            f"varden_blocked_events {m['blocked_events']}",
            "# HELP varden_warned_events Warned events",
            "# TYPE varden_warned_events gauge",
            f"varden_warned_events {m['warned_events']}",
            "# HELP varden_local_routes Local routes",
            "# TYPE varden_local_routes gauge",
            f"varden_local_routes {m['local_routes']}",
            "# HELP varden_open_alerts Open alerts",
            "# TYPE varden_open_alerts gauge",
            f"varden_open_alerts {m['open_alerts']}",
        ]
        return "\n".join(lines)+"\n"
