from __future__ import annotations
class MetricsExporter:
    def __init__(self, event_store): self.event_store=event_store
    def render_prometheus(self, tenant_id: str | None = None)->str:
        m=self.event_store.metrics(tenant_id=tenant_id)
        lines=[
            "# HELP sentinel_total_events Total events",
            "# TYPE sentinel_total_events gauge",
            f"sentinel_total_events {m['total_events']}",
            "# HELP sentinel_blocked_events Blocked events",
            "# TYPE sentinel_blocked_events gauge",
            f"sentinel_blocked_events {m['blocked_events']}",
            "# HELP sentinel_warned_events Warned events",
            "# TYPE sentinel_warned_events gauge",
            f"sentinel_warned_events {m['warned_events']}",
            "# HELP sentinel_local_routes Local routes",
            "# TYPE sentinel_local_routes gauge",
            f"sentinel_local_routes {m['local_routes']}",
            "# HELP sentinel_open_alerts Open alerts",
            "# TYPE sentinel_open_alerts gauge",
            f"sentinel_open_alerts {m['open_alerts']}",
        ]
        return "\n".join(lines)+"\n"
