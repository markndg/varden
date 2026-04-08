package ai.sentinel;

import java.util.Map;

public final class SentinelGuardResult {
    public final SentinelDecision decision;
    public final Map<String, Object> action;
    public final Integer eventId;

    public SentinelGuardResult(SentinelDecision decision, Map<String, Object> action, Integer eventId) {
        this.decision = decision;
        this.action = action;
        this.eventId = eventId;
    }
}
