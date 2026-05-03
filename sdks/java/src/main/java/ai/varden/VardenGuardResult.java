package ai.varden;

import java.util.Map;

public final class VardenGuardResult {
    public final VardenDecision decision;
    public final Map<String, Object> action;
    public final Integer eventId;

    public VardenGuardResult(VardenDecision decision, Map<String, Object> action, Integer eventId) {
        this.decision = decision;
        this.action = action;
        this.eventId = eventId;
    }
}
