package ai.varden;

import java.util.Map;

public final class VardenDecision {
    public final String action;
    public final String reason;
    public final Map<String, Object> raw;

    public VardenDecision(String action, String reason, Map<String, Object> raw) {
        this.action = action;
        this.reason = reason;
        this.raw = raw;
    }

    public boolean blocked() {
        return "block".equalsIgnoreCase(action);
    }

    public boolean warned() {
        return "warn".equalsIgnoreCase(action);
    }
}
