package ai.sentinel;

import java.util.Map;

public final class SentinelDecision {
    public final String action;
    public final String reason;
    public final Map<String, Object> raw;

    public SentinelDecision(String action, String reason, Map<String, Object> raw) {
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
