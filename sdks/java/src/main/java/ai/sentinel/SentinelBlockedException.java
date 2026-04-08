package ai.sentinel;

public final class SentinelBlockedException extends RuntimeException {
    public final SentinelGuardResult result;

    public SentinelBlockedException(String message, SentinelGuardResult result) {
        super(message);
        this.result = result;
    }
}
