package ai.varden;

public final class VardenBlockedException extends RuntimeException {
    public final VardenGuardResult result;

    public VardenBlockedException(String message, VardenGuardResult result) {
        super(message);
        this.result = result;
    }
}
