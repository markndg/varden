import ai.sentinel.Sentinel;
import ai.sentinel.SentinelBlockedException;

public final class BlockedDemo {
    public static void main(String[] args) throws Exception {
        Sentinel.protect();
        System.out.println("Sentinel Java demo: only Sentinel.protect() is required");
        try {
            Sentinel.command("python", "-c", "print('java demo')", "delete_database", "prod-customer-db").inheritIO().start();
            System.out.println("Expected block, but command ran");
        } catch (SentinelBlockedException blocked) {
            System.out.println("Sentinel blocked the command as expected");
            System.out.println(blocked.result.decision.raw);
        }
    }
}
