import ai.varden.Varden;
import ai.varden.VardenBlockedException;

public final class BlockedDemo {
    public static void main(String[] args) throws Exception {
        Varden.protect();
        System.out.println("Varden Java demo: only Varden.protect() is required");
        try {
            Varden.command("python", "-c", "print('java demo')", "delete_database", "prod-customer-db").inheritIO().start();
            System.out.println("Expected block, but command ran");
        } catch (VardenBlockedException blocked) {
            System.out.println("Varden blocked the command as expected");
            System.out.println(blocked.result.decision.raw);
        }
    }
}
