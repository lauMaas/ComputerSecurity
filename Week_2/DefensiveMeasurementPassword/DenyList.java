package Week_2.DefensiveMeasurementPassword;

import java.util.*;

public class DenyList {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        Set<String> denyList = new HashSet<>(Arrays.asList(
                "password", "123456", "qwerty", "abc123", "password1"
        ));

        System.out.println("=== Password Denylist Check ===");
        System.out.println("Common weak passwords will be rejected.");
        System.out.println("Examples: " + denyList);
        System.out.println();

        String password;
        while (true) {
            System.out.print("Enter your password: ");
            password = scanner.nextLine().trim().toLowerCase();

            if (denyList.contains(password)) {
                System.out.println("❌ That password is on the denylist. Please choose a stronger one.\n");
            } else {
                break;
            }
        }

        System.out.println("✅ Your password is accepted.");
        scanner.close();
    }
}