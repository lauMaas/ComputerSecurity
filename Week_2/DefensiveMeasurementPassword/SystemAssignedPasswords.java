package Week_2.DefensiveMeasurementPassword;

import java.util.Scanner;

public class SystemAssignedPasswords {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        String password = "";

        System.out.println("Do you want to generate a password? (yes/no)");
        String response = scanner.nextLine();

        if (response.equals("yes")) {
            password = generatePassword();
        } else {
            System.out.println("Enter manual password!");

            System.out.println("Enter your password: ");
            password = scanner.nextLine();
        }

        System.out.println("Your password is: " + password);
        scanner.close();
    }

    private static String generatePassword() {
        String password = "";
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";

        for (int i = 0; i < 16; i++) {
            int randomIndex = (int) (Math.random() * characters.length());
            password += characters.charAt(randomIndex);
        }

        return password;
    }
}
