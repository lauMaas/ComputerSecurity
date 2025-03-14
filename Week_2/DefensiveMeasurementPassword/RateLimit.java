package Week_2.DefensiveMeasurementPassword;

import java.util.Scanner;

public class RateLimit {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        int rateLimit = 3;
        int attempts = 0;

        System.out.println("Enter your password: ");
        String password = scanner.nextLine();

        while (attempts < rateLimit) {
            if (password.equals("password")) {
                attempts++;
                System.out.println("Your password is denied. Please enter a new password.");
                System.out.println("Attempts left: " + (rateLimit - attempts));
                password = scanner.nextLine();
            } else {
                System.out.println("Your password is accepted.");
                break;
            }
        }

        if (attempts == rateLimit) {
            System.out.println("You have reached the maximum number of attempts.");
        }

        scanner.close();
    }
}
