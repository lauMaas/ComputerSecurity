package Week_2.DefensiveMeasurementPassword;

import java.util.*;

public class DenyList {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        ArrayList<String> denyList = new ArrayList<>();
        denyList.add("password");
        denyList.add("123456");
        denyList.add("qwerty");
        denyList.add("abc123");
        denyList.add("password1");

        System.out.println("Enter your password: ");
        String password = scanner.nextLine();

        while (denyList.contains(password)) {
            System.out.println("Your password is denied. Please enter a new password: ");
            password = scanner.nextLine();
        }
        
        System.out.println("Your password is accepted.");
        scanner.close();

    }
}
