package Week_2.DefensiveMeasurementPassword;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class PasswordPepper {

    public static void main(String[] args) {
        String[] usernames = { "user1", "user2", "user3" };
        String[] passwords = { "password123", "password456", "password789" };
        String[] peppers = { "pepper1", "pepper2", "pepper3" }; // randomly generated peppers

        String[] hashedPassword = new String[usernames.length];

        for (int i = 0; i < usernames.length; i++) {
            hashedPassword[i] = hashPassword(passwords[i], peppers[i]);
        }

        System.out.println();
        System.out.println("Stored Table inside Datbase: ");
        System.out.println("Username        HashedPassword");
        System.out.println("--------        --------------");
        for (int i = 0; i < usernames.length; i++) {
            System.out.println(usernames[i] + "           " + hashedPassword[i]);
        }

        System.out.println();
        System.out.println("Stored Table inside OTHER Datbase: ");
        System.out.println("Username        Pepper");
        System.out.println("--------        --------------");
        for (int i = 0; i < usernames.length; i++) {
            System.out.println(usernames[i] + "           " + peppers[i]);
        }

    }

    private static String hashPassword(String password, String pepper) {
        return hash(password + pepper);
    }

    private static String hash(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(password.getBytes());
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
