package Week_2.DefensiveMeasurementPassword;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class PasswordSalting {
    public static void main(String[] args) {
        String[] usernames = { "user1", "user2", "user3" };
        String[] passwords = { "password123", "password456", "password789" };
        String[] salts = { "salt1", "salt2", "salt3" }; // randomly generated salts

        String[] hashedPassword = new String[usernames.length];

        for (int i = 0; i < usernames.length; i++) {
            hashedPassword[i] = hashPassword(passwords[i], salts[i]);
        }

        System.out.println();
        System.out.println("Stored Table inside Datbase: ");
        System.out.println("Username        Salt         HashedPassword");
        System.out.println("--------        ----         --------------");
        for (int i = 0; i < usernames.length; i++) {
            System.out.println(usernames[i] + "           " + salts[i] + "       " + hashedPassword[i]);
        }

    }

    private static String hashPassword(String password, String salt) {
        return hash(password + salt);
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
