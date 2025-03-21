package Week_2.DefensiveMeasurementPassword;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class PasswordPepper {

    private static final String GLOBAL_PEPPER = "SuperSecretPepperValue"; // stored securely elsewhere

    public static void main(String[] args) throws Exception {
        String[] usernames = { "user1", "user2", "user3" };
        String[] passwords = { "password123", "password456", "password789" };
        String[] salts = new String[usernames.length];
        String[] hashedPasswords = new String[usernames.length];

        for (int i = 0; i < usernames.length; i++) {
            salts[i] = generateSalt();
            hashedPasswords[i] = hashPassword(passwords[i], salts[i]);
        }

        // Database table stores: Username, Salt, HashedPassword
        System.out.println("\n=== DATABASE TABLE (User Storage) ===");
        System.out.printf("%-10s | %-12s | %s%n", "Username", "Salt", "HashedPassword");
        System.out.println("------------|--------------|----------------------------------------------");
        for (int i = 0; i < usernames.length; i++) {
            System.out.printf("%-10s | %-12s | %s%n", usernames[i], salts[i], hashedPasswords[i]);
        }

        // Pepper is stored elsewhere
        System.out.println("\n=== PEPPER (Stored Securely in HSM or Vault) ===");
        System.out.println("Global Pepper (Base64): " + Base64.getEncoder().encodeToString(GLOBAL_PEPPER.getBytes("UTF-8")));
    }

    private static String generateSalt() {
        byte[] salt = new byte[8];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    private static String hashPassword(String password, String salt) throws Exception {
        String combined = salt + password + GLOBAL_PEPPER;
        return hash(combined);
    }

    private static String hash(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(input.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(hashBytes);
    }
}