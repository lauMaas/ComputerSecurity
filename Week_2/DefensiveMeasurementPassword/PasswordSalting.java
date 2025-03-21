package Week_2.DefensiveMeasurementPassword;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class PasswordSalting {

    public static void main(String[] args) throws Exception {
        String[] usernames = { "user1", "user2", "user3" };
        String[] passwords = { "password123", "password456", "password789" };

        String[] salts = new String[usernames.length];
        String[] hashedPasswords = new String[usernames.length];

        // Generate salts and hash passwords
        for (int i = 0; i < usernames.length; i++) {
            salts[i] = generateSalt();
            hashedPasswords[i] = hashPassword(passwords[i], salts[i]);
        }

        // Simulate storage in a database
        System.out.println("\n=== SALTED PASSWORD STORAGE ===");
        System.out.printf("%-10s | %-12s | %s%n", "Username", "Salt", "HashedPassword");
        System.out.println("------------|--------------|----------------------------------------------");
        for (int i = 0; i < usernames.length; i++) {
            System.out.printf("%-10s | %-12s | %s%n", usernames[i], salts[i], hashedPasswords[i]);
        }
    }

    // Securely generates a random salt
    private static String generateSalt() {
        byte[] salt = new byte[8]; // 64 bits
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    // Hash password + salt
    private static String hashPassword(String password, String salt) throws Exception {
        return hash(password + salt);
    }

    // SHA-256 hash function
    private static String hash(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(input.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(hashBytes);
    }
}