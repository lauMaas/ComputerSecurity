package Week_2.DefensiveMeasurementPassword;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class IteratedHashing {
    public static void main(String[] args) {
        String password = "password123";
        int iterations = 10;

        System.out.println("=== ITERATED HASHING DEMO ===\n");
        System.out.println("Original Password: " + password);
        System.out.println("Hashing Algorithm: SHA-256");
        System.out.println("Iterations: " + iterations + "\n");

        String hashedPassword = hashPassword(password, iterations);
        System.out.println("\nFinal Hashed Password: " + hashedPassword);
    }

    private static String hashPassword(String password, int iterations) {
        String current = password;
        for(int i = 1; i <= iterations; i++) {
            String previous = current;
            current = hash(current);
            String label = "p";
            for (int j = 1; j < i; j++) {
                label = "H(" + label + ")";
            }
            label = "H(" + label + ")";
            System.out.printf("%s = %s%n", label, current);
        }
        return current;
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