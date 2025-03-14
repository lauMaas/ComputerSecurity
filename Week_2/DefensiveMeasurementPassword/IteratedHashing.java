package Week_2.DefensiveMeasurementPassword;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class IteratedHashing {
    public static void main(String[] args) {
        String password = "password123";
        int iterations = 1000;

        String hashedPassword = hashPassword(password, iterations);
        System.out.println("Hashed Password: " + hashedPassword);
    }

    private static String hashPassword(String password, int iterations) {
        for(int i = 0; i < iterations; i++) {
            password = hash(password);
        }
        return password;
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