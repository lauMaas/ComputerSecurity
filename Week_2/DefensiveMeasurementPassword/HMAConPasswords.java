package Week_2.DefensiveMeasurementPassword;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class HMAConPasswords {
    public static void main(String[] args) throws Exception {
        // Example user credentials
        String[] usernames = { "user1", "user2", "user3" };
        String[] passwords = { "password123", "password456", "password789" };

        // Shared secret key for HMAC (must be kept safe and private!)
        String secretKey = "SuperSecretHMACKey";

        // Array to store hashed passwords
        String[] hashedPasswords = new String[usernames.length];

        // Hash each password with HMAC-SHA256
        for (int i = 0; i < usernames.length; i++) {
            hashedPasswords[i] = generateHMAC(passwords[i], secretKey);
        }

        // Print simulated secure database storage
        System.out.println("\n=== Simulated Database Table ===");
        System.out.printf("%-10s | %s%n", "Username", "HashedPassword (HMAC-SHA256)");
        System.out.println("-----------|-------------------------------------------------------------");
        for (int i = 0; i < usernames.length; i++) {
            System.out.printf("%-10s | %s%n", usernames[i], hashedPasswords[i]);
        }

        // Show how the secret key is stored (in reality, this should NOT be printed)
        System.out.println("\n=== Stored Separately in a Secure Vault ===");
        System.out.println("Secret Key (base64): " + Base64.getEncoder().encodeToString(secretKey.getBytes("UTF-8")));
    }

    // Generate HMAC using HmacSHA256
    private static String generateHMAC(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256");
        mac.init(keySpec);
        byte[] hmacBytes = mac.doFinal(data.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(hmacBytes);
    }
}