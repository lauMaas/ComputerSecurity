package Week_2.DefensiveMeasurementPassword;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class HMAConPasswords {
    public static void main(String[] args) throws Exception {
        String[] usernames = { "user1", "user2", "user3" };
        String[] passwords = { "password123", "password456", "password789" };
        String secretKey = "SuperSecretHMACKey"; // A secure secret key

        String[] hashedPasswords = new String[usernames.length];

        for (int i = 0; i < usernames.length; i++) {
            hashedPasswords[i] = generateHMAC(passwords[i], secretKey);
        }

        System.out.println("\nStored Table inside Database:");
        System.out.println("Username        HashedPassword");
        System.out.println("--------        --------------");
        for (int i = 0; i < usernames.length; i++) {
            System.out.println(usernames[i] + "           " + hashedPasswords[i]);
        }

        System.out.println("\nStored Securely in a Secure Valt:");
        System.out.print("Secret Key: ");
        System.out.println(secretKey);
    }

    private static String generateHMAC(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hmacBytes = mac.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(hmacBytes); // Encode the HMAC result
    }
}