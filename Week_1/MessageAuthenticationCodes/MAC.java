package Week_1.MessageAuthenticationCodes;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class MAC {
    public static void main(String[] args) throws Exception {
        System.out.println("=== MESSAGE AUTHENTICATION CODE (HMAC) DEMO ===\n");

        // Step 1: Define message and secret key
        String message = "HELLO";
        String secretKey = "super_secret_key";

        System.out.println("[1] Original Message: " + message);
        System.out.println("[2] Shared Secret Key: " + secretKey);

        // Step 2: Generate MAC
        String hmac = generateHMAC(message, secretKey);
        System.out.println("\n[3] Generated HMAC (message, SecretKey): " + hmac);

        // Step 3: Simulate Verification (recompute MAC)
        System.out.println("\n[4] Verifying HMAC... HMAC(message, SecretKey) = HMAC(message, SecretKey)");
        boolean isValid = hmac.equals(generateHMAC(message, secretKey));
        System.out.println("    -> MAC Verification Result: " + (isValid ? "✅ Valid" : "❌ Invalid"));

        System.out.println("\n=== END OF DEMO ===");
    }

    /**
     * Generates a Base64-encoded HMAC using HmacSHA256.
     */
    public static String generateHMAC(String message, String secretKey) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes("UTF-8"), "HmacSHA256");
        mac.init(keySpec);
        byte[] hmacBytes = mac.doFinal(message.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(hmacBytes);
    }
}