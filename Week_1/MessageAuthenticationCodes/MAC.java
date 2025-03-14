package Week_1.MessageAuthenticationCodes;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class MAC {
    public static void main(String[] args) throws Exception {
        String message = "HELLO";
        String secretKey = "super_secret_key";

        // Generate MAC
        String mac = generateHMAC(message, secretKey);

        System.out.println("Message: " + message);
        System.out.println("MAC: " + mac);

        // Verify MAC
        boolean isValid = mac.equals(generateHMAC(message, secretKey));
        System.out.println("MAC Verification: " + (isValid ? "✅ Valid" : "❌ Invalid"));
    }

    public static String generateHMAC(String message, String secretKey) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256");
        mac.init(keySpec);
        byte[] hmacBytes = mac.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(hmacBytes);
    }
}