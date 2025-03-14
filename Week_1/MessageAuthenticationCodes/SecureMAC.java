package Week_1.MessageAuthenticationCodes;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.util.Base64;

public class SecureMAC {
    public static void main(String[] args) throws Exception {
        String message = "PAY 100 TO BOB";

        // Generate encryption and MAC keys
        SecretKey encryptionKey = generateAESKey();
        SecretKey macKey = generateHMACKey();

        // Encrypt the message
        String ciphertext = encryptAES(message, encryptionKey);

        // Generate MAC for the encrypted message
        String mac = generateHMAC(ciphertext, macKey);

        System.out.println();
        System.out.println("Encryption of Message");
        System.out.println("Message: " + message);
        System.out.println("Encryption Key (public key of receiver): " + encryptionKey);
        System.out.println("Ciphertext: " + ciphertext);
        System.out.println("-----------------------------------");
        System.out.println("Authentication");
        System.out.println("CipherText: " + ciphertext);
        System.out.println("MAC Key (Shared): " + macKey);
        System.out.println("MAC: " + mac);
        System.out.println("-----------------------------------");
        System.out.println("Sending");
        System.out.println("CipherText: " + ciphertext);
        System.out.println("MAC: " + mac);
        System.out.println("-----------------------------------");
        System.out.println("Decryption and Verification");
        System.out.println("CipherText: " + ciphertext);
        System.out.println("MAC Key (Shared): " + macKey);
        System.out.println("MAC: " + mac);
        System.out.println("Compare receiver MAC and sender MAC");

        // Receiver verifies and decrypts
        boolean isValid = verifyHMAC(ciphertext, mac, macKey);
        if (isValid) {
            String decryptedMessage = decryptAES(ciphertext, encryptionKey);
            System.out.println("Decrypted Message: " + decryptedMessage);
        } else {
            System.out.println("❌ MAC Verification Failed! Message was tampered.");
        }
    }

    // Generate AES Key
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    // Generate HMAC Key
    public static SecretKey generateHMACKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
        return keyGen.generateKey();
    }

    // Encrypt Message using AES
    public static String encryptAES(String message, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Decrypt Message using AES
    public static String decryptAES(String ciphertext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes);
    }

    // Generate HMAC
    public static String generateHMAC(String message, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] hmacBytes = mac.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(hmacBytes);
    }

    // Verify HMAC
    public static boolean verifyHMAC(String message, String receivedMac, SecretKey key) throws Exception {
        String calculatedMac = generateHMAC(message, key);
        return calculatedMac.equals(receivedMac);
    }
}