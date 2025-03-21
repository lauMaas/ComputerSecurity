package Week_1.Hybrid;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

public class RSA_AES {
    public static void main(String[] args) throws Exception {
        System.out.println("=== HYBRID ENCRYPTION DEMO (RSA + AES) ===\n");

        // Step 1: Generate RSA Key Pair
        System.out.println("[1] Generating RSA key pair (2048-bit)...");
        KeyPair keyPair = generateRSAKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        System.out.println("    -> RSA Public Key: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        System.out.println("    -> RSA Private Key: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));

        // Step 2: Generate AES Key
        System.out.println("\n[2] Generating AES key (128-bit)...");
        SecretKey aesKey = generateAESKey();
        System.out.println("    -> AES Key: " + Base64.getEncoder().encodeToString(aesKey.getEncoded()));

        // Step 3: Encrypt message using AES
        String message = "HELLO, THIS IS Laurin";
        System.out.println("\n[3] Encrypting message with AES...");
        System.out.println("    -> Original Message: " + message);
        byte[] encryptedMessage = encryptAES(message, aesKey);
        System.out.println("    -> Encrypted Message (Base64): " + Base64.getEncoder().encodeToString(encryptedMessage));

        // Step 4: Encrypt AES Key using RSA
        System.out.println("\n[4] Encrypting AES key with RSA (receiver's public key)...");
        byte[] encryptedAESKey = encryptRSA(aesKey.getEncoded(), publicKey);
        System.out.println("    -> Encrypted AES Key (Base64): " + Base64.getEncoder().encodeToString(encryptedAESKey));

        // Step 5: Simulate sending data...
        System.out.println("\n[5] Simulating sending the encrypted AES key and encrypted message...");

        // Step 6: Decrypt AES key using RSA
        System.out.println("\n[6] Decrypting AES key using RSA (receiver's private key)...");
        byte[] decryptedAESKeyBytes = decryptRSA(encryptedAESKey, privateKey);
        SecretKey decryptedAESKey = new SecretKeySpec(decryptedAESKeyBytes, "AES");
        System.out.println("    -> Decrypted AES Key (Base64): " + Base64.getEncoder().encodeToString(decryptedAESKey.getEncoded()));

        // Step 7: Decrypt message using AES
        System.out.println("\n[7] Decrypting message with AES...");
        String decryptedMessage = decryptAES(encryptedMessage, decryptedAESKey);
        System.out.println("    -> Decrypted Message: " + decryptedMessage);

        System.out.println("\n=== END OF DEMO ===");
    }

    // Generate RSA Key Pair (2048-bit)
    private static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    // Generate AES Key (128-bit)
    private static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    // Encrypt a message using AES
    private static byte[] encryptAES(String message, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(message.getBytes("UTF-8"));
    }

    // Decrypt a message using AES
    private static String decryptAES(byte[] encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(encryptedData), "UTF-8");
    }

    // Encrypt AES key using RSA
    private static byte[] encryptRSA(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    // Decrypt AES key using RSA
    private static byte[] decryptRSA(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }
}