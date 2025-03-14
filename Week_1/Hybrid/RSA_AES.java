package Week_1.Hybrid;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

public class RSA_AES {
    public static void main(String[] args) throws Exception {
        // Step 1: Generate RSA Key Pair for Person B (Receiver)
        KeyPair keyPair = generateRSAKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Step 2: Generate AES Key for Symmetric Encryption
        SecretKey aesKey = generateAESKey();

        // Step 3: Encrypt the message using AES
        String message = "HELLO, THIS IS Laurin";
        System.out.println("Original Message: " + message);
        byte[] encryptedMessage = encryptAES(message, aesKey);

        // Step 4: Encrypt the AES key using RSA (Person B's Public Key)
        byte[] encryptedAESKey = encryptRSA(aesKey.getEncoded(), publicKey);

        // Step 5: Send encrypted message & encrypted AES key
        System.out.println("\nEncrypted AES Key (RSA): " + Base64.getEncoder().encodeToString(encryptedAESKey));
        System.out.println("Encrypted Message (AES): " + Base64.getEncoder().encodeToString(encryptedMessage));

        // Step 6: Decrypt the AES key using RSA (Person B's Private Key)
        byte[] decryptedAESKeyBytes = decryptRSA(encryptedAESKey, privateKey);
        SecretKey decryptedAESKey = new SecretKeySpec(decryptedAESKeyBytes, "AES");

        // Step 7: Decrypt the message using AES
        String decryptedMessage = decryptAES(encryptedMessage, decryptedAESKey);
        System.out.println("\nDecrypted Message: " + decryptedMessage);
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
        return cipher.doFinal(message.getBytes());
    }

    // Decrypt a message using AES
    private static String decryptAES(byte[] encryptedData, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key); 
        return new String(cipher.doFinal(encryptedData));
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