package Week_2.ExchangeAlgorithm.PAKE;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Base64;

public class EKE {
    public static void main(String[] args) throws Exception {
        // Shared password known to both parties
        String password = "superSecretW";
        String idAlice = "Alice";
        String sessionKey = "sharedSecretKey"; // Simulating the generated session key

        // Step 1: Alice encrypts M using password W
        String M = "randomNonceM"; // Alice's random challenge message
        String encryptedM = encrypt(M, password);
        
        System.out.println("=== ENCRYPTED KEY EXCHANGE (EKE) ===\n");
        
        // Step 2: Alice sends (ID, encrypted M) to Bob
        System.out.println("[Alice -> Bob] Sending ID and Encrypted M");
        System.out.println("  ID: " + idAlice);
        System.out.println("  Encrypted M (using W): " + encryptedM + "\n");

        // Step 3: Bob decrypts M using W
        String decryptedM = decrypt(encryptedM, password);
        System.out.println("[Bob] Decrypted M using W: " + decryptedM + "\n");

        // Step 4: Bob encrypts session key using ID and M as key
        String encryptedSessionKey = encrypt(sessionKey, idAlice + decryptedM);
        System.out.println("[Bob] Encrypting session key using (ID + M) as key\n");

        // Step 5: Bob sends encrypted session key to Alice
        System.out.println("[Bob -> Alice] Sending Encrypted Session Key");
        System.out.println("  Encrypted Session Key (using ID + M): " + encryptedSessionKey + "\n");

        // Step 6: Alice decrypts session key using ID and M
        String decryptedSessionKey = decrypt(encryptedSessionKey, idAlice + M);
        System.out.println("[Alice] Decrypted Session Key using (ID + M): " + decryptedSessionKey);

        // Check if session key matches
        System.out.println("\n✅ Session Key Match: " + decryptedSessionKey.equals(sessionKey));
    }

    // Derive AES key from password
    private static SecretKeySpec deriveAESKey(String password) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = digest.digest(password.getBytes("UTF-8"));
        return new SecretKeySpec(keyBytes, 0, 16, "AES"); // AES-128
    }

    // Encrypt using AES
    private static String encrypt(String plaintext, String password) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, deriveAESKey(password));
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Decrypt using AES
    private static String decrypt(String ciphertext, String password) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, deriveAESKey(password));
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decryptedBytes, "UTF-8");
    }
} 
