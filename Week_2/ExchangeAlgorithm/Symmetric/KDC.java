package Week_2.ExchangeAlgorithm.Symmetric;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Base64;

public class KDC {
    public static void main(String[] args) throws Exception {
        // Simulate a KDC issuing a session key
        SecretKey sessionKey = generateAESKey(); // Generates the symmetric session key
        SecretKey userKey = generateAESKey(); // Each user has a pre-shared key (PSK)

        // Encrypt session key using the user's pre-shared key
        String encryptedSessionKey = encryptKey(sessionKey, userKey);

        System.out.println("🔐 KDC Generated Session Key (Plaintext): " + Base64.getEncoder().encodeToString(sessionKey.getEncoded()));
        System.out.println("🔒 Encrypted Session Key (Sent to User): " + encryptedSessionKey);

        // User decrypts the session key
        SecretKey decryptedSessionKey = decryptKey(encryptedSessionKey, userKey);
        System.out.println("✅ User Decrypted Session Key: " + Base64.getEncoder().encodeToString(decryptedSessionKey.getEncoded()));
    }

    // Generate AES key (128-bit)
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128, new SecureRandom());
        return keyGenerator.generateKey();
    }

    // Encrypt session key using the user's pre-shared key
    public static String encryptKey(SecretKey sessionKey, SecretKey userKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, userKey);
        byte[] encryptedKey = cipher.doFinal(sessionKey.getEncoded());
        return Base64.getEncoder().encodeToString(encryptedKey);
    }

    // Decrypt session key
    public static SecretKey decryptKey(String encryptedKey, SecretKey userKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, userKey);
        byte[] decryptedKeyBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedKey));
        return new javax.crypto.spec.SecretKeySpec(decryptedKeyBytes, "AES");
    }
}