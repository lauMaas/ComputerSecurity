package Week_2.ExchangeAlgorithm.Symmetric;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Base64;

public class KTC {
    public static void main(String[] args) throws Exception {
        // Generate a session key to be translated
        SecretKey sessionKey = generateAESKey();
        System.out.println(
                "🔐 KTC Session Key (Plaintext): " + Base64.getEncoder().encodeToString(sessionKey.getEncoded()));

        // User A and User B have different pre-shared keys
        SecretKey userAKey = generateAESKey();
        SecretKey userBKey = generateAESKey();

        // KTC translates the session key for both users
        String encryptedForUserA = encryptKey(sessionKey, userAKey);
        String encryptedForUserB = encryptKey(sessionKey, userBKey);

        System.out.println("🔒 Session Key Encrypted for User A: " + encryptedForUserA);
        System.out.println("🔒 Session Key Encrypted for User B: " + encryptedForUserB);

        // Users decrypt their respective keys
        SecretKey decryptedKeyA = decryptKey(encryptedForUserA, userAKey);
        SecretKey decryptedKeyB = decryptKey(encryptedForUserB, userBKey);

        System.out.println(
                "✅ User A Decrypted Session Key: " + Base64.getEncoder().encodeToString(decryptedKeyA.getEncoded()));
        System.out.println(
                "✅ User B Decrypted Session Key: " + Base64.getEncoder().encodeToString(decryptedKeyB.getEncoded()));
    }

    // Generate AES key
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128, new SecureRandom());
        return keyGenerator.generateKey();
    }

    // Encrypt session key using a user's pre-shared key
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