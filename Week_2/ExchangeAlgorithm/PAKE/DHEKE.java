package Week_2.ExchangeAlgorithm.PAKE;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Base64;

public class DHEKE {
    public static void main(String[] args) throws Exception {
        // Shared password (known to both Alice and Bob in advance)
        String password = "w";

        // Shared agreement: prime modulus (p) and base (g)
        BigInteger modulus = new BigInteger("104729");
        BigInteger base = new BigInteger("17");

        // Private keys
        BigInteger aSecret = new BigInteger("8");
        BigInteger bSecret = new BigInteger("15");

        // Compute public keys
        BigInteger A = base.modPow(aSecret, modulus);
        BigInteger B = base.modPow(bSecret, modulus);

        // Encrypt A and B before exchange
        String encryptedA = encrypt(A.toString(), password);
        String encryptedB = encrypt(B.toString(), password);

        // Exchange and decrypt A and B
        BigInteger A_received = new BigInteger(decrypt(encryptedA, password));
        BigInteger B_received = new BigInteger(decrypt(encryptedB, password));

        // Compute shared secrets
        BigInteger sA = B_received.modPow(aSecret, modulus);
        BigInteger sB = A_received.modPow(bSecret, modulus);

        // Output
        System.out.println("=== DHEKE - Encrypted Exchange over DH ===\n");

        System.out.println("[Public Agreement]");
        System.out.println("  Prime modulus (p): " + modulus);
        System.out.println("  Base (g):          " + base);
        System.out.println("  Shared secret password (w): '" + password + "'\n");

        System.out.println("[Private Keys - kept secret]");
        System.out.println("  Alice's private key (a): " + aSecret);
        System.out.println("  Bob's private key (b):   " + bSecret);

        System.out.println("\n[Public Keys - before exchange]");
        System.out.println("  Alice's public key (A = g^a mod p): " + A);
        System.out.println("  Bob's public key (B = g^b mod p):   " + B);

        System.out.println("\n[Encrypted Exchange using password 'w']");
        System.out.println("  Encrypted A (sent to Bob): " + encryptedA);
        System.out.println("  Encrypted B (sent to Alice): " + encryptedB);

        System.out.println("\n[Decrypted Public Keys]");
        System.out.println("  Bob receives and decrypts A: " + A_received);
        System.out.println("  Alice receives and decrypts B: " + B_received);

        System.out.println("\n[Shared Secret Key - computed independently]");
        System.out.println("  Alice computes: (B^a mod p) = " + sA);
        System.out.println("  Bob computes:   (A^b mod p) = " + sB);

        System.out.println("\n✅ Shared Secret Match: " + sA.equals(sB));
    }

    // Derive AES key from password (SHA-256, use first 16 bytes)
    private static SecretKeySpec deriveAESKey(String password) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(password.getBytes("UTF-8"));
        byte[] keyBytes = new byte[16]; // AES-128
        System.arraycopy(hash, 0, keyBytes, 0, 16);
        return new SecretKeySpec(keyBytes, "AES");
    }

    // Encrypt text using AES
    private static String encrypt(String plaintext, String password) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, deriveAESKey(password));
        byte[] encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // Decrypt text using AES
    private static String decrypt(String ciphertext, String password) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, deriveAESKey(password));
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        return new String(decrypted, "UTF-8");
    }
}
