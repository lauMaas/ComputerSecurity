package Week_1.Symmetric.Stream_Cipher;
import java.security.SecureRandom;
import java.util.Base64;


/**
 * UNSURE !!! IF EXACT LENGTH OR IF SHORTER
 */

public class VernamCipher {
    public static void main(String[] args) {
        String plaintext = "HELLO WORLD!!"; // 11-character plaintext
        int plaintextLength = plaintext.length();

        // Generate a random key of a shorter length (e.g., 5 characters)
        int keyLength = 5; // Shorter key for Vernam Cipher
        byte[] keyBytes = generateRandomKey(keyLength);
        String keyString = new String(keyBytes); // Convert key to a readable string

        // Extend the key cyclically to match plaintext length
        byte[] extendedKey = extendKey(keyBytes, plaintextLength);

        // Convert plaintext to binary bytes
        byte[] plaintextBytes = plaintext.getBytes();

        // Perform XOR encryption
        byte[] ciphertext = xorOperation(plaintextBytes, extendedKey);

        // Perform XOR decryption
        byte[] decrypted = xorOperation(ciphertext, extendedKey);

        // Convert results to different formats
        String keyBase64 = Base64.getEncoder().encodeToString(keyBytes);
        String ciphertextBase64 = Base64.getEncoder().encodeToString(ciphertext);
        String ciphertextAscii = new String(ciphertext);
        String ciphertextHex = bytesToHex(ciphertext);

        // Display Results
        System.out.println("Plaintext ASCII:      " + plaintext);
        System.out.println("Plaintext HEX:        " + bytesToHex(plaintextBytes));
        System.out.println("Plaintext Base64:     " + Base64.getEncoder().encodeToString(plaintextBytes));
        System.out.println("Key (Short ASCII):    " + keyString);
        System.out.println("Key (Short HEX):      " + bytesToHex(keyBytes));
        System.out.println("Key (Short Base64):   " + keyBase64);
        System.out.println("Extended Key ASCII:   " + new String(extendedKey));
        System.out.println("Extended Key HEX:     " + bytesToHex(extendedKey));
        System.out.println("Extended Key Base64:  " + Base64.getEncoder().encodeToString(extendedKey));
        System.out.println("--------------------");
        System.out.println("XOR Encryption");
        System.out.println("Plaintext Bin:        " + bytesToBinaryString(plaintextBytes));
        System.out.println("Extended Key Bin:     " + bytesToBinaryString(extendedKey));
        System.out.println("Ciphertext Bin:       " + bytesToBinaryString(ciphertext));
        System.out.println("--------------------");
        System.out.println("Ciphertext ASCII:     " + ciphertextAscii);
        System.out.println("Ciphertext HEX:       " + ciphertextHex);
        System.out.println("Ciphertext Base64:    " + ciphertextBase64);
        System.out.println("--------------------");
        System.out.println("XOR Decryption");
        System.out.println("Ciphertext Bin:       " + bytesToBinaryString(ciphertext));
        System.out.println("Extended Key Bin:     " + bytesToBinaryString(extendedKey));
        System.out.println("Decrypted Bin:        " + bytesToBinaryString(decrypted));
        System.out.println("--------------------");
        System.out.println("Decrypted ASCII:      " + new String(decrypted));
        System.out.println("Decrypted HEX:        " + bytesToHex(decrypted));
        System.out.println("Decrypted Base64:     " + Base64.getEncoder().encodeToString(decrypted));
    }

    // Generate a random key of a given length
    public static byte[] generateRandomKey(int length) {
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[length];
        random.nextBytes(key);
        return key;
    }

    // Extend the key cyclically to match the plaintext length
    public static byte[] extendKey(byte[] shortKey, int targetLength) {
        byte[] extendedKey = new byte[targetLength];
        for (int i = 0; i < targetLength; i++) {
            extendedKey[i] = shortKey[i % shortKey.length]; // Repeat key cyclically
        }
        return extendedKey;
    }

    // XOR each byte of plaintext with key
    public static byte[] xorOperation(byte[] plaintext, byte[] key) {
        byte[] ciphertext = new byte[plaintext.length];
        for (int i = 0; i < plaintext.length; i++) {
            ciphertext[i] = (byte) (plaintext[i] ^ key[i]); // XOR operation
        }
        return ciphertext;
    }

    // Convert byte array to binary string representation
    public static String bytesToBinaryString(byte[] bytes) {
        StringBuilder binaryString = new StringBuilder();
        for (byte b : bytes) {
            binaryString.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0')).append(" ");
        }
        return binaryString.toString();
    }

    // Convert byte array to hex string
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02X ", b));
        }
        return hexString.toString();
    }
}