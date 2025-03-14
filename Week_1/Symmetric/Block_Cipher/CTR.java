package Week_1.Symmetric.Block_Cipher;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

// Counter (CTR) mode of operation for AES

public class CTR {
    private static final int BLOCK_SIZE = 16; // 128-bit AES block size

    public static void main(String[] args) throws Exception {
        String plaintext = "HELLO WORLD, THIS IS Laurin"; // Example plaintext
        byte[] plaintextBytes = plaintext.getBytes();

        // Step 1: Generate AES Key
        SecretKey key = generateAESKey();

        // Step 2: Generate a Random Nonce (Half of Counter)
        byte[] nonce = generateNonce(BLOCK_SIZE / 2); // 64-bit nonce

        // Step 3: Encrypt plaintext using AES-CTR mode
        byte[] ciphertext = encryptCTR(plaintextBytes, key, nonce);

        // Step 4: Decrypt ciphertext using AES-CTR mode
        byte[] decryptedBytes = decryptCTR(ciphertext, key, nonce);
        String decryptedText = new String(decryptedBytes).trim();

        // Print Results
        System.out.println("Plaintext:              " + plaintext);
        System.out.println("Key (Binary):           " + bytesToBinaryString(key.getEncoded()));
        System.out.println("Ciphertext (Binary):    " + bytesToBinaryString(ciphertext));
        System.out.println("Ciphertext (Base64):    " + Base64.getEncoder().encodeToString(ciphertext));
        System.out.println("Decrypted Text:         " + decryptedText);
    }

    // Generate a random AES key (128-bit)
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // AES-128 key
        return keyGen.generateKey();
    }

    // Generate a random nonce (64-bit for CTR)
    public static byte[] generateNonce(int length) {
        byte[] nonce = new byte[length];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    // AES-CTR Encryption
    public static byte[] encryptCTR(byte[] plaintext, SecretKey key, byte[] nonce) throws Exception {
        return processCTR(plaintext, key, nonce, true);
    }

    // AES-CTR Decryption (same as encryption since XOR is reversible)
    public static byte[] decryptCTR(byte[] ciphertext, SecretKey key, byte[] nonce) throws Exception {
        return processCTR(ciphertext, key, nonce, false);
    }

    // AES-CTR Processing (Encryption and Decryption use the same function)
    public static byte[] processCTR(byte[] input, SecretKey key, byte[] nonce, boolean isEncryption) throws Exception {
        byte[] output = new byte[input.length];
        byte[] counterBlock = initializeCounter(nonce);

        System.out.println("---------------------------------------------");
        System.out.println("🔹 AES-CTR " + (isEncryption ? "Encryption" : "Decryption") + " Steps:");

        for (int i = 0; i < input.length; i += BLOCK_SIZE) {
            int length = Math.min(BLOCK_SIZE, input.length - i); // Handle last block properly
            byte[] dataBlock = Arrays.copyOfRange(input, i, i + length); // Extract actual block

            System.out.println("1. AES Operation:");
            System.out.println("Counter (Before AES):       " + bytesToBinaryString(counterBlock));
            System.out.println("Key Used (Binary):          " + bytesToBinaryString(key.getEncoded()));
            byte[] encryptedCounter = encryptCounter(counterBlock, key);
            System.out.println("AES Encrypted Counter:      " + bytesToBinaryString(encryptedCounter));
            System.out.println();
            System.out.println("2. XOR Operation:");
            System.out.println("AES Encrypted Counter:      " + bytesToBinaryString(encryptedCounter));
            System.out.println("Data Block:                 " + bytesToBinaryString(dataBlock));
            xorWithEncryptedCounter(dataBlock, output, encryptedCounter, i, length);

            incrementCounter(counterBlock); // Increment counter properly
            System.out.println();
            System.out.println("3. Increment Counter:");
            System.out.println("Counter (After Increment):  " + bytesToBinaryString(counterBlock));
            System.out.println();
        }
        return output;
    }

    // Initialize Counter Block
    private static byte[] initializeCounter(byte[] nonce) {
        byte[] counterBlock = new byte[BLOCK_SIZE];
        System.arraycopy(nonce, 0, counterBlock, 0, nonce.length); // First half is nonce
        return counterBlock;
    }

    // AES Encrypts the counter block
    private static byte[] encryptCounter(byte[] counterBlock, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(counterBlock);
    }

    // XOR input block with AES Encrypted Counter
    private static void xorWithEncryptedCounter(byte[] inputBlock, byte[] output, byte[] encryptedCounter, int offset,
            int length) {
        for (int j = 0; j < length; j++) {
            output[offset + j] = (byte) (inputBlock[j] ^ encryptedCounter[j]);
        }
        System.out.println("XOR Result (AES ⊕ Data):    "
                + bytesToBinaryString(Arrays.copyOfRange(output, offset, offset + length)));
    }

    // Increment the last 8 bytes of the counter
    private static void incrementCounter(byte[] counterBlock) {
        for (int i = counterBlock.length - 1; i >= counterBlock.length - 8; i--) { // Increment last 8 bytes
            if (++counterBlock[i] != 0)
                break; // Stop if no overflow
        }
    }

    // Convert byte array to Binary string
    public static String bytesToBinaryString(byte[] bytes) {
        StringBuilder binaryString = new StringBuilder();
        for (byte b : bytes) {
            binaryString.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0')).append(" ");
        }
        return binaryString.toString().trim();
    }
}