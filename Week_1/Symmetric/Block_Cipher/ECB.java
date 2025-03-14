package Week_1.Symmetric.Block_Cipher;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Arrays;

// Elecrtic Code Book (ECB) mode of operation for AES

public class ECB {
    public static void main(String[] args) throws Exception {
        String plaintext = "HELLO WORLD, THIS IS Laurin"; // 32 characters (2 blocks of 16 bytes)
        byte[] plaintextBytes = plaintext.getBytes();

        int blockSize = 16; // AES block size

        // Step 1: Generate a 128-bit (16-byte) AES key
        SecretKey key = generateAESKey();

        // Step 2: Encrypt plaintext in AES-ECB mode
        byte[] ciphertext = encryptECB(plaintextBytes, key);

        // Step 3: Decrypt ciphertext in AES-ECB mode
        byte[] decryptedBytes = decryptECB(ciphertext, key);
        String decryptedText = new String(decryptedBytes).trim();

        // Extract individual blocks for debugging
        byte[] block1 = block(0, plaintextBytes, blockSize);
        byte[] block2 = block(1, plaintextBytes, blockSize);

        // Encrypt individual blocks (for print visualization)
        byte[] encryptedBlock1 = encryptBlock(block1, key);
        byte[] encryptedBlock2 = encryptBlock(block2, key);

        // Step 4: Display results
        System.out.println("Plaintext (ASCII):      " + plaintext);
        System.out.println("Plaintext (Binary):     " + bytesToBinaryString(plaintextBytes));
        System.out.println("Plaintext (HEX):        " + bytesToHex(plaintextBytes));
        System.out.println("Plaintext (Base64):     " + Base64.getEncoder().encodeToString(plaintextBytes));
        System.out.println("---------------------------------------------");
        System.out.println("Block 1 (Binary):       " + bytesToBinaryString(block1));
        System.out.println("Block 2 (Binary):       " + bytesToBinaryString(block2));
        System.out.println("Key Block (Binary):     " + bytesToBinaryString(key.getEncoded()));
        System.out.println("---------------------------------------------");
        System.out.println("AES Encryption 1:");
        System.out.println("Key Block (Binary):     " + bytesToBinaryString(key.getEncoded()));
        System.out.println("Block 1 (Binary):       " + bytesToBinaryString(block1));
        System.out.println("AES Result (Block 1):   " + bytesToBinaryString(encryptedBlock1));
        System.out.println("Block 1 (HEX):          " + bytesToHex(encryptedBlock1));
        System.out.println();
        System.out.println("AES Encryption 2:");
        System.out.println("Key Block (Binary):     " + bytesToBinaryString(key.getEncoded()));
        System.out.println("Block 2 (Binary):       " + bytesToBinaryString(block2));
        System.out.println("AES Result (Block 2):   " + bytesToBinaryString(encryptedBlock2));
        System.out.println("Block 2 (HEX):          " + bytesToHex(encryptedBlock2));
        System.out.println("---------------------------------------------");
        System.out.println("Ciphertext (ASCII):     " + new String(ciphertext));
        System.out.println("Ciphertext (Binary):    " + bytesToBinaryString(ciphertext));
        System.out.println("Ciphertext (HEX):       " + bytesToHex(ciphertext));
        System.out.println("Ciphertext (Base64):    " + Base64.getEncoder().encodeToString(ciphertext));
        System.out.println("---------------------------------------------");
        System.out.println("Decrypted Text:         " + decryptedText);
    }

    // Generate a random AES-128 key
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // AES-128 key
        return keyGen.generateKey();
    }

    // AES-ECB Encrypt a full plaintext message
    public static byte[] encryptECB(byte[] plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    // AES-ECB Decrypt the full ciphertext
    public static byte[] decryptECB(byte[] ciphertext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(ciphertext);
    }

    // AES Encrypt a single block (for debugging individual block encryption)
    public static byte[] encryptBlock(byte[] block, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(block);
    }

    // Extract a specific block from data
    public static byte[] block(int blockNumber, byte[] data, int blockSize) {
        int start = blockNumber * blockSize;
        int end = Math.min(start + blockSize, data.length); // Handle last block

        byte[] block = new byte[blockSize];
        Arrays.fill(block, (byte) 0); // Fill block with zeros for padding
        System.arraycopy(data, start, block, 0, end - start); // Copy data into block
        return block;
    }

    // Convert byte array to binary string
    public static String bytesToBinaryString(byte[] data) {
        StringBuilder binaryString = new StringBuilder();
        for (byte b : data) {
            binaryString.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0')).append(" ");
        }
        return binaryString.toString().trim();
    }

    // Convert byte array to HEX string
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02X ", b));
        }
        return hexString.toString().trim();
    }
}