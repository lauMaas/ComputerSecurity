package Week_1.Symmetric.Block_Cipher;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Arrays;

// Cipher Block Chaining (CBC) mode of operation for AES

public class CBC {
    public static void main(String[] args) throws Exception {
        String plaintext = "HELLO WORLD, THIS IS Laurin"; // 32 characters (2 blocks of 16 bytes)
        byte[] plaintextBytes = plaintext.getBytes();
        int blockSize = 16; // AES block size

        // Step 1: Generate AES key and IV
        SecretKey key = generateAESKey();
        byte[] iv = generateIV(blockSize);

        // Step 2: Encrypt plaintext in AES-CBC mode
        byte[] ciphertext = encryptCBC(plaintextBytes, key, iv);

        // Step 3: Decrypt ciphertext in AES-CBC mode
        byte[] decryptedBytes = decryptCBC(ciphertext, key, iv);
        String decryptedText = new String(decryptedBytes).trim();

        // Extract individual blocnks for debugging
        byte[] block1 = block(0, plaintextBytes, blockSize);
        byte[] block2 = block(1, plaintextBytes, blockSize);

        // Encrypt individual blocks (for print visualization)

        // Step 4: Display results
        // Step 4: Display results
        System.out.println("Plaintext (ASCII):                      " + plaintext);
        System.out.println("Plaintext (Binary):                     " + bytesToBinaryString(plaintextBytes));
        System.out.println("Plaintext (HEX):                        " + bytesToHex(plaintextBytes));
        System.out.println("Plaintext (Base64):                     " + Base64.getEncoder().encodeToString(plaintextBytes));
        System.out.println("---------------------------------------------");

        // Print IV
        System.out.println("IV (Binary):                            " + bytesToBinaryString(iv));
        System.out.println("IV (HEX):                               " + bytesToHex(iv));
        System.out.println("---------------------------------------------");

        // Extract blocks
        System.out.println("Block 1 (Binary):                       " + bytesToBinaryString(block1));
        System.out.println("Block 1 (ASCII):                        " + new String(block1));
        System.out.println("Block 2 (Binary):                       " + bytesToBinaryString(block2));
        System.out.println("Block 2 (ASCII):                        " + new String(block2));
        System.out.println("Key Used (Binary):                      " + bytesToBinaryString(key.getEncoded()));
        System.out.println("---------------------------------------------");

        // Encrypt Block 1
        System.out.println("🔹 AES-CBC Encryption Step 1 (Block 1)");
        System.out.println("Block 1 (Before XOR):                   " + bytesToBinaryString(block1));
        System.out.println("IV (Used for XOR):                      " + bytesToBinaryString(iv));
        byte[] xorBlock1 = xorOperation(block1, iv);
        System.out.println("XOR Result (Block 1 ⊕ IV):              " + bytesToBinaryString(xorBlock1));

        System.out.println();

        byte[] encryptedBlock1 = encryptBlockCBC(block1, key, iv);
        System.out.println("Key Used (Binary):                      " + bytesToBinaryString(key.getEncoded()));
        System.out.println("XOR Result (Block 1 ⊕ IV):              " + bytesToBinaryString(xorBlock1));
        System.out.println("AES Encrypted (Block 1 XORed):          " + bytesToBinaryString(encryptedBlock1));
        System.out.println("Encr Block 1 (HEX):                     " + bytesToHex(encryptedBlock1));
        System.out.println("---------------------------------------------");

        // Encrypt Block 2
        System.out.println("🔹 AES-CBC Encryption Step 2 (Block 2)");
        System.out.println("Block 2 (Before XOR):                   " + bytesToBinaryString(block2));
        System.out.println("Ciphertext Block 1 (Used for XOR):      " + bytesToBinaryString(encryptedBlock1));
        byte[] xorBlock2 = xorOperation(block2, encryptedBlock1);
        System.out.println("XOR Result (Block 2 ⊕ Prev Ciphertext): " + bytesToBinaryString(xorBlock2));
        
        System.out.println();
        
        byte[] encryptedBlock2 = encryptBlockCBC(block2, key, encryptedBlock1);
        System.out.println("Key Used (Binary):                      " + bytesToBinaryString(key.getEncoded()));
        System.out.println("XOR Result (Block 2 ⊕ Prev Ciphertext): " + bytesToBinaryString(xorBlock2));
        System.out.println("AES Encrypted (Block 2 XORed):          " + bytesToBinaryString(encryptedBlock2));
        System.out.println("Encr Block 2 (HEX):                     " + bytesToHex(encryptedBlock2));
        System.out.println("---------------------------------------------");

        // Print Final Ciphertext
        System.out.println("Ciphertext (Binary):                    " + bytesToBinaryString(ciphertext));
        System.out.println("Ciphertext (HEX):                       " + bytesToHex(ciphertext));
        System.out.println("Ciphertext (Base64):                    " + Base64.getEncoder().encodeToString(ciphertext));
        System.out.println("---------------------------------------------");

        // Decryption Result
        System.out.println("Decrypted Text:              " + decryptedText);
    }

    // Generate a random AES-128 key
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // AES-128 key
        return keyGen.generateKey();
    }

    // Generate a random IV
    public static byte[] generateIV(int blockSize) {
        byte[] iv = new byte[blockSize];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    // AES-CBC Encrypt full plaintext
    public static byte[] encryptCBC(byte[] plaintext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(plaintext);
    }

    // AES-CBC Decrypt full ciphertext
    public static byte[] decryptCBC(byte[] ciphertext, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(ciphertext);
    }

    // Encrypt a single block (for debugging CBC behavior)
    public static byte[] encryptBlockCBC(byte[] block, SecretKey key, byte[] prevCiphertext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(prevCiphertext));
        return cipher.doFinal(block);
    }

    // Extract a specific block from data
    public static byte[] block(int blockNumber, byte[] data, int blockSize) {
        int start = blockNumber * blockSize;
        int end = Math.min(start + blockSize, data.length);

        byte[] block = new byte[blockSize];
        Arrays.fill(block, (byte) 0); // Zero padding
        System.arraycopy(data, start, block, 0, end - start);
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

    // XOR each byte of plaintext with key
    public static byte[] xorOperation(byte[] plaintext, byte[] key) {
        byte[] ciphertext = new byte[plaintext.length];
        for (int i = 0; i < plaintext.length; i++) {
            ciphertext[i] = (byte) (plaintext[i] ^ key[i]); // XOR operation
        }
        return ciphertext;
    }
}