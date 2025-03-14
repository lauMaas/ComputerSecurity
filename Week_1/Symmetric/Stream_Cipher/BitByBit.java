package Week_1.Symmetric.Stream_Cipher;

import java.util.Random;

class BitByBitStreamCipher {

    public static void main(String[] args) {
        String plaintext = "Hello World";
        byte[] plaintextBytes = plaintext.getBytes();

        // Generate a pseudo-random keystream of the same length
        byte[] keystream = generateKeystream(plaintextBytes.length * 8);

        // Encrypt the plaintext
        byte[] ciphertext = encryptBitByBit(plaintextBytes, keystream);

        // Decrypt the ciphertext
        byte[] decryptedText = encryptBitByBit(ciphertext, keystream);

        System.out.println("Plaintext: " + plaintext);
        System.out.println("Plaintext (Binary): " + toBinaryString(plaintextBytes));
        System.out.println("Keystream: " + toBinaryString(keystream));
        System.out.println("Ciphertext: " + new String(ciphertext));
        System.out.println("Ciphertext (Binary): " + toBinaryString(ciphertext));

        System.out.println("Decrypted Text: " + new String(decryptedText));
    }

    // Encrypts (or decrypts) bit-by-bit using XOR
    public static byte[] encryptBitByBit(byte[] data, byte[] keystream) {
        byte[] result = new byte[data.length];

        for (int i = 0; i < data.length; i++) {
            byte encryptedByte = 0;
            for (int bit = 0; bit < 8; bit++) {
                int dataBit = (data[i] >> (7 - bit)) & 1; // Extract bit
                int keyBit = (keystream[i] >> (7 - bit)) & 1; // Get keystream bit
                int encryptedBit = dataBit ^ keyBit; // XOR operation
                encryptedByte |= (encryptedBit << (7 - bit)); // Set bit in new byte
            }
            result[i] = encryptedByte;
        }
        return result;
    }

    // Generate a pseudo-random keystream of n bits (stored as bytes)
    public static byte[] generateKeystream(int bitLength) {
        byte[] keystream = new byte[bitLength / 8];
        Random random = new Random();
        random.nextBytes(keystream);
        return keystream;
    }

    // Convert a byte array to a binary string for display
    public static String toBinaryString(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%8s ", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'));
        }
        return sb.toString();
    }
}
