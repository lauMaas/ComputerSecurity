package Week_1.Symmetric.Stream_Cipher;

import java.util.Base64;

public class CaesarCipher {

    public static void main(String[] args) {
        String plaintext = "Hello, This is Laurin!";
        int key = 3; // Caesar shift key

        System.out.println("=== CAESAR CIPHER DEMO ===\n");
        System.out.println("Original Message:   " + plaintext);
        System.out.println("Shift Amount:       " + key + " positions\n");

        // Encrypt
        String encrypted = encrypt(plaintext, key);
        System.out.println("Encrypted Message:  " + encrypted);
        System.out.println("Encrypted (Binary): " + toBinaryString(encrypted));
        System.out.println("Encrypted (Base64): " + Base64.getEncoder().encodeToString(encrypted.getBytes()));
        System.out.println();

        // Decrypt
        String decrypted = decrypt(encrypted, key);
        System.out.println("Decrypted Message:  " + decrypted + "\n");

        // Print shift table for the specific message
        printShiftTableForMessage(plaintext, key);
    }

    // Caesar Cipher Encryption
    public static String encrypt(String input, int shift) {
        StringBuilder result = new StringBuilder();
        for (char c : input.toCharArray()) {
            char enc = (char) ((c + shift) % 256);
            result.append(enc);
        }
        return result.toString();
    }

    // Decrypt using inverse shift
    public static String decrypt(String input, int shift) {
        StringBuilder result = new StringBuilder();
        for (char c : input.toCharArray()) {
            char dec = (char) ((c - shift + 256) % 256); // ensure no negative values
            result.append(dec);
        }
        return result.toString();
    }

    // Print shift table for each character
    public static void printShiftTableForMessage(String message, int shift) {
        System.out.println("=== SHIFT TABLE FOR PLAINTEXT CHARACTERS ===");
        for (char c : message.toCharArray()) {
            char shifted;
            if (Character.isUpperCase(c)) {
                shifted = (char) (((c - 'A' + shift) % 26) + 'A');
            } else if (Character.isLowerCase(c)) {
                shifted = (char) (((c - 'a' + shift) % 26) + 'a');
            } else {
                shifted = (char) (c + shift); // shift all other chars
            }
            System.out.printf("  '%c' (%d) -> '%c' (%d) | Binary: %8s -> %8s\n",
                    c, (int) c, shifted, (int) shifted,
                    Integer.toBinaryString(c | 0x100).substring(1),
                    Integer.toBinaryString(shifted | 0x100).substring(1));
        }
    }

    // Convert string to binary
    public static String toBinaryString(String text) {
        StringBuilder binary = new StringBuilder();
        for (char c : text.toCharArray()) {
            binary.append(String.format("%8s", Integer.toBinaryString(c)).replace(' ', '0')).append(" ");
        }
        return binary.toString().trim();
    }
}
