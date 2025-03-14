package Week_1.Table;

import java.util.Base64;

public class BinaryToBase64 {

    public static void main(String[] args) {
        // Step 1: Define 6 bytes of binary data
        byte[] binaryData = "Hello!".getBytes();

        System.out.println();

        // Step 2: Print the binary data for reference
        System.out.println("Binary Data (8 bits per byte):");
        printBinaryData(binaryData);
        
        System.out.println();

        System.out.println("Binary Data (6 bits per byte):");
        printBinaryDataIn6BitChunks(binaryData);

        // Step 3: Convert the binary data to Base64
        String base64Encoded = Base64.getEncoder().encodeToString(binaryData);

        // Step 4: Display Base64 conversion details
        System.out.println("Base64 Encoded String: " + base64Encoded);

        // Step 5: Perform bit-by-bit Base64 mapping
        System.out.println("\nBit-by-Bit Mapping to Base64:");
        bitByBitBase64Mapping(binaryData);
    }

    // Helper: Print binary representation of byte array
    public static void printBinaryData(byte[] data) {
        for (byte b : data) {
            System.out.print(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0') + " ");
        }
        System.out.println();
    }

    // Helper: Perform bit-by-bit mapping to Base64
    public static void bitByBitBase64Mapping(byte[] data) {
        StringBuilder bitStream = new StringBuilder();

        // Convert each byte to binary and append to bitStream
        for (byte b : data) {
            bitStream.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'));
        }

        // Process in chunks of 6 bits
        for (int i = 0; i < bitStream.length(); i += 6) {
            String sixBits = bitStream.substring(i, Math.min(i + 6, bitStream.length()));
            if (sixBits.length() < 6) {
                // Pad with zeros if less than 6 bits
                sixBits = String.format("%-6s", sixBits).replace(' ', '0');
            }

            // Convert 6 bits to Base64 index
            int base64Index = Integer.parseInt(sixBits, 2);
            char base64Char = base64Character(base64Index);

            // Display mapping
            System.out.println("Binary: " + sixBits + " -> Decimal: " + base64Index + " -> Base64: " + base64Char);
        }
    }

    // Helper: Map Base64 index to character
    public static char base64Character(int index) {
        final String base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        return base64Chars.charAt(index);
    }

    public static void printBinaryDataIn6BitChunks(byte[] data) {
        StringBuilder binaryString = new StringBuilder();
        for (byte b : data) {
            binaryString.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'));
        }

        for (int i = 0; i < binaryString.length(); i += 6) {
            String sixBits = binaryString.substring(i, Math.min(i + 6, binaryString.length()));
            if (sixBits.length() < 6) {
                sixBits = String.format("%-6s", sixBits).replace(' ', '0');
            }
            System.out.print(sixBits + " ");
        }
        System.out.println();
    }
}