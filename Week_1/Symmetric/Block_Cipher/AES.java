package Week_1.Symmetric.Block_Cipher;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class AES {
    public static void main(String[] args) {
        String plainText = "Hello World!!!";
        byte[] plainTextBytes = plainText.getBytes();
        int blockSizeByte = 16; // AES block size (16 bytes per block)

        byte[] key = generateAESKey();


    }

    public static byte[] xOR(byte[] block1, byte[] block2) {
        byte[] result = new byte[block1.length];
        for (int i = 0; i < block1.length; i++) {
            result[i] = (byte) (block1[i] ^ block2[i]);
        }
        return result;
    }

    public static byte[] generateAESKey() {
        // Generate AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // 128-bit key
        SecretKey key = keyGen.generateKey();
        return key.getEncoded();
    }

}
