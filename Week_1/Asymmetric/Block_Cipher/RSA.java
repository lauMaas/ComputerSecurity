package Week_1.Asymmetric.Block_Cipher;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class RSA {
    public static void main(String[] args) throws Exception {
        // Step 1: Generate RSA Key Pairs for Person A and Person B
        System.out.println("Generating keys for Person A...");
        KeyPair personAKeyPair = generateRSAKeyPair();
        PublicKey personAPublicKey = personAKeyPair.getPublic();
        PrivateKey personAPrivateKey = personAKeyPair.getPrivate();
        System.out.println("Person A's Public Key (Base64): " + formatKeyInBase64(personAPublicKey.getEncoded()));
        System.out.println("Person A's Private Key (Base64): " + formatKeyInBase64(personAPrivateKey.getEncoded()));

        System.out.println("Generating keys for Person B...");
        KeyPair personBKeyPair = generateRSAKeyPair();
        PublicKey personBPublicKey = personBKeyPair.getPublic();
        PrivateKey personBPrivateKey = personBKeyPair.getPrivate();
        System.out.println("Person B's Public Key (Base64): " + formatKeyInBase64(personBPublicKey.getEncoded()));
        System.out.println("Person B's Private Key (Base64): " + formatKeyInBase64(personBPrivateKey.getEncoded()));

        // Step 2: Person A encrypts a message for Person B using Person B's public key
        String messageFromA = "HELLO, THIS IS Laurin";
        System.out.println("\nPerson A wants to send: " + messageFromA);
        String encryptedMessageForB = encrypt(messageFromA, personBPublicKey);
        System.out.println("Encrypted Message for Person B: " + encryptedMessageForB);

        // Step 3: Person B decrypts the message using their private key
        String decryptedMessageForB = decrypt(encryptedMessageForB, personBPrivateKey);
        System.out.println("Person B decrypted the message: " + decryptedMessageForB);

        // Step 4: Person B replies to Person A
        String replyFromB = "HELLO, Laurin! THIS IS Person B.";
        System.out.println("\nPerson B wants to reply: " + replyFromB);
        String encryptedReplyForA = encrypt(replyFromB, personAPublicKey);
        System.out.println("Encrypted Reply for Person A: " + encryptedReplyForA);

        // Step 5: Person A decrypts the reply using their private key
        String decryptedReplyForA = decrypt(encryptedReplyForA, personAPrivateKey);
        System.out.println("Person A decrypted the reply: " + decryptedReplyForA);
    }

    // Method to generate an RSA Key Pair
    private static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // Key size (2048 bits)
        return keyGen.generateKeyPair();
    }

    // Method to encrypt a message using a public key
    private static String encrypt(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes); // Encode as Base64 for easy viewing
    }

    // Method to decrypt a message using a private key
    private static String decrypt(String encryptedMessage, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes); // Convert bytes back to string
    }

    // Method to format a key in Base64
    private static String formatKeyInBase64(byte[] keyBytes) {
        return Base64.getEncoder().encodeToString(keyBytes);
    }
}