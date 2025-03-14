package Week_2.ExchangeAlgorithm.Asymmetric;

import java.math.BigInteger;
import java.security.SecureRandom;

public class ElGamal {
    public static void main(String[] args) {
        // Step 1: Key Generation
        BigInteger modulus = new BigInteger("456789098765");  // Large prime p
        BigInteger base = new BigInteger("1234567891");        // Primitive root g
        BigInteger privateKey = new BigInteger("123456789");   // Alice's private key

        // Compute public key: y = g^x mod p
        BigInteger publicKey = modExp(base, privateKey, modulus);

        System.out.println("ElGamal Key Generation:");
        System.out.println("Modulus (p): " + modulus);
        System.out.println("Base (g): " + base);
        System.out.println("Private Key (x): " + privateKey);
        System.out.println("Public Key (y): " + publicKey);
        System.out.println();

        // Step 2: Encryption
        BigInteger message = new BigInteger("9876543210");  // Example plaintext message
        BigInteger ephemeralKey = new BigInteger("98765");  // Random ephemeral key k

        // Compute ciphertext:
        BigInteger c1 = modExp(base, ephemeralKey, modulus);           // c1 = g^k mod p
        BigInteger c2 = (message.multiply(modExp(publicKey, ephemeralKey, modulus))).mod(modulus); // c2 = m * y^k mod p

        System.out.println("ElGamal Encryption:");
        System.out.println("Original Message: " + message);
        System.out.println("Ephemeral Key (k): " + ephemeralKey);
        System.out.println("Ciphertext c1: " + c1);
        System.out.println("Ciphertext c2: " + c2);
        System.out.println();

        // Step 3: Decryption
        BigInteger sharedSecret = modExp(c1, privateKey, modulus);   // Compute shared secret s = c1^x mod p
        BigInteger decryptedMessage = (c2.multiply(sharedSecret.modInverse(modulus))).mod(modulus); // m = c2 / s mod p

        System.out.println("ElGamal Decryption:");
        System.out.println("Shared Secret (s): " + sharedSecret);
        System.out.println("Decrypted Message: " + decryptedMessage);
    }

    // Modular exponentiation function
    public static BigInteger modExp(BigInteger base, BigInteger exp, BigInteger mod) {
        return base.modPow(exp, mod);  // Efficient exponentiation in Java
    }
}