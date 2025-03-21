package Week_1.DigitalSignature;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class DigitalSignatureHash {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        int bitLength = 16; // Small bit-length
        SecureRandom random = new SecureRandom();

        // Generate RSA key pair for Alice
        System.out.println("Alice's Keys:");
        RSAKeyPair2 alice = new RSAKeyPair2(bitLength, random);
        alice.printKeys();

        System.out.println("\n--------------------------------------------------\n");

        // Message
        String message = "HELLO";
        System.out.println("Original Message: " + message);

        // Alice signs the message with a hash
        BigInteger hash = alice.hashMessage(message);
        BigInteger signature = alice.signMessageWithHash(message); // Line 26
        System.out.println("Alice's Message Hashed: " + hash);
        System.out.println("Alice's Digital Signature (With Hashing - Single Number): " + signature);

        System.out.println("\n--------------------------------------------------\n");

        // Bob verifies the signature
        boolean isValid = alice.verifySignatureWithHash(message, signature);
        System.out.println("Bob Verifies Alice's Signature (With Hashing): " + (isValid ? "✅ Valid" : "❌ Invalid"));
    }
}

class RSAKeyPair2 {
    public final BigInteger p, q, N, phi, e, d;
    public final SecureRandom random;

    public RSAKeyPair2(int bitLength, SecureRandom random) {
        this.random = random;
        this.p = BigInteger.probablePrime(bitLength, random);
        this.q = BigInteger.probablePrime(bitLength, random);
        this.N = p.multiply(q);
        this.phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        this.e = BigInteger.valueOf(65537); // Common RSA public exponent
        if (!e.gcd(phi).equals(BigInteger.ONE)) {
            throw new IllegalArgumentException("e and phi(N) are not coprime!");
        }

        this.d = e.modInverse(phi);
    }

    public void printKeys() {
        System.out.println("p: " + p);
        System.out.println("q: " + q);
        System.out.println("N (p * q): " + N);
        System.out.println("phi(N): " + phi);
        System.out.println("Public Key (e, N): (" + e + ", " + N + ")");
        System.out.println("Private Key (d, N): (" + d + ", " + N + ")");
    }

    // 🔹 Step 1: Compute Hash of Message
    public BigInteger hashMessage(String message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(message.getBytes(StandardCharsets.UTF_8));
        BigInteger hash = new BigInteger(1, hashBytes);
        return hash.mod(N);
    }

    // 🔹 Step 2: Sign the Hash with Private Key
    public BigInteger signMessageWithHash(String message) throws NoSuchAlgorithmException {
        BigInteger hash = hashMessage(message);
        return hash.modPow(d, N); // S = Hash(M)^d mod N
    }

    // 🔹 Step 4: Verify Signature with Public Key
    public boolean verifySignatureWithHash(String message, BigInteger signature) throws NoSuchAlgorithmException {
        BigInteger expectedHash = hashMessage(message);
        BigInteger decryptedHash = signature.modPow(e, N); // Decrypt signature with public key

        System.out.println("Bob's Decrypted Hash: " + decryptedHash);
        System.out.println("Bob's Expected Hash: " + expectedHash);
        return expectedHash.equals(decryptedHash);
    }
}