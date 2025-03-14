package Week_1.DigitalSignature;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;

public class DigitalSignature {
    public static void main(String[] args) {
        int bitLength = 16; // Small bit-length for clarity
        SecureRandom random = new SecureRandom();

        // Generate keys for Alice
        System.out.println("Alice's Keys:");
        RSAKeyPair1 alice = new RSAKeyPair1(bitLength, random);
        alice.printKeys();

        // Generate keys for Bob (not needed for signature verification)
        System.out.println("\nBob's Keys:");
        RSAKeyPair1 bob = new RSAKeyPair1(bitLength, random);
        bob.printKeys();

        System.out.println("\n--------------------------------------------------\n");
        System.out.println("Digital Signature Process:");

        // Message
        String message = "HELLO";
        System.out.println("\nOriginal Message: " + message);
        printTable(message, alice);

        // Alice signs the message character-by-character
        BigInteger[] aliceSignature = alice.signMessagePerCharacter(message);
        System.out.println("\nAlice's Digital Signature (Per Character): ");
        for (BigInteger s : aliceSignature) {
            System.out.print(s + " ");
        }
        System.out.println();

        System.out.println("\n--------------------------------------------------\n");
        System.out.println("Digital Signature Verification:");

        // Bob verifies the signature using Alice's public key
        boolean isValid = alice.verifySignaturePerCharacter(message, aliceSignature);
        System.out.println("Bob Verifies Alice's Signature: " + (isValid ? "✅ Valid" : "❌ Invalid"));
    }

    public static void printTable(String message, RSAKeyPair1 keyPair) {
        System.out.printf("\n%-10s %-10s %-10s %-50s %-50s\n",
                "Char", "ASCII", "M", "Signature (S = M^d mod N)", "Verification (M' = S^e mod N)");
        System.out.println(
                "----------------------------------------------------------------------------------------------------------");

        StringBuilder signedMessage = new StringBuilder();
        StringBuilder verifiedMessage = new StringBuilder();

        for (char c : message.toCharArray()) {
            BigInteger M = BigInteger.valueOf((int) c); // Convert char to BigInteger
            BigInteger S = M.modPow(keyPair.d, keyPair.N); // Signature: S = M^d mod N
            BigInteger M_prime = S.modPow(keyPair.e, keyPair.N); // Verification: M' = S^e mod N

            // Print table row
            System.out.printf("%-10c %-10d %-10d %-50s %-50s\n",
                    c, (int) c, M,
                    M + "^" + keyPair.d + " mod " + keyPair.N + " = " + S,
                    S + "^" + keyPair.e + " mod " + keyPair.N + " = " + M_prime);

            signedMessage.append(S).append(" ");
            verifiedMessage.append((char) M_prime.intValue()); // Convert back to char
        }
    }
}

class RSAKeyPair1 {
    public final BigInteger p, q, N, phi, e, d;
    public final SecureRandom random;

    public RSAKeyPair1(int bitLength, SecureRandom random) {
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
        System.out.println("p:                        " + p);
        System.out.println("q:                        " + q);
        System.out.println("N (p * q):                " + N);
        System.out.println("phi(N) (p-1)*(q-1):       " + phi);
        System.out.println("Public Key (e, N):       (" + e + ", " + N + ")");
        System.out.println("Private Key (d, N):      (" + d + ", " + N + ")");
    }

    // 🔹 Sign each character separately
    public BigInteger[] signMessagePerCharacter(String message) {
        BigInteger[] signatures = new BigInteger[message.length()];
        for (int i = 0; i < message.length(); i++) {
            BigInteger M = BigInteger.valueOf((int) message.charAt(i));
            signatures[i] = M.modPow(d, N); // S = M^d mod N
        }
        return signatures;
    }

    // 🔹 Verify each character separately
    public boolean verifySignaturePerCharacter(String message, BigInteger[] signature) {
        for (int i = 0; i < message.length(); i++) {
            BigInteger M = BigInteger.valueOf((int) message.charAt(i));
            BigInteger M_prime = signature[i].modPow(e, N); // M' = S^e mod N
            if (!M.equals(M_prime)) {
                return false; // If any character fails, return false
            }
        }
        return true;
    }
}