package Week_2.ExchangeAlgorithm.Symmetric;

import java.math.BigInteger;

public class DiffieHellman {
    public static void main(String[] args) {
        // Shared agreement: prime modulus (p) and base (g)
        BigInteger modulus = new BigInteger("104729"); // Large prime number
        BigInteger base = new BigInteger("17");        // Primitive root mod p

        // Private keys (should be randomly generated in real scenarios)
        BigInteger aSecret = new BigInteger("8");   // Alice's private key
        BigInteger bSecret = new BigInteger("15");  // Bob's private key

        // Public keys
        BigInteger A = modExp(base, aSecret, modulus); // Alice's public key
        BigInteger B = modExp(base, bSecret, modulus); // Bob's public key

        // Shared secret computation
        BigInteger sA = modExp(B, aSecret, modulus); // Alice computes secret
        BigInteger sB = modExp(A, bSecret, modulus); // Bob computes secret

        // Output
        System.out.println("=== DIFFIE-HELLMAN KEY EXCHANGE DEMO ===\n");

        System.out.println("[Public Agreement]");
        System.out.println("  Prime modulus (p): " + modulus);
        System.out.println("  Base (g):          " + base);

        System.out.println("\n[Private Keys - kept secret]");
        System.out.println("  Alice's private key (a): " + aSecret);
        System.out.println("  Bob's private key (b):   " + bSecret);

        System.out.println("\n[Public Keys - exchanged openly]");
        System.out.println("  Alice's public key (A = g^a mod p): " + A);
        System.out.println("  Bob's public key (B = g^b mod p):   " + B);

        System.out.println("\n[Shared Secret Key - computed independently]");
        System.out.println("  Alice computes: (B^a mod p) = " + sA);
        System.out.println("  Bob computes:   (A^b mod p) = " + sB);

        System.out.println("\n✅ Shared Secret Match: " + sA.equals(sB));
    }

    // Efficient modular exponentiation using Java's BigInteger
    public static BigInteger modExp(BigInteger base, BigInteger exp, BigInteger mod) {
        return base.modPow(exp, mod);
    }
}