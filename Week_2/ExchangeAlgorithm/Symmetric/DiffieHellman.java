package Week_2.ExchangeAlgorithm.Symmetric;

import java.math.BigInteger;

public class DiffieHellman {
    public static void main(String[] args) {
        // Alice and Bob agree on a prime number p and a base g
        BigInteger modulus = new BigInteger("104729"); // Large prime number
        BigInteger base = new BigInteger("17");

        // Alice generates a private key a
        BigInteger aSecret = new BigInteger("8");

        // Bob generates a private key b
        BigInteger bSecret = new BigInteger("15");

        // Alice computes A = g^a mod p
        BigInteger A = modExp(base, aSecret, modulus);

        // Bob computes B = g^b mod p
        BigInteger B = modExp(base, bSecret, modulus);

        // Alice and Bob exchange A and B
        // Alice computes s = B^a mod p
        BigInteger sA = modExp(B, aSecret, modulus);

        // Bob computes s = A^b mod p
        BigInteger sB = modExp(A, bSecret, modulus);

        System.out.println("Shared between Alice and Bob");
        System.out.println("Base:                    " + base);
        System.out.println("Prime (Modulus):         " + modulus);
        System.out.println();
        System.out.println("Calculating what Alice and Bob share");
        System.out.println("Alice's Private Key:     " + aSecret);
        System.out.println("Bob's Private Key:       " + bSecret);
        System.out.println("Alice's Public Key:      " + A);
        System.out.println("Bob's Public Key:        " + B);
        System.out.println();
        System.out.println("Shared Secret Key (Should be the same)");
        System.out.println("Alice's Secret Key:      " + sA);
        System.out.println("Bob's Secret Key:        " + sB);
    }

    // Method to perform modular exponentiation using BigInteger
    public static BigInteger modExp(BigInteger base, BigInteger exp, BigInteger mod) {
        return base.modPow(exp, mod); // Java's built-in efficient method
    }
}