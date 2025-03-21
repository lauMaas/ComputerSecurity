package Week_1.Asymmetric.Block_Cipher;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAManual {
    public static void main(String[] args) {
        int bitLength = 16; // p and q are 16 bits each (~32-bit RSA key)
        SecureRandom random = new SecureRandom();

        // Step 1: Generate p and q (small primes for clarity)
        BigInteger p = BigInteger.probablePrime(bitLength, random);
        BigInteger q = BigInteger.probablePrime(bitLength, random);

        // Step 2: Compute N and phi(N)
        BigInteger N = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // Step 3: Choose e (public exponent)
        BigInteger e = BigInteger.valueOf(65537); // Common RSA public exponent
        if (!e.gcd(phi).equals(BigInteger.ONE)) {
            throw new IllegalArgumentException("e and phi(N) are not coprime!");
        }

        // Step 4: Compute d (private exponent)
        BigInteger d = e.modInverse(phi); // d = e^-1 mod phi(N)

        // Print RSA Key Generation Steps
        System.out.println();
        System.out.println("Step 1: Generate two distinct prime numbers (p, q)");
        System.out.println("p:                        " + p);
        System.out.println("q:                        " + q);

        System.out.println("\nStep 2: Compute N and φ(N)");
        System.out.println("N (p * q):                " + N);
        System.out.println("φ(N) (p-1)*(q-1):         " + phi);

        System.out.println("\nStep 3: Choose Public Exponent (e)");
        System.out.println("Chosen e:                 " + e);
        System.out.println("Verify gcd(e, φ(N)) = 1:  " + e.gcd(phi));

        System.out.println("\nStep 4: Compute Private Exponent (d)");
        System.out.println("d = e^(-1) mod φ(N)");
        System.out.println("d = " + e + "^-1 mod " + phi);
        System.out.println("d:                        " + d);

        System.out.println("\nFinal RSA Key Pairs:");
        System.out.println("Public Key (e, N):       (" + e + ", " + N + ")");
        System.out.println("Private Key (d, N):      (" + d + ", " + N + ")");
        System.out.println("\n");

        // Step 5: Encrypt and Decrypt Character by Character
        String message = "HELLO"; // 5 * 8 = 40 bits
        System.out.println("Original Message:         " + message);

        System.out.printf("%-10s %-10s %-10s %-50s %-50s\n", 
                          "Char", "ASCII", "M", "Encrypted (C = M^e mod N)", "Decrypted (M = C^d mod N)");
        System.out.println("---------------------------------------------------------------------------------------------------------------------------");

        StringBuilder encryptedMessage = new StringBuilder();
        StringBuilder decryptedMessage = new StringBuilder();

        for (char c : message.toCharArray()) {
            BigInteger M = BigInteger.valueOf((int) c); // Convert char to BigInteger
            BigInteger C = M.modPow(e, N); // Encryption: C = M^e mod N
            BigInteger decryptedM = C.modPow(d, N); // Decryption: M = C^d mod N

            // Print table row with formulas plugged in
            System.out.printf("%-10c %-10d %-10d %-50s %-50s\n", 
                              c, (int) c, M, 
                              M + "^" + e + " mod " + N + " = " + C, 
                              C + "^" + d + " mod " + N + " = " + decryptedM);

            encryptedMessage.append(C).append(" ");
            decryptedMessage.append((char) decryptedM.intValue()); // Convert back to char
        }

        System.out.println("\nEncrypted Message:        " + encryptedMessage.toString().trim());
        System.out.println("Decrypted Message:        " + decryptedMessage.toString());
        System.out.println();
    }
}