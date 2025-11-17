import java.util.*;

public class EuclideanAlgorithms {

    // Basic Euclidean Algorithm
    public static int basicEuclidean(int r1, int r2) {
        System.out.printf("%3s %5s %5s %5s%n", "q", "r1", "r2", "r");
        while (r2 != 0) {
            int q = r1 / r2;
            int r = r1 % r2;
            System.out.printf("%3d %5d %5d %5d%n", q, r1, r2, r);
            r1 = r2;
            r2 = r;
        }
        System.out.println("\nGCD is " + r1);
        return r1;
    }

    // Extended Euclidean Algorithm
    public static int[] extendedEuclidean(int a, int b) {
        int s1 = 1, s2 = 0;
        int t1 = 0, t2 = 1;

        System.out.printf("%3s %5s %5s %5s %5s %5s %5s %5s %5s %5s%n",
                "q", "a", "b", "r", "s1", "s2", "s", "t1", "t2", "t");

        while (b != 0) {
            int q = a / b;
            int r = a % b;
            int s = s1 - q * s2;
            int t = t1 - q * t2;

            System.out.printf("%3d %5d %5d %5d %5d %5d %5d %5d %5d %5d%n",
                    q, a, b, r, s1, s2, s, t1, t2, t);

            a = b;
            b = r;
            s1 = s2;
            s2 = s;
            t1 = t2;
            t2 = t;
        }

        System.out.println("\nGCD is " + a + ", s = " + s1 + ", t = " + t1);
        return new int[] { a, s1, t1 };
    }

    // Tabular Euclidean Algorithm for Modular Inverse
    public static int[] tabularEuclidean(int r1, int r2) {
        int t1 = 0, t2 = 1;
        int originalModulus = r1;

        System.out.printf("%3s %5s %5s %5s %5s %5s %5s%n", "q", "r1", "r2", "r", "t1", "t2", "t");

        while (r2 != 0) {
            int q = r1 / r2;
            int r = r1 % r2;
            int t = t1 - q * t2;

            System.out.printf("%3d %5d %5d %5d %5d %5d %5d%n", q, r1, r2, r, t1, t2, t);

            r1 = r2;
            r2 = r;
            t1 = t2;
            t2 = t;
        }

        int gcd = r1;
        if (gcd == 1) {
            int modularInverse = ((t1 % originalModulus) + originalModulus) % originalModulus;
            System.out.println("\nGCD is " + gcd + ", Modular Inverse = " + modularInverse);
            return new int[] { gcd, modularInverse };
        } else {
            System.out.println("\nGCD is " + gcd + ", Modular Inverse does not exist.");
            return new int[] { gcd, -1 };
        }
    }

    public static void main(String[] args) {
        // Example inputs
        int[][] inputs = { { 30, 20 }, { 35, 15 }, { 17, 31 } };

        for (int[] pair : inputs) {
            int a = pair[0], b = pair[1];
            System.out.println("Input: " + a + " " + b);
            basicEuclidean(a, b);
            System.out.println();

            System.out.println("Input: " + a + " " + b);
            extendedEuclidean(a, b);
            System.out.println();

            System.out.println("Input: " + a + " " + b);
            tabularEuclidean(a, b);
            System.out.println("\n-----------------------\n");
        }
    }
}
