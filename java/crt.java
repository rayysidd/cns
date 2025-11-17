import java.util.*;

public class crt {

    // Compute modular inverse using Extended Euclidean Algorithm
    public static Integer modInverse(int a, int m) {
        int t1 = 0, t2 = 1;
        int r1 = m, r2 = a;

        while (r2 != 0) {
            int q = r1 / r2;
            int r = r1 % r2;
            int t = t1 - q * t2;
            r1 = r2;
            r2 = r;
            t1 = t2;
            t2 = t;
        }
        if (r1 == 1) {
            return ((t1 % m) + m) % m; // Ensure positive
        } else {
            return null; // Inverse does not exist
        }
    }

    // Reconstruct number using Chinese Remainder Theorem
    public static int crtReconstruct(int[] residues, int[] moduli) throws Exception {
        long M = 1;
        for (int m : moduli)
            M *= m;

        long result = 0;
        for (int i = 0; i < moduli.length; i++) {
            long mi = moduli[i];
            long Mi = M / mi;
            Integer MiInv = modInverse((int) Mi, (int) mi);
            if (MiInv == null) {
                throw new Exception("Modular inverse for Mi=" + Mi + " mod " + mi + " doesn't exist.");
            }
            result += residues[i] * Mi * MiInv;
        }

        return (int) (result % M);
    }

    // Convert number to residue representation
    public static int[] toResidueRepresentation(int number, int[] moduli) {
        int[] residues = new int[moduli.length];
        for (int i = 0; i < moduli.length; i++) {
            residues[i] = number % moduli[i];
        }
        return residues;
    }

    // Perform arithmetic operation on residues
    public static int[] performOperation(int[] aRes, int[] bRes, int[] moduli, char op) throws Exception {
        int[] cRes = new int[moduli.length];
        for (int i = 0; i < moduli.length; i++) {
            int a = aRes[i], b = bRes[i], m = moduli[i];
            switch (op) {
                case '+':
                    cRes[i] = (a + b) % m;
                    break;
                case '-':
                    cRes[i] = (a - b + m) % m; // Ensure positive
                    break;
                case '*':
                    cRes[i] = (a * b) % m;
                    break;
                case '/':
                    Integer bInv = modInverse(b, m);
                    if (bInv == null) {
                        throw new Exception("Modular inverse of " + b + " mod " + m + " does not exist.");
                    }
                    cRes[i] = (a * bInv) % m;
                    break;
                default:
                    throw new Exception("Unsupported operation");
            }
        }
        return cRes;
    }

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        System.out.println("Initialize the system:");
        System.out.print("Enter number of moduli (k): ");
        int k = sc.nextInt();
        int[] moduli = new int[k];
        for (int i = 0; i < k; i++) {
            System.out.print("Enter modulus m" + (i + 1) + " (should be coprime): ");
            moduli[i] = sc.nextInt();
        }

        long M = 1;
        for (int m : moduli)
            M *= m;
        System.out.println("\nModuli: " + Arrays.toString(moduli));
        System.out.println("Product of moduli M = " + M + "\n");

        while (true) {
            System.out.println("\nMenu:");
            System.out.println("1. Add A + B");
            System.out.println("2. Subtract A - B");
            System.out.println("3. Multiply A * B");
            System.out.println("4. Divide A / B (modular division)");
            System.out.println("5. Exit");
            System.out.print("Enter your choice (1-5): ");
            int choice = sc.nextInt();

            if (choice == 5) {
                System.out.println("Exiting program.");
                break;
            }

            System.out.print("Enter first large number A: ");
            int A = sc.nextInt();
            System.out.print("Enter second large number B: ");
            int B = sc.nextInt();

            int[] aRes = toResidueRepresentation(A, moduli);
            int[] bRes = toResidueRepresentation(B, moduli);

            System.out.println("A in residues: " + Arrays.toString(aRes));
            System.out.println("B in residues: " + Arrays.toString(bRes));

            try {
                char op = ' ';
                switch (choice) {
                    case 1 -> op = '+';
                    case 2 -> op = '-';
                    case 3 -> op = '*';
                    case 4 -> op = '/';
                    default -> {
                        System.out.println("Invalid choice.");
                        continue;
                    }
                }

                int[] cRes = performOperation(aRes, bRes, moduli, op);
                System.out.println("Result residues: " + Arrays.toString(cRes));

                int C = crtReconstruct(cRes, moduli);
                System.out.println("Final Result C = A " + op + " B mod M = " + C);

            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        }
        sc.close();
    }
}
