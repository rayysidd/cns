public class rsa {

    // -----------------------------
    // Step 1: RSA encryption/decryption functions
    // -----------------------------
    public static int encryptRSA(int m, int e, int n) {
        return (int) (Math.pow(m, e) % n);
    }

    public static int decryptRSA(int c, int d, int n) {
        return (int) (Math.pow(c, d) % n);
    }

    // -----------------------------
    // Step 2: Simple XOR for symmetric encryption
    // -----------------------------
    public static int[] xorEncrypt(String message, int key) {
        int[] encrypted = new int[message.length()];
        for (int i = 0; i < message.length(); i++) {
            encrypted[i] = message.charAt(i) ^ key;
        }
        return encrypted;
    }

    public static String xorDecrypt(int[] encrypted, int key) {
        char[] decrypted = new char[encrypted.length];
        for (int i = 0; i < encrypted.length; i++) {
            decrypted[i] = (char) (encrypted[i] ^ key);
        }
        return new String(decrypted);
    }

    public static void main(String[] args) {
        // -----------------------------
        // Step 3: Define keys and message
        // -----------------------------
        int receiverPublicE = 7;
        int receiverPrivateD = 3;
        int receiverN = 33;

        int symmetricKey = 4; // simple number as symmetric key
        String message = "HELLO";

        System.out.println("Original message: " + message);

        // -----------------------------
        // Step 4: Encrypt message with symmetric key
        // -----------------------------
        int[] encryptedMessage = xorEncrypt(message, symmetricKey);
        System.out.print("Encrypted message (XOR): ");
        for (int c : encryptedMessage)
            System.out.print(c + " ");
        System.out.println();

        // -----------------------------
        // Step 5: Encrypt symmetric key with receiver's public key (RSA)
        // -----------------------------
        int encryptedSymKey = encryptRSA(symmetricKey, receiverPublicE, receiverN);
        System.out.println("Encrypted symmetric key (RSA): " + encryptedSymKey);

        // -----------------------------
        // Step 6: Receiver decrypts symmetric key
        // -----------------------------
        int decryptedSymKey = decryptRSA(encryptedSymKey, receiverPrivateD, receiverN);
        System.out.println("Decrypted symmetric key: " + decryptedSymKey);

        // -----------------------------
        // Step 7: Receiver decrypts message
        // -----------------------------
        String decryptedMessage = xorDecrypt(encryptedMessage, decryptedSymKey);
        System.out.println("Decrypted message: " + decryptedMessage);
    }
}
