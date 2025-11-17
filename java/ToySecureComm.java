import java.util.*;
import java.math.BigInteger;

// ----------------------- TPE -----------------------
class TPE {
    private Map<String, BigInteger> publicKeys = new HashMap<>();

    public void register(String id, BigInteger pubKey) {
        publicKeys.put(id, pubKey);
        System.out.println(id + " registered with TPE");
    }

    public BigInteger requestKey(String id) {
        return publicKeys.get(id);
    }
}

// ----------------------- Toy RSA -----------------------
class ToyRSA {
    public BigInteger n, e, d;

    public ToyRSA(int p, int q, int eVal) {
        n = BigInteger.valueOf(p).multiply(BigInteger.valueOf(q));
        BigInteger phi = BigInteger.valueOf(p - 1).multiply(BigInteger.valueOf(q - 1));
        e = BigInteger.valueOf(eVal);
        d = e.modInverse(phi);
    }

    public BigInteger encrypt(BigInteger msg, BigInteger pubKey) {
        return msg.modPow(pubKey, n);
    }

    public BigInteger decrypt(BigInteger cipher) {
        return cipher.modPow(d, n);
    }

    public BigInteger sign(BigInteger msg) {
        return msg.modPow(d, n);
    }

    public boolean verify(BigInteger msg, BigInteger signature, BigInteger pubKey) {
        return msg.equals(signature.modPow(pubKey, n));
    }
}

// ----------------------- Toy Symmetric XOR -----------------------
class ToySymmetric {
    public static String encrypt(String msg, int key) {
        char[] chars = msg.toCharArray();
        for (int i = 0; i < chars.length; i++)
            chars[i] ^= key;
        return new String(chars);
    }

    public static String decrypt(String cipher, int key) {
        return encrypt(cipher, key); // XOR is symmetric
    }
}

// ----------------------- Peer -----------------------
class Peer {
    String id;
    ToyRSA rsa;
    TPE tpe;
    Map<String, BigInteger> keyring = new HashMap<>();

    public Peer(String id, int p, int q, int eVal, TPE tpe) {
        this.id = id;
        this.rsa = new ToyRSA(p, q, eVal);
        this.tpe = tpe;
    }

    public void register() {
        tpe.register(id, rsa.e); // register public key
    }

    public void requestKey(String peerId) {
        if (!keyring.containsKey(peerId)) {
            BigInteger k = tpe.requestKey(peerId);
            keyring.put(peerId, k);
            System.out.println(id + " retrieved " + peerId + "'s public key");
        }
    }

    public int ssl1Handshake(Peer receiver) {
        // Generate toy random "shared secret"
        int secret = new Random().nextInt(256);

        // Sign secret
        BigInteger signed = rsa.sign(BigInteger.valueOf(secret));

        // Encrypt with receiver's public key
        BigInteger encrypted = signed.modPow(keyring.get(receiver.id), receiver.rsa.n);

        // Receiver decrypts with private key
        BigInteger decrypted = receiver.rsa.decrypt(encrypted);

        // Verify signature
        boolean valid = receiver.rsa.verify(BigInteger.valueOf(secret), decrypted, rsa.e);
        if (valid) {
            System.out.println("Handshake success: Shared secret=" + secret);
            return secret;
        } else {
            System.out.println("Handshake failed");
            return -1;
        }
    }

    public void sendMessage(Peer receiver, String msg, int secret) {
        // Encrypt with shared secret
        String cipher = ToySymmetric.encrypt(msg, secret);

        // Sign message
        BigInteger signature = rsa.sign(BigInteger.valueOf(msg.hashCode()));

        // Receiver decrypts
        String plain = ToySymmetric.decrypt(cipher, secret);

        // Verify signature
        boolean valid = receiver.rsa.verify(BigInteger.valueOf(plain.hashCode()), signature, rsa.e);

        System.out.println(id + " -> " + receiver.id + " : " + plain + " | Signature valid? " + valid);
    }
}

// ----------------------- Main -----------------------
public class ToySecureComm {
    public static void main(String[] args) {
        TPE tpe = new TPE();

        // Create peers
        Peer Alice = new Peer("Alice", 17, 23, 3, tpe);
        Peer Bob = new Peer("Bob", 19, 29, 3, tpe);
        Peer Charlie = new Peer("Charlie", 13, 31, 3, tpe);
        Peer David = new Peer("David", 11, 37, 3, tpe);

        // Registration
        Alice.register();
        Bob.register();
        Charlie.register();
        David.register();

        // Keyring maintenance
        Alice.requestKey("Bob");
        Bob.requestKey("Alice");

        // SSL-1 handshake
        int secret = Alice.ssl1Handshake(Bob);

        // Secure message exchange
        if (secret != -1) {
            Alice.sendMessage(Bob, "Hello Bob!", secret);
            Bob.sendMessage(Alice, "Hi Alice!", secret);
        }
    }
}
