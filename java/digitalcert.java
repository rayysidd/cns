import java.util.*;

/**
 * SimpleSSL1Demo.java
 *
 * Educational demo (concept-only) of:
 * - Third-Party Entity (TPE) for public key registration & lookup
 * - Peers (Alice, Bob, Charlie, David) with local keyrings (HashMap)
 * - Simplified Diffie-Hellman handshake with signed DH values
 * - "Envelope" of signature using receiver's public key (XOR-based for demo)
 * - Shared symmetric key derivation from DH secret
 * - Symmetric encryption using XOR with derived key
 * - Message signing/verifying using toy integer-signature
 *
 * This is NOT secure; it is purely a classroom demonstration with small ints.
 */
public class digitalcert {

    // ------------------- Third Party Entity -------------------
    static class TPE {
        // map identity -> publicKey (int)
        private final Map<String, Integer> registry = new HashMap<>();

        void register(String id, int publicKey) {
            registry.put(id, publicKey);
            System.out.println("[TPE] Registered: " + id + " -> pub=" + publicKey);
        }

        Integer getPublicKey(String id) {
            return registry.get(id);
        }
    }

    // ------------------- Peer -------------------
    static class Peer {
        final String name;
        final TPE tpe;
        final Map<String, Integer> keyring = new HashMap<>(); // local cache of other peers' public keys
        final int privKey; // toy private key (small int)
        final int pubKey; // toy public key derived from private key

        // DH domain params (very small for demo)
        static final int DH_P = 23;
        static final int DH_G = 5;
        static final Random RNG = new Random(12345);

        Peer(String name, TPE tpe, int privKey) {
            this.name = name;
            this.tpe = tpe;
            this.privKey = privKey;
            this.pubKey = privKey * 2 + 1; // simple derivation so pub != priv (toy)
            System.out.println("[" + name + "] created: priv=" + this.privKey + " pub=" + this.pubKey);
        }

        void registerWithTPE() {
            tpe.register(name, pubKey);
        }

        // request other peer's public key once and store in keyring
        void ensureKeyInKeyring(String other) {
            if (keyring.containsKey(other)) {
                System.out.println("[" + name + "] Key for " + other + " already in keyring.");
                return;
            }
            Integer pk = tpe.getPublicKey(other);
            if (pk == null) {
                System.out.println("[" + name + "] TPE does not have public key for " + other);
                return;
            }
            keyring.put(other, pk);
            System.out.println("[" + name + "] Retrieved and stored public key for " + other + " -> " + pk);
        }

        Integer getKeyFromKeyring(String other) {
            return keyring.get(other);
        }

        // modular exponentiation (int version) base^exp mod mod
        static int modPow(int base, int exp, int mod) {
            int result = 1 % mod;
            int b = base % mod;
            for (int i = 0; i < exp; i++) {
                result = (result * b) % mod;
            }
            return result;
        }

        // ---------------- Handshake (SSL-1 simplified) ----------------
        // Initiator creates DH public A, signs it, envelopes signature with receiver's
        // pub, sends (A, encSig)
        static class InitiatorPayload {
            final int A;
            final int encSigA;
            final int aSecret;

            InitiatorPayload(int A, int encSigA, int aSecret) {
                this.A = A;
                this.encSigA = encSigA;
                this.aSecret = aSecret;
            }
        }

        InitiatorPayload initiateHandshake(String receiverName) {
            ensureKeyInKeyring(receiverName);
            Integer recvPub = getKeyFromKeyring(receiverName);
            if (recvPub == null)
                throw new RuntimeException("No receiver public key in keyring");

            // generate small DH secret
            int a = 2 + RNG.nextInt(6); // small value 2..7
            int A = modPow(DH_G, a, DH_P);

            // sign A using toy signature: sig = A * privKey
            int sigA = A * this.privKey;

            // envelope: XOR signature with receiver's public key (toy)
            int encSigA = sigA ^ recvPub;

            System.out.println("[" + name + "] -> initiate: A=" + A + " encSigA=" + encSigA + " (a=" + a + ")");
            return new InitiatorPayload(A, encSigA, a);
        }

        // Responder: decrypt encSigA, verify signature using initiator's pub; create B,
        // sign B, envelope with initiator pub; compute shared
        static class ResponderReply {
            final int B;
            final int encSigB;
            final int bSecret;
            final int sharedAtResponder;

            ResponderReply(int B, int encSigB, int bSecret, int sharedAtResponder) {
                this.B = B;
                this.encSigB = encSigB;
                this.bSecret = bSecret;
                this.sharedAtResponder = sharedAtResponder;
            }
        }

        ResponderReply respondHandshake(String initiatorName, InitiatorPayload payload) {
            ensureKeyInKeyring(initiatorName);
            Integer initiatorPub = getKeyFromKeyring(initiatorName);
            if (initiatorPub == null)
                throw new RuntimeException("No initiator pub key");

            // decrypt signature: XOR with initiator's pub (same op)
            int sigA = payload.encSigA ^ initiatorPub;

            // verify signature: sigA % initiatorPub == A (toy verify)
            boolean ok = (sigA % initiatorPub) == payload.A;
            if (!ok) {
                System.out.println("[" + name + "] FAILED to verify signature on A from " + initiatorName);
                throw new RuntimeException("Signature verification failed");
            }
            System.out.println("[" + name + "] Verified signature on A from " + initiatorName);

            // generate DH secret and public
            int b = 2 + RNG.nextInt(6);
            int B = modPow(DH_G, b, DH_P);

            // sign B
            int sigB = B * this.privKey;

            // envelope with initiator's public key
            int encSigB = sigB ^ initiatorPub;

            // compute shared secret at responder: shared = A^b mod p
            int shared = modPow(payload.A, b, DH_P);

            System.out.println(
                    "[" + name + "] -> respond: B=" + B + " encSigB=" + encSigB + " (b=" + b + ") shared=" + shared);
            return new ResponderReply(B, encSigB, b, shared);
        }

        // Initiator finishes: decrypt encSigB, verify, compute shared
        int finishHandshake(String responderName, InitiatorPayload init, ResponderReply reply) {
            ensureKeyInKeyring(responderName);
            Integer respPub = getKeyFromKeyring(responderName);
            if (respPub == null)
                throw new RuntimeException("No responder pub key");

            // decrypt sigB
            int sigB = reply.encSigB ^ respPub;

            // verify sigB % respPub == B
            boolean ok = (sigB % respPub) == reply.B;
            if (!ok) {
                System.out.println("[" + name + "] FAILED to verify signature on B from " + responderName);
                throw new RuntimeException("Responder signature verification failed");
            }
            System.out.println("[" + name + "] Verified signature on B from " + responderName);

            // compute shared secret as B^a mod p
            int shared = modPow(reply.B, init.aSecret, DH_P);
            System.out.println("[" + name + "] Computed shared=" + shared);
            return shared;
        }

        // derive symmetric key integer (0..255) from shared secret (toy)
        static int deriveSymKey(int shared) {
            return (shared * 7) % 256; // toy derivation
        }

        // symmetric XOR encrypt/decrypt
        static String xorEncryptString(String plaintext, int key) {
            char[] arr = plaintext.toCharArray();
            char[] out = new char[arr.length];
            for (int i = 0; i < arr.length; i++) {
                out[i] = (char) (arr[i] ^ key);
            }
            return new String(out);
        }

        // toy message signature: sig = message length * privKey
        int signMessage(String plaintext) {
            return plaintext.length() * this.privKey;
        }

        // verify message signature: sig % pubKey == length
        boolean verifyMessage(String plaintext, int signature, int senderPub) {
            return (signature % senderPub) == plaintext.length();
        }

        // perform full handshake with another Peer (direct call)
        int performHandshakeWith(Peer other) {
            InitiatorPayload init = initiateHandshake(other.name);
            ResponderReply resp = other.respondHandshake(this.name, init);
            int sharedInitiator = finishHandshake(other.name, init, resp);
            int sharedResponder = resp.sharedAtResponder;
            if (sharedInitiator != sharedResponder) {
                throw new RuntimeException("DH mismatch: " + sharedInitiator + " vs " + sharedResponder);
            }
            System.out
                    .println("[" + this.name + "] and [" + other.name + "] derived shared secret: " + sharedInitiator);
            int sym = deriveSymKey(sharedInitiator);
            System.out.println("[" + this.name + "] Symmetric key (int): " + sym);
            return sym;
        }

        // send a secure encrypted and signed message (returns package)
        static class SecurePackage {
            final String ciphertext;
            final int signature;
            final String sender;

            SecurePackage(String ciphertext, int signature, String sender) {
                this.ciphertext = ciphertext;
                this.signature = signature;
                this.sender = sender;
            }
        }

        SecurePackage sendSecureMessage(Peer receiver, int symKey, String plaintext) {
            // ensure receiver key in keyring for future verification
            ensureKeyInKeyring(receiver.name);
            String ct = xorEncryptString(plaintext, symKey);
            int sig = signMessage(plaintext);
            System.out.println("[" + name + "] -> send secure to " + receiver.name + ": ciphertext(prefix)='"
                    + (ct.length() > 20 ? ct.substring(0, 20) + "..." : ct) + "' signature=" + sig);
            return new SecurePackage(ct, sig, this.name);
        }

        void receiveSecureMessage(SecurePackage pkg, int symKey) {
            // ensure we have sender's public key
            ensureKeyInKeyring(pkg.sender);
            Integer senderPub = getKeyFromKeyring(pkg.sender);
            if (senderPub == null) {
                System.out.println("[" + name + "] Missing sender public key for " + pkg.sender);
                return;
            }
            String pt = xorEncryptString(pkg.ciphertext, symKey);
            boolean verified = verifyMessage(pt, pkg.signature, senderPub);
            System.out.println("[" + name + "] Received secure from " + pkg.sender + ". Signature valid? " + verified);
            if (verified) {
                System.out.println("[" + name + "] Plaintext: " + pt);
            } else {
                System.out.println("[" + name + "] Signature invalid — message rejected.");
            }
        }
    }

    // ------------------- Demo orchestration -------------------
    public static void main(String[] args) {
        System.out.println("=== SimpleSSL1 Demo (toy, educational) ===\n");

        TPE tpe = new TPE();

        // create peers with tiny private keys
        Peer alice = new Peer("alice", tpe, 5);
        Peer bob = new Peer("bob", tpe, 7);
        Peer charlie = new Peer("charlie", tpe, 11);
        Peer david = new Peer("david", tpe, 13);

        System.out.println("\n-- Registration Phase --");
        alice.registerWithTPE();
        bob.registerWithTPE();
        charlie.registerWithTPE();
        david.registerWithTPE();

        System.out.println("\n-- Keyring maintenance: alice requests bob's key (once) --");
        alice.ensureKeyInKeyring("bob");
        System.out.println("Second request should use keyring (no TPE call):");
        alice.ensureKeyInKeyring("bob");

        System.out.println("\n-- SSL-1 Handshake & Symmetric Key Derivation (Alice -> Bob) --");
        int symKey = alice.performHandshakeWith(bob);

        System.out.println("\n-- Secure Message Exchange (Alice -> Bob) --");
        Peer.SecurePackage pkg = alice.sendSecureMessage(bob, symKey, "HELLO BOB");
        bob.receiveSecureMessage(pkg, symKey);

        System.out.println("\n-- Done --");
    }
}
