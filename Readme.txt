# -------------------------
# Caesar Cipher
# -------------------------

# Encrypt
def caesar_encrypt(text, shift):
    result = ""
    for char in text.upper():
        if char.isalpha():
            result += chr((ord(char) - 65 + shift) % 26 + 65)
        else:
            result += char
    return result

# Decrypt
def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


# Example
pt = "HELLO WORLD"
ct = caesar_encrypt(pt, 3)
print("Encrypted:", ct)
print("Decrypted:", caesar_decrypt(ct, 3))


# -------------------------
# Monoalphabetic Cipher
# -------------------------

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Encrypt
def mono_encrypt(text, key):
    text = text.upper()
    mapping = {ALPHABET[i]: key[i] for i in range(26)}
    result = ""
    for char in text:
        if char.isalpha():
            result += mapping[char]
        else:
            result += char
    return result

# Decrypt
def mono_decrypt(ciphertext, key):
    inverse = {key[i]: ALPHABET[i] for i in range(26)}
    result = ""
    for char in ciphertext:
        if char.isalpha():
            result += inverse[char]
        else:
            result += char
    return result


# Example
key = "QWERTYUIOPASDFGHJKLZXCVBNM"
pt = "HELLO WORLD"
ct = mono_encrypt(pt, key)
print("Encrypted:", ct)
print("Decrypted:", mono_decrypt(ct, key))


# -------------------------
# Playfair Cipher
# -------------------------

def playfair_generate_key(key):
    key = key.upper().replace("J", "I")
    matrix = []
    used = set()

    for c in key:
        if c not in used and c.isalpha():
            matrix.append(c)
            used.add(c)

    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if c not in used and c != "J":
            matrix.append(c)

    return [matrix[i:i+5] for i in range(0, 25, 5)]

def playfair_loc(matrix, letter):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == letter:
                return r, c

def playfair_prepare(text):
    text = text.upper().replace("J", "I")
    text = "".join(c for c in text if c.isalpha())

    i = 0
    pairs = []
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) else "X"

        if a == b:
            pairs.append(a + "X")
            i += 1
        else:
            pairs.append(a + b)
            i += 2

    if len(pairs[-1]) == 1:
        pairs[-1] += "X"

    return pairs

def playfair_encrypt(text, key):
    matrix = playfair_generate_key(key)
    pairs = playfair_prepare(text)
    cipher = ""

    for a, b in pairs:
        r1, c1 = playfair_loc(matrix, a)
        r2, c2 = playfair_loc(matrix, b)

        if r1 == r2:
            cipher += matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5]
        elif c1 == c2:
            cipher += matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2]
        else:
            cipher += matrix[r1][c2] + matrix[r2][c1]

    return cipher

def playfair_decrypt(cipher, key):
    matrix = playfair_generate_key(key)
    pairs = [cipher[i:i+2] for i in range(0, len(cipher), 2)]
    plain = ""

    for a, b in pairs:
        r1, c1 = playfair_loc(matrix, a)
        r2, c2 = playfair_loc(matrix, b)

        if r1 == r2:
            plain += matrix[r1][(c1 - 1) % 5] + matrix[r2][(c2 - 1) % 5]
        elif c1 == c2:
            plain += matrix[(r1 - 1) % 5][c1] + matrix[(r2 - 1) % 5][c2]
        else:
            plain += matrix[r1][c2] + matrix[r2][c1]

    return plain


# Example
pt = "HELLO"
ct = playfair_encrypt(pt, "MONARCHY")
print("Encrypted:", ct)
print("Decrypted:", playfair_decrypt(ct, "MONARCHY"))


# -------------------------
# Hill Cipher (2x2)
# -------------------------

import numpy as np

def hill_encrypt(text, key):
    text = text.upper().replace(" ", "")
    if len(text) % 2 != 0:
        text += "X"

    result = ""
    for i in range(0, len(text), 2):
        block = np.array([[ord(text[i]) - 65],
                          [ord(text[i+1]) - 65]])
        enc = key.dot(block) % 26
        result += chr(enc[0][0] + 65) + chr(enc[1][0] + 65)

    return result

def hill_decrypt(cipher, key):
    det = int(np.round(np.linalg.det(key))) % 26
    det_inv = pow(det, -1, 26)  # modular inverse

    adj = np.array([[key[1][1], -key[0][1]],
                    [-key[1][0], key[0][0]]])
    inv_key = (det_inv * adj) % 26

    result = ""
    for i in range(0, len(cipher), 2):
        block = np.array([[ord(cipher[i]) - 65],
                          [ord(cipher[i+1]) - 65]])
        dec = inv_key.dot(block) % 26
        result += chr(int(dec[0][0]) + 65) + chr(int(dec[1][0]) + 65)

    return result


# Example
key = np.array([[3, 3],
                [2, 5]])

pt = "HELP"
ct = hill_encrypt(pt, key)
print("Encrypted:", ct)
print("Decrypted:", hill_decrypt(ct, key))


# -------------------------
# Vigenere Cipher
# -------------------------

def vigenere_encrypt(text, key):
    text = text.upper()
    key = key.upper()
    result = ""
    j = 0

    for c in text:
        if c.isalpha():
            shift = ord(key[j % len(key)]) - 65
            result += chr((ord(c) - 65 + shift) % 26 + 65)
            j += 1
        else:
            result += c
    return result

def vigenere_decrypt(text, key):
    text = text.upper()
    key = key.upper()
    result = ""
    j = 0

    for c in text:
        if c.isalpha():
            shift = ord(key[j % len(key)]) - 65
            result += chr((ord(c) - 65 - shift) % 26 + 65)
            j += 1
        else:
            result += c
    return result


# Example
pt = "ATTACKATDAWN"
ct = vigenere_encrypt(pt, "LEMON")
print("Encrypted:", ct)
print("Decrypted:", vigenere_decrypt(ct, "LEMON"))
































# Basic Euclidean Algorithm (Tabular Method)

a = int(input("Enter first number: "))
b = int(input("Enter second number: "))

# r1 must be larger
r1 = max(a, b)
r2 = min(a, b)

print("\nq\t r1\t r2\t r")
print("-"*30)

while r2 != 0:
    q = r1 // r2
    r = r1 % r2
    print(q, "\t", r1, "\t", r2, "\t", r)

    # shift values
    r1 = r2
    r2 = r

print("\nGCD =", r1)



# Extended Euclidean Algorithm (Tabular Method)

a = int(input("Enter first number: "))
b = int(input("Enter second number: "))

r1 = a
r2 = b
s1, s2 = 1, 0
t1, t2 = 0, 1

print("\nq\t r1\t r2\t r\t s1\t s2\t s\t t1\t t2\t t")
print("-"*70)

while r2 != 0:
    q = r1 // r2
    r = r1 % r2
    s = s1 - q * s2
    t = t1 - q * t2

    print(q, "\t", r1, "\t", r2, "\t", r, "\t", s1, "\t", s2, "\t", s, "\t", t1, "\t", t2, "\t", t)

    r1, r2 = r2, r
    s1, s2 = s2, s
    t1, t2 = t2, t

print("\nGCD =", r1)
print("s =", s1)
print("t =", t1)


# Euclidean Algorithm for GCD and MI (Modular Inverse)

a = int(input("Enter first number (a): "))
b = int(input("Enter modulus (b): "))

r1 = a
r2 = b
t1, t2 = 0, 1

print("\nq\t r1\t r2\t r\t t1\t t2\t t")
print("-"*50)

while r2 != 0:
    q = r1 // r2
    r = r1 % r2
    t = t1 - q * t2

    print(q, "\t", r1, "\t", r2, "\t", r, "\t", t1, "\t", t2, "\t", t)

    r1, r2 = r2, r
    t1, t2 = t2, t

print("\nGCD =", r1)

if r1 == 1:
    print("Modular Inverse =", t1 % b)
else:
    print("Modular Inverse does NOT exist (numbers not co-prime)")



































# Simple CRT Calculator (Addition, Subtraction, Multiplication, Division)

# --- Step 1: Take moduli ---
k = int(input("Enter number of moduli (k): "))
mods = []

for i in range(k):
    mods.append(int(input("Enter m" + str(i+1) + ": ")))

# Product M
M = 1
for m in mods:
    M *= m

# --- Helper: GCD and inverse (very simple version) ---
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    for x in range(m):
        if (a * x) % m == 1:
            return x
    return None


# --- Menu loop ---
while True:
    print("\n1. Addition")
    print("2. Subtraction")
    print("3. Multiplication")
    print("4. Division")
    print("5. Quit")

    ch = input("Enter choice: ")

    if ch == "5":
        break

    # Step 2: Take numbers
    A = int(input("Enter A: "))
    B = int(input("Enter B: "))

    # Step 3: Convert to residues
    a = []
    b = []
    for m in mods:
        a.append(A % m)
        b.append(B % m)

    # Step 4: Perform operation
    c = []

    if ch == "1":          # ADD
        for i in range(k):
            c.append((a[i] + b[i]) % mods[i])

    elif ch == "2":        # SUBTRACT
        for i in range(k):
            c.append((a[i] - b[i]) % mods[i])

    elif ch == "3":        # MULTIPLY
        for i in range(k):
            c.append((a[i] * b[i]) % mods[i])

    elif ch == "4":        # DIVIDE
        for i in range(k):
            inv = mod_inverse(b[i], mods[i])
            if inv is None:
                print("Division not possible for modulus", mods[i])
                c = []
                break
            c.append((a[i] * inv) % mods[i])

    # Step 5: Print residues
    if c:
        print("Residues (c1, c2, ... ck):", c)

        # Reconstruct final C using simplest CRT formula
        C = 0
        for i in range(k):
            Mi = M // mods[i]
            inv = mod_inverse(Mi % mods[i], mods[i])
            C += c[i] * Mi * inv

        C = C % M
        print("Final answer C =", C)
        print("Modulus M =", M)

































# simple_rsa_key_distribution_xor.py
# Very simple educational demo: RSA key distribution + XOR symmetric encryption

import random

# ---------- tiny helpers ----------
def egcd(a,b):
    if b==0:
        return (a,1,0)
    g,x1,y1 = egcd(b, a % b)
    return (g, y1, x1 - (a//b)*y1)

def modinv(a,m):
    g,x,y = egcd(a % m, m)
    if g != 1:
        return None
    return x % m

def str_to_int(b):
    return int.from_bytes(b, 'big')

def int_to_bytes(i, length):
    return i.to_bytes(length, 'big')

# ---------- RSA key setup (very simple) ----------
inp = input("Enter p (prime) or Enter to use default p=61: ").strip()
p = int(inp) if inp else 61
inp = input("Enter q (prime) or Enter to use default q=53: ").strip()
q = int(inp) if inp else 53

n = p * q
phi = (p-1)*(q-1)

e = 65537
if egcd(e, phi)[0] != 1:
    e = 3
    while egcd(e, phi)[0] != 1:
        e += 2

d = modinv(e, phi)

print("\nPublic key (n,e):", n, e)
print("Private exponent d is kept secret.")

# ---------- Sender: symmetric key + encrypt it with RSA ----------
# Simple: let user type a short symmetric key or auto-generate
k_in = input("\nEnter a short symmetric key (press Enter to auto-generate 8 random bytes): ").strip()
if k_in:
    sym_key = k_in.encode('utf-8')
else:
    sym_key = bytes([random.randrange(0,256) for _ in range(8)])
print("Symmetric key (bytes):", sym_key)

# convert sym key to integer, encrypt with RSA public key
k_int = str_to_int(sym_key)
c_key = pow(k_int, e, n)   # RSA encrypt symmetric key
print("Encrypted symmetric key (integer):", c_key)

# ---------- Sender: encrypt a large message using XOR with sym_key ----------
msg = input("\nEnter plaintext message to send: ")
plain_bytes = msg.encode('utf-8')

def xor_encrypt(data, key):
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b ^ key[i % len(key)])
    return bytes(out)

cipher_bytes = xor_encrypt(plain_bytes, sym_key)
print("Ciphertext (hex, first 100 chars):", cipher_bytes.hex()[:100])

# ---------- Transmission: c_key and cipher_bytes ----------

# ---------- Receiver: decrypt symmetric key with RSA private key ----------
k_int_recv = pow(c_key, d, n)
# reconstruct bytes: ensure same length as original symmetric key
key_len = len(sym_key)
sym_key_recv = int_to_bytes(k_int_recv, key_len)
print("\nReceiver recovered symmetric key (bytes):", sym_key_recv)

# ---------- Receiver: decrypt message using XOR ----------
recovered = xor_encrypt(cipher_bytes, sym_key_recv)
try:
    print("Recovered plaintext:", recovered.decode('utf-8'))
except:
    print("Recovered plaintext (raw):", recovered)

# ---------- Verify ----------
if recovered == plain_bytes:
    print("\nSuccess: Decrypted message matches original.")
else:
    print("\nError: Decrypted message does not match.")






























RSA AUTHENTICITY CONDIFENTIALITY




# demo_tpe_peers.py
# Simple simulation: TPE + 4 Peers + SSL-1-like handshake + secure messages
# Educational only.

import random

# ---------- tiny math helpers ----------
def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        return None
    return x % m

# ---------- very small RSA keygen (for clarity only) ----------
def small_rsa_keygen():
    # choose two small primes (educational)
    small_primes = [61, 53, 59, 67, 71, 73, 79, 83]
    p = random.choice(small_primes)
    q = random.choice([x for x in small_primes if x != p])
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if egcd(e, phi)[0] != 1:
        # fallback
        e = 3
        while egcd(e, phi)[0] != 1:
            e += 2
    d = modinv(e, phi)
    return (n, e, d)

# ---------- simple XOR symmetric cipher ----------
def xor_encrypt_bytes(data_bytes, key_bytes):
    out = bytearray()
    klen = len(key_bytes)
    for i, b in enumerate(data_bytes):
        out.append(b ^ key_bytes[i % klen])
    return bytes(out)

def int_to_bytes(x):
    return x.to_bytes((x.bit_length() + 7) // 8 or 1, 'big')

def bytes_to_int(b):
    return int.from_bytes(b, 'big')

# ---------- Third-Party Entity (TPE) ----------
class TPE:
    def __init__(self):
        # identity -> (n, e) public key
        self.store = {}

    def register(self, identity, public_key):
        # public_key is tuple (n, e)
        self.store[identity] = public_key
        print(f"TPE: Registered {identity}")

    def get_public_key(self, identity):
        return self.store.get(identity)

# ---------- Peer (Alice/Bob/Charlie/David) ----------
class Peer:
    def __init__(self, name, tpe):
        self.name = name
        self.tpe = tpe
        # generate keypair
        self.n, self.e, self.d = small_rsa_keygen()
        # local keyring: identity -> (n, e)
        self.keyring = {}
        # register with TPE
        self.tpe.register(self.name, (self.n, self.e))
        print(f"{self.name}: Generated RSA keys (n={self.n}, e={self.e})")

    def fetch_key_if_missing(self, identity):
        if identity == self.name:
            return (self.n, self.e)
        if identity in self.keyring:
            return self.keyring[identity]
        pk = self.tpe.get_public_key(identity)
        if pk is None:
            print(f"{self.name}: TPE has no key for {identity}")
            return None
        self.keyring[identity] = pk
        print(f"{self.name}: Fetched {identity}'s public key from TPE")
        return pk

    # RSA sign integer value (educational): signature = value^d mod n
    def rsa_sign_int(self, value_int):
        return pow(value_int, self.d, self.n)

    # RSA verify integer signature: recovers int = sig^e mod n
    def rsa_verify_int(self, sig_int, signer_pub):
        n_s, e_s = signer_pub
        return pow(sig_int, e_s, n_s)

    # RSA encrypt int with recipient pubkey
    def rsa_encrypt_int_for(self, value_int, recipient_pub):
        n_r, e_r = recipient_pub
        return pow(value_int, e_r, n_r)

    # RSA decrypt int with own private key
    def rsa_decrypt_int(self, cipher_int):
        return pow(cipher_int, self.d, self.n)

    # Perform SSL-1-like handshake as Sender to receiver_name
    def ssl1_handshake_as_sender(self, receiver_name, dh_params=(23, 5)):
        # dh_params: (p, g) small prime and base (educational)
        p, g = dh_params
        # ensure we have receiver's pubkey
        rec_pub = self.fetch_key_if_missing(receiver_name)
        if rec_pub is None:
            raise Exception("Receiver public key missing")

        # 1) Sender picks secret a, computes A = g^a mod p
        a = random.randrange(2, p-2)
        A = pow(g, a, p)           # integer
        # 2) Sender signs A (simple RSA integer signature)
        sigA = self.rsa_sign_int(A)    # sig = A^d_sender mod n_sender
        # 3) Sender encrypts the signature with receiver's public key
        enc_sigA = self.rsa_encrypt_int_for(sigA, rec_pub)
        # Sender sends enc_sigA to receiver (in real system: over network)
        # Store 'a' so sender can compute shared key later
        print(f"{self.name} -> {receiver_name}: Sent encrypted signed DH value")
        # Return values that would be transmitted
        return {
            'enc_sigA': enc_sigA,
            'dh_params': dh_params,
            'sender_identity': self.name,
            # for simulation only: sender keeps own 'a' to compute shared key
            'sender_private_a': a
        }

    # Receiver handles handshake message from sender and returns symmetric key bytes
    def ssl1_handshake_as_receiver(self, msg):
        enc_sigA = msg['enc_sigA']
        dh_params = msg['dh_params']
        sender_id = msg['sender_identity']
        p, g = dh_params

        # fetch sender pubkey if needed
        sender_pub = self.fetch_key_if_missing(sender_id)
        if sender_pub is None:
            raise Exception("Sender public key missing")

        # Receiver decrypts enc_sigA with own private key => gets signature integer (sigA)
        sigA = self.rsa_decrypt_int(enc_sigA)
        # Verify signature: compute recovered_A = sigA^e_sender mod n_sender
        recovered_A = self.rsa_verify_int(sigA, sender_pub)

        # If verification succeeded, recovered_A is A
        if recovered_A <= 0 or recovered_A >= p:
            print(f"{self.name}: Verification failed or A out of range")
            return None

        # Receiver picks own DH secret b and computes shared secret K = A^b mod p
        b = random.randrange(2, p-2)
        K = pow(recovered_A, b, p)
        # Convert K to bytes for symmetric key (simple)
        sym_key_bytes = int_to_bytes(K)
        # Receiver needs to respond to sender with a value so sender can compute same K.
        # In classic DH they'd exchange public A and B; here only sender sent A (hidden).
        # To help sender compute K, receiver sends B = g^b mod p, signed and encrypted similarly.
        B = pow(g, b, p)
        sigB = self.rsa_sign_int(B)
        # Encrypt signature of B with sender's public key
        enc_sigB = self.rsa_encrypt_int_for(sigB, sender_pub)
        # Return response containing enc_sigB and receiver identity and the K bytes derived
        print(f"{self.name} -> {sender_id}: Sent encrypted signed DH response")
        return {
            'enc_sigB': enc_sigB,
            'sym_key_bytes': sym_key_bytes,
            'receiver_private_b': b,
            'receiver_identity': self.name
        }

    # Sender finalizes handshake using receiver response and its private 'a', producing same sym key bytes
    def ssl1_finalize_sender(self, response, sender_private_a, receiver_identity):
        enc_sigB = response['enc_sigB']
        # decrypt enc_sigB with sender private key -> sigB
        sigB = self.rsa_decrypt_int(enc_sigB)
        # fetch receiver public key
        rec_pub = self.fetch_key_if_missing(receiver_identity)
        if rec_pub is None:
            raise Exception("Receiver pub missing")
        # recover B = sigB^e_receiver mod n_receiver
        B = pow(sigB, rec_pub[1], rec_pub[0])  # note: rec_pub = (n,e)
        # compute shared secret K = B^a mod p (we need p from DH params, but for simplicity use same small p)
        p = 23  # matches dh_params used earlier
        # In actual implementation we'd carry p; here we assume p=23 consistent
        K = pow(B, sender_private_a, p)
        sym_key_bytes = int_to_bytes(K)
        return sym_key_bytes

    # Send an encrypted and signed message using symmetric key bytes and receiver_identity
    def send_secure_message(self, plaintext, receiver_identity, sym_key_bytes):
        # ensure receiver pub is in keyring (needed for verification later)
        self.fetch_key_if_missing(receiver_identity)
        # 1) symmetric encryption (XOR)
        pt_bytes = plaintext.encode('utf-8')
        cipher_bytes = xor_encrypt_bytes(pt_bytes, sym_key_bytes)
        # 2) signature on plaintext (simple RSA integer signature on integer of plaintext bytes)
        m_int = bytes_to_int(pt_bytes)
        sig_m = self.rsa_sign_int(m_int)  # signature integer
        # For transmission, send cipher_bytes and sig_m and sender id
        return {
            'cipher_bytes': cipher_bytes,
            'sig_m': sig_m,
            'sender_identity': self.name
        }

    # Receive a secure message: decrypt using sym_key_bytes and verify signature using sender pubkey
    def receive_secure_message(self, msg, sym_key_bytes):
        cipher_bytes = msg['cipher_bytes']
        sig_m = msg['sig_m']
        sender_id = msg['sender_identity']
        # decrypt cipher
        pt_bytes = xor_encrypt_bytes(cipher_bytes, sym_key_bytes)
        # recover m_int from decrypted plaintext
        m_int = bytes_to_int(pt_bytes)
        # get sender public key
        sender_pub = self.fetch_key_if_missing(sender_id)
        if sender_pub is None:
            print(f"{self.name}: cannot verify signature, missing sender pubkey")
            return None
        # verify: pow(sig_m, e_sender, n_sender) should equal m_int
        recovered = pow(sig_m, sender_pub[1], sender_pub[0])
        if recovered == m_int:
            try:
                text = pt_bytes.decode('utf-8')
            except:
                text = "<binary>"
            print(f"{self.name}: Signature valid. Message: {text}")
            return text
        else:
            print(f"{self.name}: Signature INVALID.")
            return None

# ---------- Demo run ----------
def demo():
    # Create TPE
    tpe = TPE()

    # Create peers and register their public keys
    alice = Peer("Alice", tpe)
    bob = Peer("Bob", tpe)
    charlie = Peer("Charlie", tpe)
    david = Peer("David", tpe)

    # Example: Alice wants to talk to Bob
    print("\n=== Alice -> Bob: Key check and SSL-1 handshake ===")
    # Alice ensures Bob's public key in her keyring
    bob_pub = alice.fetch_key_if_missing("Bob")
    # Alice initiates handshake
    msg1 = alice.ssl1_handshake_as_sender("Bob", dh_params=(23,5))
    # Bob processes
    resp = bob.ssl1_handshake_as_receiver(msg1)
    if resp is None:
        print("Handshake failed at Bob")
        return
    # Alice finalizes and gets symmetric key bytes
    sym_alice = alice.ssl1_finalize_sender(resp, msg1['sender_private_a'], resp['receiver_identity'])
    sym_bob = resp['sym_key_bytes']
    print("Alice derived symmetric key bytes:", sym_alice)
    print("Bob derived symmetric key bytes:  ", sym_bob)
    # They should match
    if sym_alice == sym_bob:
        print("Handshake success: symmetric keys match")
    else:
        print("Handshake mismatch!")

    # Secure message exchange
    print("\n=== Secure message exchange ===")
    m = "Hello Bob, this is Alice."
    msg_sent = alice.send_secure_message(m, "Bob", sym_alice)
    bob.receive_secure_message(msg_sent, sym_bob)

    # Bob replies to Alice
    reply = "Hello Alice, Bob here."
    msg_sent2 = bob.send_secure_message(reply, "Alice", sym_bob)
    alice.receive_secure_message(msg_sent2, sym_alice)

if __name__ == "__main__":
    demo()



















To implement i) AES (Advanced Encryption Standard) algorithm, ii) RSA encryption/decryption algorithm, and iii) Hybrid cryptosystem combining both symmetric and asymmetric encryption


"""
crypto_lab.py
Single-file menu:
1) AES-128 Encrypt/Decrypt (ECB & CBC)
2) RSA Encrypt/Decrypt (PKCS#1 OAEP)
3) Hybrid: RSA to wrap AES session key + AES for message
4) Performance comparison (RSA-only vs Hybrid)
5) Quit

Dependency: PyCryptodome
If you don't have it, install:
    pip install pycryptodome
"""

from time import time
import os
import sys

# Try import PyCryptodome; if missing, tell user and exit
try:
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
except Exception as e:
    print("This script requires PyCryptodome. Install with: pip install pycryptodome")
    print("Import error:", e)
    sys.exit(1)


# -------------------------
# Helpers
# -------------------------
def input_bytes(prompt="Input text: "):
    s = input(prompt)
    return s.encode('utf-8')

def show_hex(b, label=""):
    print(label + b.hex())

# AES helper (128-bit key enforced)
def aes_encrypt(plaintext_bytes, key_bytes, mode='CBC', iv=None):
    key = key_bytes[:16]  # AES-128: first 16 bytes
    if mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        ct = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
        return ct, None
    else:  # CBC
        if iv is None:
            iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
        return ct, iv

def aes_decrypt(ciphertext_bytes, key_bytes, mode='CBC', iv=None):
    key = key_bytes[:16]
    if mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        pt = unpad(cipher.decrypt(ciphertext_bytes), AES.block_size)
        return pt
    else:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ciphertext_bytes), AES.block_size)
        return pt

# RSA helpers using OAEP
def rsa_generate(bits=2048):
    key = RSA.generate(bits)
    priv = key
    pub = key.publickey()
    return priv, pub

def rsa_encrypt_with_pub(pubkey, data_bytes):
    cipher = PKCS1_OAEP.new(pubkey)
    return cipher.encrypt(data_bytes)

def rsa_decrypt_with_priv(privkey, cipher_bytes):
    cipher = PKCS1_OAEP.new(privkey)
    return cipher.decrypt(cipher_bytes)


# -------------------------
# Menu actions
# -------------------------
def menu():
    print("\nMenu:")
    print("1) AES Encryption/Decryption")
    print("2) RSA Encryption/Decryption")
    print("3) Hybrid (RSA wrap AES key + AES encrypt message)")
    print("4) Performance Comparison (RSA-only vs Hybrid)")
    print("5) Quit")

# 1 AES
def action_aes():
    print("\nAES-128 (library) — choose mode")
    mode = input("Mode (ECB/CBC) [CBC]: ").strip().upper() or "CBC"
    if mode not in ('ECB','CBC'):
        print("Invalid mode, using CBC")
        mode = 'CBC'
    key_input = input("Enter key (text, will be hashed/truncated to 16 bytes) or press Enter to auto-generate: ").strip()
    if key_input:
        key_bytes = key_input.encode('utf-8').ljust(16, b'\0')[:16]
    else:
        key_bytes = get_random_bytes(16)
        print("Generated AES-128 key (hex):", key_bytes.hex())

    plaintext = input("Enter plaintext: ")
    ptb = plaintext.encode('utf-8')
    ct, iv = aes_encrypt(ptb, key_bytes, mode=mode)
    print("Ciphertext (hex):", ct.hex())
    if iv:
        print("IV (hex):", iv.hex())

    # Decrypt to show
    pt_recovered = aes_decrypt(ct, key_bytes, mode=mode, iv=iv)
    print("Recovered plaintext:", pt_recovered.decode('utf-8'))

# 2 RSA
def action_rsa():
    print("\nRSA: key generation and ENC/DEC with OAEP")
    bits = input("RSA key size in bits [2048]: ").strip()
    bits = int(bits) if bits else 2048
    print("Generating RSA keys...")
    priv, pub = rsa_generate(bits)
    print("Public modulus n (hex, first 200 chars):", format(pub.n, 'x')[:200])
    # Encryption
    message = input("Enter message to encrypt (short, < key size - padding): ")
    mbytes = message.encode('utf-8')
    try:
        c = rsa_encrypt_with_pub(pub, mbytes)
    except Exception as e:
        print("Encryption error (message too long?):", e)
        return
    print("Ciphertext (hex, prefix):", c.hex()[:200])
    # Decrypt
    recovered = rsa_decrypt_with_priv(priv, c)
    print("Decrypted plaintext:", recovered.decode('utf-8'))

# 3 Hybrid
def action_hybrid():
    print("\nHybrid system demo: RSA wraps AES-128 session key, AES encrypts large message.")
    # Generate RSA keys for receiver (simulate receiver)
    bits = input("Receiver RSA key size in bits [2048]: ").strip()
    bits = int(bits) if bits else 2048
    print("Generating receiver RSA keys...")
    recv_priv, recv_pub = rsa_generate(bits)
    # Sender prepares AES session key
    session_key = get_random_bytes(16)  # AES-128
    print("Generated AES session key (hex):", session_key.hex())
    # Sender wraps session key with RSA (receiver public key)
    wrapped_key = rsa_encrypt_with_pub(recv_pub, session_key)
    print("Wrapped AES key with RSA (hex prefix):", wrapped_key.hex()[:200])
    # Sender encrypts actual (possibly large) message with AES (CBC)
    message = input("Enter plaintext message to encrypt with AES: ")
    ptb = message.encode('utf-8')
    ciphertext, iv = aes_encrypt(ptb, session_key, mode='CBC')
    print("AES ciphertext (hex prefix):", ciphertext.hex()[:200])
    print("IV (hex):", iv.hex())
    # --- TRANSMISSION: wrapped_key, iv, ciphertext sent to receiver ---
    # Receiver unwraps AES session key using private RSA key
    unwrapped_key = rsa_decrypt_with_priv(recv_priv, wrapped_key)
    print("Receiver recovered AES session key (hex):", unwrapped_key.hex())
    # Receiver decrypts AES ciphertext
    recovered = aes_decrypt(ciphertext, unwrapped_key, mode='CBC', iv=iv)
    print("Recovered plaintext:", recovered.decode('utf-8'))

# 4 Performance comparison
def action_performance():
    print("\nPerformance comparison: encrypting a 10KB message")
    size_kb = input("Message size in KB [10]: ").strip()
    size_kb = int(size_kb) if size_kb else 10
    msg = os.urandom(size_kb * 1024)  # random bytes as "plaintext"

    # 4a Pure RSA approach (not practical): split into blocks and RSA-encrypt each small block.
    bits = 2048
    print("Generating RSA keypair ({} bits) ...".format(bits))
    priv, pub = rsa_generate(bits)

    # determine max payload per RSA-OAEP encrypt: roughly key_size_bytes - 2*hash_len - 2
    # For 2048 bits, AES-OAEP with SHA-1 -> ~214 bytes payload; but we keep it simple: try small blocks of 190 bytes
    block_size = 190

    t0 = time()
    rsa_blocks = []
    for i in range(0, len(msg), block_size):
        block = msg[i:i+block_size]
        rsa_blocks.append(rsa_encrypt_with_pub(pub, block))
    t1 = time()
    rsa_encrypt_time = t1 - t0
    print("RSA-only encryption time for {} KB: {:.4f} s ({} blocks)".format(size_kb, rsa_encrypt_time, len(rsa_blocks)))

    # 4b Hybrid: RSA wrap of AES key + AES encrypt whole message
    session_key = get_random_bytes(16)
    t0 = time()
    wrapped = rsa_encrypt_with_pub(pub, session_key)   # one RSA operation
    ct, iv = aes_encrypt(msg, session_key, mode='CBC')  # one AES bulk op
    t1 = time()
    hybrid_time = t1 - t0
    print("Hybrid (1 RSA + AES bulk) time for {} KB: {:.4f} s".format(size_kb, hybrid_time))

    print("\nConclusion: Hybrid is much faster for large data (RSA-only does many expensive ops).")

# main loop
def main():
    while True:
        menu()
        choice = input("Choice: ").strip()
        if choice == '1':
            action_aes()
        elif choice == '2':
            action_rsa()
        elif choice == '3':
            action_hybrid()
        elif choice == '4':
            action_performance()
        elif choice == '5':
            print("Bye")
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    main()






















SHA

# sha256_merkle_lab.py
# Simple, readable SHA-256 implementation + analysis suite + Merkle tree
# Educational, self-contained (no external libraries).

import struct
import math
import time
import random
from collections import Counter

# ---------------------------
# SHA-256 Implementation
# ---------------------------

# Constants: first 32 bits of fractional parts of cube roots of first 64 primes
K = [
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]

def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def _shr(x, n):
    return x >> n

def _ch(x, y, z):
    return (x & y) ^ (~x & z)

def _maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def _big_sigma0(x):
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)

def _big_sigma1(x):
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)

def _small_sigma0(x):
    return _rotr(x, 7) ^ _rotr(x, 18) ^ _shr(x, 3)

def _small_sigma1(x):
    return _rotr(x, 17) ^ _rotr(x, 19) ^ _shr(x, 10)

def sha256(message_bytes):
    """Compute SHA-256 digest (bytes) for given message bytes."""
    # Initialize hash values (first 32 bits of fractional parts of sqrt of first 8 primes)
    H = [
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    ]

    # Pre-processing: padding
    ml = len(message_bytes) * 8  # message length in bits
    message = bytearray(message_bytes)
    message.append(0x80) # append '1' bit and seven '0' bits
    # append k zero bytes such that length ≡ 56 mod 64
    while (len(message) % 64) != 56:
        message.append(0)
    # append message length as 64-bit big-endian integer
    message += struct.pack('>Q', ml)

    # Process the message in successive 512-bit chunks
    for chunk_start in range(0, len(message), 64):
        chunk = message[chunk_start:chunk_start+64]
        # Create message schedule W[0..63] of 32-bit words
        W = [0]*64
        for t in range(16):
            W[t] = struct.unpack('>I', chunk[4*t:4*t+4])[0]
        for t in range(16, 64):
            s0 = _small_sigma0(W[t-15])
            s1 = _small_sigma1(W[t-2])
            W[t] = (W[t-16] + s0 + W[t-7] + s1) & 0xFFFFFFFF

        # Initialize working variables a..h with current hash value
        a,b,c,d,e,f,g,h = H

        # Compression function main loop
        for t in range(64):
            T1 = (h + _big_sigma1(e) + _ch(e,f,g) + K[t] + W[t]) & 0xFFFFFFFF
            T2 = (_big_sigma0(a) + _maj(a,b,c)) & 0xFFFFFFFF
            h = g
            g = f
            f = e
            e = (d + T1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (T1 + T2) & 0xFFFFFFFF

        # Add the compressed chunk to the current hash value
        H = [
            (H[0] + a) & 0xFFFFFFFF,
            (H[1] + b) & 0xFFFFFFFF,
            (H[2] + c) & 0xFFFFFFFF,
            (H[3] + d) & 0xFFFFFFFF,
            (H[4] + e) & 0xFFFFFFFF,
            (H[5] + f) & 0xFFFFFFFF,
            (H[6] + g) & 0xFFFFFFFF,
            (H[7] + h) & 0xFFFFFFFF,
        ]

    # Produce final hash value (big-endian)
    digest = b''.join(struct.pack('>I', hpart) for hpart in H)
    return digest

def sha256_hexdigest(message_bytes):
    return sha256(message_bytes).hex()

# ---------------------------
# Simple Security Analysis Tools
# ---------------------------

def avalanche_effect_test(input_text, bit_flips=1):
    """Flip some bits in the input and measure changed bits in hash (avalanche)."""
    m = bytearray(input_text.encode('utf-8'))
    h_orig = sha256(m)
    # Flip lowest bits in first 'bit_flips' positions (or random)
    m2 = bytearray(m)
    # flip sequential bits across bytes
    for i in range(bit_flips):
        byte_idx = i // 8
        bit_idx = i % 8
        if byte_idx >= len(m2):
            # extend with zero byte if needed
            m2 += b'\x00' * (byte_idx - len(m2) + 1)
        m2[byte_idx] ^= (1 << bit_idx)
    h_new = sha256(m2)
    # count differing bits
    diff_bits = 0
    for a,b in zip(h_orig, h_new):
        diff_bits += bin(a ^ b).count('1')
    print("Original hash:", h_orig.hex())
    print("Modified hash:", h_new.hex())
    print(f"Bit flips in input: {bit_flips}. Changed bits in hash: {diff_bits} / 256")
    return diff_bits

def distribution_test(num_samples=1000):
    """Check byte-frequency distribution across many hashes to observe uniformity."""
    counts = Counter()
    for i in range(num_samples):
        data = random.randbytes(random.randint(1,64))
        h = sha256(data)
        counts.update(h)  # counts each byte value's occurrences
    # compute frequencies
    total_bytes = num_samples * 32
    # Show top and bottom frequencies
    items = sorted(counts.items(), key=lambda kv: kv[1])
    print("Distribution (byte value : count) - lowest 5:")
    for val, cnt in items[:5]:
        print(val, cnt)
    print("... highest 5:")
    for val, cnt in items[-5:]:
        print(val, cnt)
    # simple metric: mean and variance
    freqs = [counts[i] for i in range(256)]
    mean = sum(freqs)/256
    var = sum((x-mean)**2 for x in freqs)/256
    print(f"Mean byte frequency: {mean:.2f}, Variance: {var:.2f}")

def birthday_collision_demo(target_bits=24, max_trials=200000):
    """
    Demo of birthday attack for collisions on first `target_bits` bits of hash.
    target_bits should be small (e.g., 24) to be practical.
    """
    print(f"Searching for collision on first {target_bits} bits (truncated SHA-256).")
    seen = {}
    mask = (1 << target_bits) - 1
    trials = 0
    while trials < max_trials:
        trials += 1
        data = random.randbytes(random.randint(1, 64))
        h = sha256(data)
        firstbits = int.from_bytes(h, 'big') >> (256 - target_bits)
        if firstbits in seen:
            print(f"Collision found after {trials} trials:")
            print("Message1 (hex):", seen[firstbits].hex())
            print("Message2 (hex):", data.hex())
            print("Truncated hash:", hex(firstbits))
            return True
        seen[firstbits] = data
    print("No collision found within max trials.")
    return False

def timing_benchmark(sizes_bytes=[16, 256, 1024, 4096, 16384], reps=20):
    """Time sha256 on inputs of different sizes (average over reps)."""
    print("Timing SHA-256 for sizes (bytes):", sizes_bytes)
    for size in sizes_bytes:
        t0 = time.time()
        for _ in range(reps):
            data = random.randbytes(size)
            sha256(data)
        t1 = time.time()
        avg_ms = (t1 - t0) * 1000 / reps
        print(f"Size {size} bytes: avg time {avg_ms:.3f} ms per hash")

def comparative_notes():
    print("""
Comparative notes (short):
- MD5: 128-bit digest, fast, but broken for collision resistance (practical collisions exist).
- SHA-1: 160-bit digest, faster than SHA-256 but collision attacks exist (practical).
- SHA-256: 256-bit digest, currently secure against practical collisions; stronger security margin.
Security properties:
- Pre-image & second pre-image: computationally infeasible for SHA-256 with current tech.
- Collision resistance: 2^128 brute force is theoretical bound; no practical collisions known for full SHA-256.
""")

# ---------------------------
# Merkle Tree Implementation
# ---------------------------

class MerkleTree:
    """Simple binary Merkle Tree using SHA-256 (non-balanced fill with duplicate last if odd)."""
    def __init__(self, data_blocks):
        """
        data_blocks: list of bytes (each block)
        """
        self.leaves = [sha256(d) for d in data_blocks]
        self.levels = []
        self.build_tree()

    def build_tree(self):
        cur = self.leaves[:]
        self.levels = [cur]
        while len(cur) > 1:
            nxt = []
            for i in range(0, len(cur), 2):
                left = cur[i]
                right = cur[i+1] if i+1 < len(cur) else cur[i]  # duplicate last if odd
                parent = sha256(left + right)
                nxt.append(parent)
            cur = nxt
            self.levels.append(cur)

    def root(self):
        if not self.levels:
            return None
        return self.levels[-1][0]

    def get_proof(self, index):
        """
        Returns a proof for leaf at `index`:
        list of tuples (sibling_hash, is_left) where is_left indicates whether sibling is the left node.
        """
        proof = []
        idx = index
        for level in self.levels[:-1]:  # exclude root level
            if idx % 2 == 0:
                # sibling is idx+1 if exists else duplicate
                sib_idx = idx+1 if idx+1 < len(level) else idx
                proof.append((level[sib_idx], False))  # sibling is right
            else:
                sib_idx = idx-1
                proof.append((level[sib_idx], True))   # sibling is left
            idx = idx // 2
        return proof

    @staticmethod
    def verify_proof(leaf_data, proof, root_hash):
        """Verify proof (list of (sibling_hash, is_left)) against expected root_hash."""
        computed = sha256(leaf_data)
        for sib_hash, is_left in proof:
            if is_left:
                computed = sha256(sib_hash + computed)
            else:
                computed = sha256(computed + sib_hash)
        return computed == root_hash

# ---------------------------
# Simple CLI Menu
# ---------------------------

def menu():
    print("\n=== SHA-256 & Merkle Lab ===")
    print("1) Compute SHA-256 hash (hex)")
    print("2) Avalanche effect test")
    print("3) Distribution test (random inputs)")
    print("4) Birthday collision demo (truncated bits)")
    print("5) Timing benchmark")
    print("6) Build Merkle tree and produce/verify proof")
    print("7) Comparative notes (MD5, SHA-1, SHA-256)")
    print("8) Quit")

def main():
    while True:
        menu()
        ch = input("Choice: ").strip()
        if ch == '1':
            s = input("Enter message: ")
            print("SHA-256:", sha256_hexdigest(s.encode('utf-8')))
        elif ch == '2':
            s = input("Enter base message: ")
            flips = input("Number of input bit flips [1]: ").strip()
            flips = int(flips) if flips else 1
            avalanche_effect_test(s, flips)
        elif ch == '3':
            n = input("Number of random samples [1000]: ").strip()
            n = int(n) if n else 1000
            distribution_test(n)
        elif ch == '4':
            bits = input("Target bits for collision (e.g., 20-26) [24]: ").strip()
            bits = int(bits) if bits else 24
            birthday_collision_demo(bits)
        elif ch == '5':
            timing_benchmark()
        elif ch == '6':
            n = input("Number of data blocks [5]: ").strip()
            n = int(n) if n else 5
            blocks = []
            print("Enter blocks (press Enter to auto-randomize):")
            for i in range(n):
                line = input(f"Block {i}: ")
                if not line:
                    blocks.append(random.randbytes(random.randint(4,64)))
                else:
                    blocks.append(line.encode('utf-8'))
            tree = MerkleTree(blocks)
            print("Root hash:", tree.root().hex())
            idx = int(input(f"Which block index to prove (0..{n-1})? "))
            proof = tree.get_proof(idx)
            print("Proof length:", len(proof))
            ok = MerkleTree.verify_proof(blocks[idx], proof, tree.root())
            print("Verification result:", ok)
        elif ch == '7':
            comparative_notes()
        elif ch == '8':
            print("Bye")
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    main()


































X509

pip install cryptography

"""
mini_pki.py -- Simple X.509 parser, chain validator, and tiny CA operations demo.

Requirements:
    pip install cryptography
Run:
    python mini_pki.py
"""

import os
import sys
import time
import random
from datetime import datetime, timedelta

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtensionOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
    from cryptography.hazmat.backends import default_backend
except Exception as e:
    print("Missing 'cryptography'. Install with: pip install cryptography")
    print("Import error:", e)
    sys.exit(1)

STORE_DIR = "pki_store"
if not os.path.exists(STORE_DIR):
    os.makedirs(STORE_DIR)

# -----------------------
# Utilities for files
# -----------------------
def save_bytes(path, data):
    open(path, "wb").write(data)
    print("Saved:", path)

def load_bytes(path):
    return open(path, "rb").read()

def path_in_store(name):
    return os.path.join(STORE_DIR, name)

# -----------------------
# X.509 parsing
# -----------------------
def load_cert_from_file(path):
    data = load_bytes(path)
    try:
        cert = x509.load_pem_x509_certificate(data, default_backend())
    except ValueError:
        cert = x509.load_der_x509_certificate(data, default_backend())
    return cert

def pretty_name(name):
    # convert x509.Name to readable string
    return ", ".join(f"{attr.oid._name}={attr.value}" for attr in name)

def parse_and_print_certificate(path):
    try:
        cert = load_cert_from_file(path)
    except Exception as e:
        print("Failed to load certificate:", e)
        return
    print("\n=== Certificate:", path, "===\n")
    print("Version:", cert.version.name)
    print("Serial Number:", cert.serial_number)
    print("Signature Algorithm:", cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else cert.signature_algorithm_oid._name)
    print("Issuer:", pretty_name(cert.issuer))
    print("Subject:", pretty_name(cert.subject))
    print("Not valid before:", cert.not_valid_before)
    print("Not valid after :", cert.not_valid_after)
    print("Public key type:", cert.public_key().__class__.__name__)
    print("\nExtensions:")
    for ext in cert.extensions:
        try:
            print(" -", ext.oid._name, ":", ext.value)
        except Exception:
            print(" -", ext.oid, ":", ext.value)
    print("\nRaw fingerprint (SHA256):", cert.fingerprint(hashes.SHA256()).hex())
    print("PEM length:", len(cert.public_bytes(serialization.Encoding.PEM)), "bytes")
    print("===============================\n")

# -----------------------
# Simple CA operations
# -----------------------
def create_rsa_key(key_size=2048):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    return key

def write_key_to_file(key, path, password=None):
    if password:
        enc = serialization.BestAvailableEncryption(password.encode())
    else:
        enc = serialization.NoEncryption()
    pem = key.private_bytes(encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                            encryption_algorithm=enc)
    save_bytes(path, pem)

def write_cert_to_file(cert, path):
    pem = cert.public_bytes(serialization.Encoding.PEM)
    save_bytes(path, pem)

def create_self_signed_ca(common_name="MyMiniRootCA", key_size=2048, days=3650):
    key = create_rsa_key(key_size)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.utcnow()
    cert = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(issuer)\
        .public_key(key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(now - timedelta(days=1))\
        .not_valid_after(now + timedelta(days=days))\
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)\
        .add_extension(x509.KeyUsage(key_cert_sign=True, digital_signature=True,
                                     key_encipherment=False, content_commitment=True,
                                     data_encipherment=False, key_agreement=False,
                                     encipher_only=False, decipher_only=False, crl_sign=True),
                       critical=True)\
        .sign(private_key=key, algorithm=hashes.SHA256(), backend=default_backend())
    # Save
    ts = int(time.time())
    key_path = path_in_store(f"ca_{common_name}_{ts}_key.pem")
    cert_path = path_in_store(f"ca_{common_name}_{ts}_cert.pem")
    write_key_to_file(key, key_path)
    write_cert_to_file(cert, cert_path)
    print("Created CA key and self-signed certificate.")
    return key_path, cert_path

def issue_certificate(subject_cn, issuer_key_path, issuer_cert_path, is_ca=False, days=365, key_size=2048):
    # Generate subject key
    subj_key = create_rsa_key(key_size)
    subj_pub = subj_key.public_key()
    now = datetime.utcnow()

    # load issuer
    issuer_key_pem = load_bytes(issuer_key_path)
    issuer_key = load_pem_private_key(issuer_key_pem, password=None, backend=default_backend())
    issuer_cert = load_cert_from_file(issuer_cert_path)
    issuer_name = issuer_cert.subject

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    builder = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(issuer_name)\
        .public_key(subj_pub)\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(now - timedelta(minutes=1))\
        .not_valid_after(now + timedelta(days=days))\
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)

    # add KeyUsage for end-entity
    builder = builder.add_extension(x509.KeyUsage(key_cert_sign=is_ca, digital_signature=True,
                                                  key_encipherment=True, content_commitment=True,
                                                  data_encipherment=False, key_agreement=False,
                                                  encipher_only=False, decipher_only=False, crl_sign=is_ca),
                                    critical=True)
    cert = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256(), backend=default_backend())

    ts = int(time.time())
    subj_key_path = path_in_store(f"{subject_cn}_{ts}_key.pem")
    subj_cert_path = path_in_store(f"{subject_cn}_{ts}_cert.pem")
    write_key_to_file(subj_key, subj_key_path)
    write_cert_to_file(cert, subj_cert_path)
    print(f"Issued certificate for {subject_cn}")
    return subj_key_path, subj_cert_path

# -----------------------
# Revocation (simple)
# -----------------------
CRL_FILE = path_in_store("mini_crl.txt")
def revoke_certificate(cert_path, reason="unspecified"):
    cert = load_cert_from_file(cert_path)
    serial = cert.serial_number
    with open(CRL_FILE, "a") as f:
        f.write(f"{serial},{reason},{int(time.time())}\n")
    print("Revoked cert serial:", serial)

def is_revoked(cert):
    if not os.path.exists(CRL_FILE):
        return False
    serial = cert.serial_number
    with open(CRL_FILE, "r") as f:
        for line in f:
            parts = line.strip().split(",")
            if parts and int(parts[0]) == serial:
                return True
    return False

# -----------------------
# Chain validation (basic)
# -----------------------
def verify_signature(cert_to_check, signer_pubkey):
    """
    Verify cert_to_check was signed by signer_pubkey.
    """
    try:
        signer_pubkey.verify(
            signature=cert_to_check.signature,
            data=cert_to_check.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=cert_to_check.signature_hash_algorithm
        )
        return True
    except Exception as e:
        return False

def validate_chain(chain_paths, trusted_root_paths):
    """
    chain_paths: list of cert file paths in order [end-entity, intermediate1, ..., maybe root]
    trusted_root_paths: list of root cert files considered trusted
    Returns (valid_bool, reason)
    """
    # load chain certs
    try:
        chain_certs = [load_cert_from_file(p) for p in chain_paths]
    except Exception as e:
        return False, f"Failed to load chain: {e}"

    # load trusted roots
    trusted_roots = [load_cert_from_file(p) for p in trusted_root_paths]

    # basic checks: validity periods and revocation
    now = datetime.utcnow()
    for cert in chain_certs:
        if cert.not_valid_before > now or cert.not_valid_after < now:
            return False, f"Certificate with serial {cert.serial_number} not within validity period."
        if is_revoked(cert):
            return False, f"Certificate serial {cert.serial_number} is revoked."

    # verify signatures up the chain: for each cert i, verify signed by cert i+1 public key;
    # final cert should be signed by one of the trusted roots.
    for i in range(len(chain_certs)-1):
        child = chain_certs[i]
        issuer = chain_certs[i+1]
        issuer_pub = issuer.public_key()
        if not verify_signature(child, issuer_pub):
            return False, f"Signature verification failed for cert serial {child.serial_number} signed by next cert."

    # try each trusted root: check if last cert in chain is signed by a trusted root OR matches trusted root itself
    top = chain_certs[-1]
    for root in trusted_roots:
        # either top equals root (self-signed root) or top signed by root
        if top.fingerprint(hashes.SHA256()) == root.fingerprint(hashes.SHA256()):
            # top is the trusted root itself
            return True, "Chain valid and ends in trusted root."
        else:
            root_pub = root.public_key()
            if verify_signature(top, root_pub):
                return True, "Chain valid and signed by a trusted root."
    return False, "Top of chain is not trusted."

# -----------------------
# Simple CLI Menu
# -----------------------
def menu():
    print("\n== Mini PKI Menu ==")
    print("1) Parse X.509 certificate file (PEM or DER)")
    print("2) Validate certificate chain")
    print("3) CA operations: create CA / issue cert")
    print("4) Revoke certificate")
    print("5) Certificate status check (revoked/valid)")
    print("6) List pki_store files")
    print("7) Quit")

def list_store():
    print("Files in store:")
    for fn in sorted(os.listdir(STORE_DIR)):
        print(" -", fn)

def action_parse():
    path = input("Enter certificate file path: ").strip()
    if not os.path.exists(path):
        print("File not found.")
        return
    parse_and_print_certificate(path)

def action_validate_chain():
    print("Enter chain file paths in order (end-entity first), comma-separated.")
    s = input("Chain paths: ").strip()
    chain_paths = [p.strip() for p in s.split(",") if p.strip()]
    print("Enter trusted root cert paths (comma-separated).")
    s2 = input("Roots: ").strip()
    roots = [p.strip() for p in s2.split(",") if p.strip()]
    valid, reason = validate_chain(chain_paths, roots)
    print("Validation result:", valid, "-", reason)

def action_ca_ops():
    print("1) Create self-signed CA")
    print("2) Issue certificate signed by existing CA")
    opt = input("Choice: ").strip()
    if opt == '1':
        cn = input("CA Common Name [MiniRootCA]: ").strip() or "MiniRootCA"
        ks = input("Key size [2048]: ").strip()
        ks = int(ks) if ks else 2048
        create_self_signed_ca(common_name=cn, key_size=ks)
    elif opt == '2':
        issuer_key = input("Issuer private key file path: ").strip()
        issuer_cert = input("Issuer cert file path: ").strip()
        if not (os.path.exists(issuer_key) and os.path.exists(issuer_cert)):
            print("Issuer files not found.")
            return
        subj_cn = input("Subject CN (e.g., alice.example): ").strip()
        is_ca = input("Should the issued cert be CA? (y/N): ").strip().lower() == 'y'
        issue_certificate(subj_cn, issuer_key, issuer_cert, is_ca=is_ca)
    else:
        print("Unknown option.")

def action_revoke():
    path = input("Certificate file path to revoke: ").strip()
    if not os.path.exists(path):
        print("Not found.")
        return
    reason = input("Reason (optional): ").strip() or "unspecified"
    revoke_certificate(path, reason)

def action_status_check():
    path = input("Certificate file path to check: ").strip()
    if not os.path.exists(path):
        print("Not found.")
        return
    cert = load_cert_from_file(path)
    print("Serial:", cert.serial_number)
    print("Subject:", pretty_name(cert.subject))
    print("Issuer:", pretty_name(cert.issuer))
    now = datetime.utcnow()
    if cert.not_valid_before > now or cert.not_valid_after < now:
        print("Status: Not currently valid (time).")
    elif is_revoked(cert):
        print("Status: Revoked.")
    else:
        print("Status: Valid (not revoked and within validity period).")

def main():
    print("Mini PKI demo. store:", STORE_DIR)
    while True:
        menu()
        ch = input("Choice: ").strip()
        if ch == '1':
            action_parse()
        elif ch == '2':
            action_validate_chain()
        elif ch == '3':
            action_ca_ops()
        elif ch == '4':
            action_revoke()
        elif ch == '5':
            action_status_check()
        elif ch == '6':
            list_store()
        elif ch == '7':
            print("Bye")
            break 
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()









