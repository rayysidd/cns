#!/usr/bin/env python3
"""
crypto_lab.py

Single-file implementation of:
 - AES-128 (SubBytes, ShiftRows, MixColumns, AddRoundKey, KeyExpansion)
 - AES modes: ECB and CBC (PKCS#7)
 - RSA key generation (Miller-Rabin), PKCS#1 v1.5 padding, encrypt/decrypt
 - Hybrid cryptosystem (AES session key encrypted with RSA)
 - Performance comparison: pure RSA vs Hybrid

All inputs and outputs are logged to LOG_FILE (output.txt) with timestamps.
Usage: python3 crypto_lab.py
"""
import os
import sys
import struct
import time
import secrets
from math import ceil, log2

LOG_FILE = "output.txt"

def now_ts():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

def log_to_file(text: str):
    """Append timestamped text to the log file for lab records."""
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{now_ts()}] {text}\n")

def bytes_xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    padding = block_size - (len(data) % block_size)
    return data + bytes([padding]) * padding

def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Invalid padding (empty data)")
    p = data[-1]
    if p < 1 or p > 16:
        raise ValueError("Invalid padding value")
    if data[-p:] != bytes([p]) * p:
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-p]

# ---------------------------
# AES-128 Implementation
# ---------------------------

SBOX = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

INV_SBOX = [0]*256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

RCON = [
0x00000000,
0x01000000,0x02000000,0x04000000,0x08000000,
0x10000000,0x20000000,0x40000000,0x80000000,
0x1b000000,0x36000000
]

def sub_word(word: int) -> int:
    return ((SBOX[(word >> 24) & 0xFF] << 24) |
            (SBOX[(word >> 16) & 0xFF] << 16) |
            (SBOX[(word >> 8) & 0xFF] << 8) |
            (SBOX[word & 0xFF]))

def rot_word(word: int) -> int:
    return ((word << 8) & 0xFFFFFFFF) | ((word >> 24) & 0xFF)

def key_expansion(key: bytes) -> list:
    # AES-128: Nk=4, Nr=10, Nb=4
    assert len(key) == 16
    Nk = 4
    Nb = 4
    Nr = 10
    w = [0] * (Nb * (Nr + 1))
    # initial words
    for i in range(Nk):
        w[i] = struct.unpack(">I", key[4*i:4*i+4])[0]
    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i - 1]
        if i % Nk == 0:
            temp = sub_word(rot_word(temp)) ^ RCON[i // Nk]
        w[i] = w[i - Nk] ^ temp
    return w

def add_round_key(state: list, round_key_words: list):
    # state is 4x4 bytes as list of 16 ints column-major
    for c in range(4):
        word = round_key_words[c]
        state[4*c + 0] ^= (word >> 24) & 0xFF
        state[4*c + 1] ^= (word >> 16) & 0xFF
        state[4*c + 2] ^= (word >> 8) & 0xFF
        state[4*c + 3] ^= word & 0xFF

def sub_bytes(state: list):
    for i in range(16):
        state[i] = SBOX[state[i]]

def inv_sub_bytes(state: list):
    for i in range(16):
        state[i] = INV_SBOX[state[i]]

def shift_rows(state: list):
    # rows are bytes at positions: row r, column c => index = 4*c + r
    new = state.copy()
    for r in range(4):
        for c in range(4):
            new[4*c + r] = state[4*((c + r) % 4) + r]
    state[:] = new

def inv_shift_rows(state: list):
    new = state.copy()
    for r in range(4):
        for c in range(4):
            new[4*c + r] = state[4*((c - r) % 4) + r]
    state[:] = new

def gmul(a: int, b: int) -> int:
    p = 0
    for i in range(8):
        if b & 1:
            p ^= a
        hi_bit = a & 0x80
        a <<= 1
        if hi_bit:
            a ^= 0x11b
        a &= 0xFF
        b >>= 1
    return p

def mix_columns(state: list):
    for c in range(4):
        i = 4*c
        a0, a1, a2, a3 = state[i], state[i+1], state[i+2], state[i+3]
        state[i+0] = gmul(0x02, a0) ^ gmul(0x03, a1) ^ a2 ^ a3
        state[i+1] = a0 ^ gmul(0x02, a1) ^ gmul(0x03, a2) ^ a3
        state[i+2] = a0 ^ a1 ^ gmul(0x02, a2) ^ gmul(0x03, a3)
        state[i+3] = gmul(0x03, a0) ^ a1 ^ a2 ^ gmul(0x02, a3)

def inv_mix_columns(state: list):
    for c in range(4):
        i = 4*c
        a0, a1, a2, a3 = state[i], state[i+1], state[i+2], state[i+3]
        state[i+0] = gmul(0x0e, a0) ^ gmul(0x0b, a1) ^ gmul(0x0d, a2) ^ gmul(0x09, a3)
        state[i+1] = gmul(0x09, a0) ^ gmul(0x0e, a1) ^ gmul(0x0b, a2) ^ gmul(0x0d, a3)
        state[i+2] = gmul(0x0d, a0) ^ gmul(0x09, a1) ^ gmul(0x0e, a2) ^ gmul(0x0b, a3)
        state[i+3] = gmul(0x0b, a0) ^ gmul(0x0d, a1) ^ gmul(0x09, a2) ^ gmul(0x0e, a3)

def aes_encrypt_block(block: bytes, round_keys: list) -> bytes:
    assert len(block) == 16
    state = list(block)
    Nr = 10
    add_round_key(state, round_keys[0:4])
    for rnd in range(1, Nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[4*rnd:4*(rnd+1)])
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[4*Nr:4*(Nr+1)])
    return bytes(state)

def aes_decrypt_block(block: bytes, round_keys: list) -> bytes:
    assert len(block) == 16
    state = list(block)
    Nr = 10
    add_round_key(state, round_keys[4*Nr:4*(Nr+1)])
    inv_shift_rows(state)
    inv_sub_bytes(state)
    for rnd in range(Nr-1, 0, -1):
        add_round_key(state, round_keys[4*rnd:4*(rnd+1)])
        inv_mix_columns(state)
        inv_shift_rows(state)
        inv_sub_bytes(state)
    add_round_key(state, round_keys[0:4])
    return bytes(state)

def aes_key_schedule_bytes(key: bytes):
    return key_expansion(key)

def aes_encrypt(data: bytes, key: bytes, mode: str = "ECB", iv: bytes = None) -> bytes:
    assert mode in ("ECB", "CBC")
    round_keys = aes_key_schedule_bytes(key)
    data_p = pkcs7_pad(data, 16)
    out = bytearray()
    if mode == "ECB":
        for i in range(0, len(data_p), 16):
            out.extend(aes_encrypt_block(data_p[i:i+16], round_keys))
    else:  # CBC
        if iv is None:
            raise ValueError("IV required for CBC")
        prev = iv
        for i in range(0, len(data_p), 16):
            block = bytes_xor(data_p[i:i+16], prev)
            ct = aes_encrypt_block(block, round_keys)
            out.extend(ct)
            prev = ct
    return bytes(out)

def aes_decrypt(data: bytes, key: bytes, mode: str = "ECB", iv: bytes = None) -> bytes:
    assert mode in ("ECB", "CBC")
    round_keys = aes_key_schedule_bytes(key)
    out = bytearray()
    if mode == "ECB":
        for i in range(0, len(data), 16):
            out.extend(aes_decrypt_block(data[i:i+16], round_keys))
    else:
        if iv is None:
            raise ValueError("IV required for CBC")
        prev = iv
        for i in range(0, len(data), 16):
            dec = aes_decrypt_block(data[i:i+16], round_keys)
            out.extend(bytes_xor(dec, prev))
            prev = data[i:i+16]
    return pkcs7_unpad(bytes(out))

# ---------------------------
# RSA Implementation
# ---------------------------

def is_probable_prime(n: int, k: int = 12) -> bool:
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        skip = False
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                skip = True
                break
        if skip:
            continue
        return False
    return True

def generate_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate

def egcd(a:int,b:int):
    if b==0:
        return (a,1,0)
    g,x1,y1 = egcd(b, a%b)
    return (g, y1, x1 - (a//b)*y1)

def modinv(a:int, m:int):
    g,x,y = egcd(a,m)
    if g!=1:
        raise Exception("modular inverse does not exist")
    return x % m

def rsa_generate_keys(bits: int = 1024):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while q == p:
        q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if phi % e == 0:
        e = 3
        while phi % e == 0:
            e = secrets.choice([3,5,17,257,65537])
    d = modinv(e, phi)
    return {'n': n, 'e': e, 'd': d, 'p': p, 'q': q}

def rsa_pkcs1_v1_5_pad_encrypt(message: bytes, k: int) -> bytes:
    mlen = len(message)
    if mlen > k - 11:
        raise ValueError("message too long for RSA PKCS#1 v1.5 padding")
    ps_len = k - mlen - 3
    ps = bytearray()
    while len(ps) < ps_len:
        b = secrets.token_bytes(1)
        if b != b'\x00':
            ps += b
    return b'\x00\x02' + bytes(ps) + b'\x00' + message

def rsa_pkcs1_v1_5_unpad_decrypt(em: bytes) -> bytes:
    if len(em) < 11:
        raise ValueError("decryption error")
    if em[0] != 0x00 or em[1] != 0x02:
        raise ValueError("decryption error")
    sep_idx = em.find(b'\x00', 2)
    if sep_idx < 0 or sep_idx < 10:
        raise ValueError("decryption error")
    return em[sep_idx+1:]

def rsa_encrypt(message: bytes, pub: dict) -> int:
    n = pub['n']
    e = pub['e']
    k = (n.bit_length() + 7)//8
    em = rsa_pkcs1_v1_5_pad_encrypt(message, k)
    m_int = int.from_bytes(em, 'big')
    c = pow(m_int, e, n)
    return c

def rsa_decrypt_int(c_int: int, priv: dict) -> bytes:
    n = priv['n']
    d = priv['d']
    k = (n.bit_length() + 7)//8
    m_int = pow(c_int, d, n)
    em = m_int.to_bytes(k, 'big')
    return rsa_pkcs1_v1_5_unpad_decrypt(em)

def rsa_encrypt_bytes(message: bytes, pub: dict) -> bytes:
    c_int = rsa_encrypt(message, pub)
    k = (pub['n'].bit_length() + 7)//8
    return c_int.to_bytes(k, 'big')

def rsa_decrypt_bytes(cipher_bytes: bytes, priv: dict) -> bytes:
    c_int = int.from_bytes(cipher_bytes, 'big')
    return rsa_decrypt_int(c_int, priv)

def rsa_encrypt_large(message: bytes, pub: dict) -> bytes:
    n = pub['n']
    k = (n.bit_length() + 7)//8
    max_chunk = k - 11
    out = bytearray()
    for i in range(0, len(message), max_chunk):
        chunk = message[i:i+max_chunk]
        out.extend(rsa_encrypt_bytes(chunk, pub))
    return bytes(out)

def rsa_decrypt_large(cipher: bytes, priv: dict) -> bytes:
    n = priv['n']
    k = (n.bit_length() + 7)//8
    if len(cipher) % k != 0:
        raise ValueError("invalid ciphertext length for RSA large decrypt")
    out = bytearray()
    for i in range(0, len(cipher), k):
        block = cipher[i:i+k]
        out.extend(rsa_decrypt_bytes(block, priv))
    return bytes(out)

# ---------------------------
# Hybrid Cryptosystem
# ---------------------------

def hybrid_encrypt(plaintext: bytes, rsa_pub: dict, aes_mode: str = "CBC") -> dict:
    session_key = secrets.token_bytes(16)
    enc_session = rsa_encrypt_bytes(session_key, rsa_pub)
    iv = secrets.token_bytes(16) if aes_mode == "CBC" else b'\x00'*16
    ciphertext = aes_encrypt(plaintext, session_key, mode=aes_mode, iv=iv if aes_mode=="CBC" else None)
    return {
        'enc_session_key': enc_session,
        'iv': iv,
        'ciphertext': ciphertext
    }

def hybrid_decrypt(package: dict, rsa_priv: dict, aes_mode: str = "CBC") -> bytes:
    session_key = rsa_decrypt_bytes(package['enc_session_key'], rsa_priv)
    iv = package['iv'] if aes_mode == "CBC" else None
    plaintext = aes_decrypt(package['ciphertext'], session_key, mode=aes_mode, iv=iv)
    return plaintext

# ---------------------------
# CLI Menu and Demo (with logging)
# ---------------------------

def input_bytes(prompt: str = "") -> bytes:
    s = input(prompt)
    return s.encode('utf-8')

def run_aes_menu():
    print("\n-- AES Encryption/Decryption --")
    key_input = input("Enter 16-byte key (ascii) or empty to generate random: ")
    if key_input == "":
        key = secrets.token_bytes(16)
        print("Generated key (hex):", key.hex())
    else:
        keyb = key_input.encode('utf-8')
        if len(keyb) != 16:
            print("Key must be 16 bytes (AES-128). Padding/trimming applied.")
            keyb = (keyb + b'\x00'*16)[:16]
        key = keyb
    mode = input("Mode (ECB/CBC) [CBC]: ").strip().upper() or "CBC"
    if mode not in ("ECB","CBC"):
        mode = "CBC"
    iv = None
    if mode == "CBC":
        iv = secrets.token_bytes(16)
        print("IV (hex):", iv.hex())
    plaintext = input("Enter plaintext: ").encode('utf-8')
    try:
        ct = aes_encrypt(plaintext, key, mode=mode, iv=iv)
        pt = aes_decrypt(ct, key, mode=mode, iv=iv)
        print("Ciphertext (hex):", ct.hex())
        print("Decrypted plaintext:", pt.decode('utf-8', errors='replace'))
        # Logging
        log_to_file("=== AES ===")
        log_to_file(f"Mode: {mode}")
        log_to_file(f"Key (hex): {key.hex()}")
        if iv:
            log_to_file(f"IV (hex): {iv.hex()}")
        log_to_file(f"Plaintext: {plaintext.decode('utf-8', errors='replace')}")
        log_to_file(f"Ciphertext (hex): {ct.hex()}")
        log_to_file(f"Decrypted: {pt.decode('utf-8', errors='replace')}")
        log_to_file("")  # blank line
    except Exception as ex:
        print("AES error:", ex)
        log_to_file(f"AES error: {ex}")

def run_rsa_menu():
    print("\n-- RSA Key Generation / Encrypt / Decrypt --")
    bits = int(input("Key size in bits [1024]: ") or "1024")
    print("Generating RSA keys... this may take a while (Miller-Rabin primality test).")
    t0 = time.time()
    keys = rsa_generate_keys(bits)
    t1 = time.time()
    elapsed = t1 - t0
    print(f"Generated RSA keypair in {elapsed:.2f}s.")
    print("Public modulus n (hex):", hex(keys['n']))
    print("Public exponent e:", keys['e'])
    demo_plain = input("Enter a short message to encrypt with RSA (will be PKCS#1 v1.5 padded): ").encode('utf-8')
    try:
        ct = rsa_encrypt_bytes(demo_plain, keys)
        pt = rsa_decrypt_bytes(ct, keys)
        print("Ciphertext (hex):", ct.hex()[:200] + ("..." if len(ct.hex())>200 else ""))
        print("Decrypted plaintext:", pt.decode('utf-8', errors='replace'))
        # Logging
        log_to_file("=== RSA ===")
        log_to_file(f"Key size (bits): {bits}")
        log_to_file(f"Key generation time (s): {elapsed:.3f}")
        log_to_file(f"Public exponent: {keys['e']}")
        log_to_file(f"Plaintext: {demo_plain.decode('utf-8', errors='replace')}")
        log_to_file(f"Ciphertext (hex): {ct.hex()}")
        log_to_file(f"Decrypted: {pt.decode('utf-8', errors='replace')}")
        log_to_file("")
    except Exception as ex:
        print("RSA error:", ex)
        log_to_file(f"RSA error: {ex}")
    return keys

def run_hybrid_menu(rsa_keys):
    print("\n-- Hybrid Encryption Demo --")
    plaintext = input("Enter plaintext to send: ").encode('utf-8')
    mode = input("AES mode (ECB/CBC) [CBC]: ").strip().upper() or "CBC"
    try:
        package = hybrid_encrypt(plaintext, rsa_keys, aes_mode=mode)
        print("Package created.")
        print("Encrypted session key (hex prefix):", package['enc_session_key'].hex()[:200] + ("..." if len(package['enc_session_key'].hex())>200 else ""))
        print("IV (hex):", package['iv'].hex() if package['iv'] else "None")
        print("Ciphertext (hex prefix):", package['ciphertext'].hex()[:200] + ("..." if len(package['ciphertext'].hex())>200 else ""))
        recovered = hybrid_decrypt(package, rsa_keys, aes_mode=mode)
        print("Recovered plaintext:", recovered.decode('utf-8', errors='replace'))
        # Logging
        log_to_file("=== Hybrid ===")
        log_to_file(f"AES mode: {mode}")
        log_to_file(f"Plaintext: {plaintext.decode('utf-8', errors='replace')}")
        log_to_file(f"Encrypted session key (hex): {package['enc_session_key'].hex()}")
        if package['iv']:
            log_to_file(f"IV (hex): {package['iv'].hex()}")
        log_to_file(f"Ciphertext (hex): {package['ciphertext'].hex()}")
        log_to_file(f"Decrypted: {recovered.decode('utf-8', errors='replace')}")
        log_to_file("")
    except Exception as ex:
        print("Hybrid error:", ex)
        log_to_file(f"Hybrid error: {ex}")

def run_perf_comparison(rsa_keys):
    print("\n-- Performance Comparison: Pure RSA vs Hybrid --")
    sizes = [1024, 10*1024, 100*1024]  # 1KB, 10KB, 100KB
    n = rsa_keys['n']
    k = (n.bit_length() + 7)//8
    print(f"RSA modulus size: {n.bit_length()} bits ({k} bytes). Max RSA data chunk per encrypt: {k-11} bytes")
    log_to_file("=== Performance Comparison ===")
    log_to_file(f"RSA modulus bits: {n.bit_length()}, k bytes: {k}, max chunk: {k-11}")
    for s in sizes:
        print(f"\nMessage size: {s} bytes")
        message = secrets.token_bytes(s)
        # Pure RSA
        t0 = time.time()
        try:
            rsa_ct = rsa_encrypt_large(message, rsa_keys)
            t1 = time.time()
            rsa_dec = rsa_decrypt_large(rsa_ct, rsa_keys)
            t2 = time.time()
            ok = rsa_dec == message
            print(f"Pure RSA encrypt: {t1-t0:.3f}s, decrypt: {t2-t1:.3f}s, total: {t2-t0:.3f}s, success: {ok}")
            log_to_file(f"Pure RSA size {s} bytes: encrypt {t1-t0:.3f}s decrypt {t2-t1:.3f}s total {t2-t0:.3f}s success {ok}")
        except Exception as ex:
            print("Pure RSA failed (message too big or other):", ex)
            log_to_file(f"Pure RSA size {s} bytes failed: {ex}")
        # Hybrid
        t0 = time.time()
        package = hybrid_encrypt(message, rsa_keys, aes_mode="CBC")
        t1 = time.time()
        recovered = hybrid_decrypt(package, rsa_keys, aes_mode="CBC")
        t2 = time.time()
        ok2 = recovered == message
        print(f"Hybrid encrypt: {t1-t0:.3f}s, decrypt: {t2-t1:.3f}s, total: {t2-t0:.3f}s, success: {ok2}")
        log_to_file(f"Hybrid size {s} bytes: encrypt {t1-t0:.3f}s decrypt {t2-t1:.3f}s total {t2-t0:.3f}s success {ok2}")
    print("\nConclusion: Hybrid should be much faster and more practical for larger messages.")
    log_to_file("Conclusion: Hybrid should be much faster and more practical for larger messages.")
    log_to_file("")

def menu():
    rsa_keys = None
    while True:
        print("\n===== Crypto Lab Menu =====")
        print("1) AES Encryption/Decryption (ECB/CBC)")
        print("2) RSA Keygen / Encrypt / Decrypt")
        print("3) Hybrid System (AES session key encrypted with RSA)")
        print("4) Performance Comparison (Pure RSA vs Hybrid)")
        print("5) Quit")
        choice = input("Choose: ").strip()
        if choice == '1':
            run_aes_menu()
        elif choice == '2':
            rsa_keys = run_rsa_menu()
        elif choice == '3':
            if rsa_keys is None:
                print("First generate RSA keys (option 2).")
            else:
                run_hybrid_menu(rsa_keys)
        elif choice == '4':
            if rsa_keys is None:
                print("First generate RSA keys (option 2).")
            else:
                run_perf_comparison(rsa_keys)
        elif choice == '5':
            print("Bye.")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting.")
        sys.exit(0)
