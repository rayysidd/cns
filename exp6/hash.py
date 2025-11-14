import struct
import time
import hashlib
import random
import os

# =========================================================
# SHA-256 IMPLEMENTATION
# =========================================================

def rotr(x, n): return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
def Ch(x, y, z): return (x & y) ^ (~x & z)
def Maj(x, y, z): return (x & y) ^ (x & z) ^ (y & z)
def Sigma0(x): return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
def Sigma1(x): return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
def sigma0(x): return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
def sigma1(x): return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)

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

H0 = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]

def sha256(message: bytes):
    ml = len(message) * 8
    message += b'\x80'
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'
    message += struct.pack('>Q', ml)

    H = H0[:]
    for i in range(0, len(message), 64):
        w = list(struct.unpack('>16L', message[i:i+64]))
        for j in range(16, 64):
            w.append((sigma1(w[j-2]) + w[j-7] + sigma0(w[j-15]) + w[j-16]) & 0xFFFFFFFF)

        a,b,c,d,e,f,g,h = H
        for j in range(64):
            t1 = (h + Sigma1(e) + Ch(e,f,g) + K[j] + w[j]) & 0xFFFFFFFF
            t2 = (Sigma0(a) + Maj(a,b,c)) & 0xFFFFFFFF
            h,g,f,e,d,c,b,a = g,f,e,(d+t1)&0xFFFFFFFF,c,b,a,(t1+t2)&0xFFFFFFFF
        H = [(x+y) & 0xFFFFFFFF for x,y in zip(H,[a,b,c,d,e,f,g,h])]

    return ''.join(f'{h:08x}' for h in H)

# =========================================================
# SECURITY ANALYSIS
# =========================================================

def avalanche_effect(text):
    original_hash = sha256(text.encode())
    flipped = bytearray(text.encode())
    flipped[0] ^= 1
    new_hash = sha256(bytes(flipped))
    diff_bits = sum(bin(int(a,16) ^ int(b,16)).count("1")
                    for a,b in zip([original_hash[i:i+8] for i in range(0,64,8)],
                                   [new_hash[i:i+8] for i in range(0,64,8)]))
    return (diff_bits/256)*100

def collision_simulation(trials=5000):
    seen = {}
    for _ in range(trials):
        text = str(random.random())
        h = sha256(text.encode())[:8]
        if h in seen: return True
        seen[h] = True
    return False

def performance_test():
    sizes = [10,100,1000,10000]
    results = {}
    for s in sizes:
        data = b'a'*s
        start = time.time()
        sha256(data)
        end = time.time()
        results[s] = (end-start)*1000
    return results

def compare_with_md5_sha1(text):
    return {
        "MD5": hashlib.md5(text.encode()).hexdigest(),
        "SHA1": hashlib.sha1(text.encode()).hexdigest(),
        "SHA256": sha256(text.encode())
    }

# =========================================================
# MERKLE TREE
# =========================================================

class MerkleTree:
    def __init__(self, data_blocks):
        self.leaves = [sha256(block.encode()) for block in data_blocks]
        self.root = self.build_tree(self.leaves)

    def build_tree(self, nodes):
        if len(nodes) == 1: return nodes[0]
        new_level = []
        for i in range(0,len(nodes),2):
            left = nodes[i]
            right = nodes[i+1] if i+1 < len(nodes) else left
            new_level.append(sha256((left+right).encode()))
        return self.build_tree(new_level)

    def get_root(self): return self.root

# =========================================================
# PRINT AND LOG FUNCTION (flush after every write)
# =========================================================

def print_log(text, file):
    print(text)
    file.write(text + "\n")
    file.flush()  # <- flush immediately to disk

# =========================================================
# MENU-DRIVEN INTERFACE
# =========================================================

def interactive_menu():
    with open("output.txt", "w", encoding="utf-8") as fout:
        while True:
            print_log("\n==== Cryptographic Hash Functions ====", fout)
            print_log("1. SHA-256 Hash Generation", fout)
            print_log("2. Security Analysis Tests", fout)
            print_log("3. Merkle Tree Operations", fout)
            print_log("4. Quit", fout)

            choice = input("Enter choice: ").strip()
            fout.write(f"Choice entered: {choice}\n")
            fout.flush()

            if choice == "1":
                msg = input("Enter message: ")
                hash_val = sha256(msg.encode())
                print_log(f"SHA-256: {hash_val}", fout)

            elif choice == "2":
                msg = input("Enter test message: ")
                print_log(f"Avalanche Effect (%): {avalanche_effect(msg):.2f}", fout)
                print_log(f"Collision Simulation (found?): {collision_simulation()}", fout)
                perf = performance_test()
                print_log("Performance (ms):", fout)
                for size, t in perf.items():
                    print_log(f"  Size {size}: {t:.4f} ms", fout)
                comp = compare_with_md5_sha1(msg)
                print_log("MD5/SHA1/SHA256 Comparison:", fout)
                print_log(f"  MD5: {comp['MD5']}", fout)
                print_log(f"  SHA1: {comp['SHA1']}", fout)
                print_log(f"  SHA256: {comp['SHA256']}", fout)

            elif choice == "3":
                blocks = input("Enter data blocks (comma separated): ").split(",")
                blocks = [b.strip() for b in blocks if b.strip()]
                tree = MerkleTree(blocks)
                print_log(f"Merkle Root Hash: {tree.get_root()}", fout)

            elif choice == "4":
                print_log("Exiting...", fout)
                break

            else:
                print_log("Invalid choice", fout)

# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":
    interactive_menu()
    print("\nAll outputs have also been saved to 'output.txt'.")
