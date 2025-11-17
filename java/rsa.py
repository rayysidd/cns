from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# -----------------------------
# Step 1: Generate receiver RSA keys
# -----------------------------
receiver_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
receiver_public_key = receiver_key.public_key()
key=rsa.generate_private_key()
# -----------------------------
# Step 2: Simple XOR for symmetric encryption
# -----------------------------
def xor_encrypt(message, key):
    return [ord(ch) ^ key for ch in message]

def xor_decrypt(encrypted, key):
    return "".join(chr(c ^ key) for c in encrypted)

# -----------------------------
# Step 3: Hybrid Encryption Demo
# -----------------------------
message = "HELLO"
symmetric_key = 42  # simple number for XOR

print("Original message:", message)

# Encrypt message using XOR
encrypted_message = xor_encrypt(message, symmetric_key)
print("Encrypted message (XOR):", encrypted_message)

# Encrypt symmetric key using receiver's public RSA key
sym_key_bytes = symmetric_key.to_bytes(2, byteorder='big')
encrypted_sym_key = receiver_public_key.encrypt(
    sym_key_bytes,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("Encrypted symmetric key (RSA):", encrypted_sym_key.hex())

# Decrypt symmetric key using receiver's private RSA key
decrypted_sym_key_bytes = receiver_key.decrypt(
    encrypted_sym_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
decrypted_sym_key = int.from_bytes(decrypted_sym_key_bytes, byteorder='big')
print("Decrypted symmetric key:", decrypted_sym_key)

# Decrypt message using XOR with decrypted symmetric key
decrypted_message = xor_decrypt(encrypted_message, decrypted_sym_key)
print("Decrypted message:", decrypted_message)
