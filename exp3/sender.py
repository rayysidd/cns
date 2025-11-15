# sender.py
import socket
import json
import random
import string

# Change these IPs as per your network
third_party_ip = 'localhost' # CHANGED: IP where third party server runs
receiver_ip = 'localhost' # IP where receiver service runs

def encrypt_rsa(public_key, plaintext):
    e, n = public_key
    return [pow(ord(c), e, n) for c in plaintext]

def xor_encrypt(message, key):
    key_repeated = (key * (len(message) // len(key) + 1))[:len(message)]
    return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(message, key_repeated))

def register_identity(identity, public_key):
    request = {
        "action": "register",
        "identity": identity,
        "public_key": public_key
    }
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((third_party_ip, 4444)) # connect to third party server IP
        s.send(json.dumps(request).encode())
        response = s.recv(1024)
        print("Registration response:", response.decode())

def get_public_key(identity):
    request = {
        "action": "get_key",
        "identity": identity
    }
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((third_party_ip, 4444)) # connect to third party server IP
        s.send(json.dumps(request).encode())
        response = s.recv(2048).decode()
        data = json.loads(response)
        if data['status'] == 'success':
            return tuple(data['public_key'])
        else:
            print("Public key not found for", identity)
            return None

def send_message(encrypted_symmetric_key, encrypted_message):
    data = {
        "encrypted_symmetric_key": encrypted_symmetric_key,
        "encrypted_message": encrypted_message
    }
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((receiver_ip, 3333)) # connect to receiver service IP
        s.send(json.dumps(data).encode())
        print("Message sent to receiver")

def generate_symmetric_key(length=16):
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for i in range(length))

def main():
    identity = "alice"
    public_key = (24181, 32111) # sender's public key
    
    register_identity(identity, public_key)
    
    receiver_identity = "bob"
    receiver_public_key = get_public_key(receiver_identity)
    
    if not receiver_public_key:
        print("Could not get receiver's public key. Is receiver.py running?")
        return
    
    symmetric_key = generate_symmetric_key()
    print("Symmetric key:", symmetric_key)
    
    encrypted_sym_key = encrypt_rsa(receiver_public_key, symmetric_key)
    print("Encrypted symmetric key (first 10 ints):", encrypted_sym_key[:10])
    
    large_message = "lorem epsom" * 500 # large message > 10K letters
    encrypted_message = xor_encrypt(large_message, symmetric_key)
    
    send_message(encrypted_sym_key, encrypted_message)

if __name__ == "__main__":
    main()