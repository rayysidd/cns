# receiver.py
import socket
import json

def decrypt_rsa(private_key, ciphertext):
    d, n = private_key
    return ''.join(chr(pow(c, d, n)) for c in ciphertext)

def xor_decrypt(encrypted_message, key):
    key_repeated = (key * (len(encrypted_message) // len(key) + 1))[:len(encrypted_message)]
    return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(encrypted_message, key_repeated))

def register_identity(identity, public_key, third_party_ip):
    request = {
        "action": "register",
        "identity": identity,
        "public_key": public_key
    }
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((third_party_ip, 4444))
        s.send(json.dumps(request).encode())
        response = s.recv(1024)
        print("Registration response:", response.decode())

def listen_for_messages(private_key, receiver_ip):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((receiver_ip, 3333))
        server.listen()
        print(f"Receiver listening on {receiver_ip}:3333")
        
        while True:
            conn, addr = server.accept()
            with conn:
                data = conn.recv(65536).decode()
                if not data:
                    continue
                
                message = json.loads(data)
                encrypted_sym_key = message['encrypted_symmetric_key']
                encrypted_message = message['encrypted_message']
                
                symmetric_key = decrypt_rsa(private_key, encrypted_sym_key)
                print("Decrypted symmetric key:", symmetric_key)
                
                decrypted_msg = xor_decrypt(encrypted_message, symmetric_key)
                print("\nDecrypted message (first 500 chars):")
                print(decrypted_msg[:500])
                print("------ End of message snippet ------\n")
                # Stop listening after one message for this example
                break 
    print("Receiver shutting down.")


def main():
    identity = "bob"
    receiver_public_key = (4261, 32111) # Use your receiver public key here
    receiver_private_key = (24181, 32111) # Use your receiver private key here
    
    third_party_ip = 'localhost' # CHANGED: Third party server IP
    receiver_ip = 'localhost' # This machine's IP
    
    # Register receiver's public key with third party
    register_identity(identity, receiver_public_key, third_party_ip)
    
    # Start listening for messages
    listen_for_messages(receiver_private_key, receiver_ip)

if __name__ == "__main__":
    main()