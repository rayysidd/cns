import json
import os
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode


class Peer:
    def __init__(self, identity, tpe_url, keyring_file):
        self.identity = identity
        self.tpe_url = tpe_url
        self.keyring_file = keyring_file

        # Load or generate RSA keys
        self._load_or_generate_keys()

        # Load or create keyring dict {identity: public_key}
        self.keyring = self._load_keyring()

    def _load_or_generate_keys(self):
        key_file = f'{self.identity}_private.pem'
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                self.private_key = RSA.import_key(f.read())
        else:
            self.private_key = RSA.generate(2048)
            with open(key_file, 'wb') as f:
                f.write(self.private_key.export_key('PEM'))
        self.public_key = self.private_key.publickey()

    def _load_keyring(self):
        if os.path.exists(self.keyring_file):
            with open(self.keyring_file, 'r') as f:
                return json.load(f)
        return {}

    def _save_keyring(self):
        with open(self.keyring_file, 'w') as f:
            json.dump(self.keyring, f)

    def register_with_tpe(self):
        pub_pem = self.public_key.export_key('PEM').decode()
        res = requests.post(f'{self.tpe_url}/register', json={'identity': self.identity, 'public_key': pub_pem})
        if res.ok:
            print(f'[{self.identity}] Registered with TPE')
        else:
            print(f'[{self.identity}] Registration failed: {res.text}')

    def get_public_key(self, identity):
        # Return from keyring or fetch from TPE if missing
        if identity == self.identity:
            return self.public_key

        if identity in self.keyring:
            return RSA.import_key(self.keyring[identity])

        # Fetch from TPE
        res = requests.get(f'{self.tpe_url}/get_key/{identity}')
        if not res.ok:
            print(f'[{self.identity}] Could not get public key for {identity}')
            return None

        pub_pem = res.json().get('public_key')
        self.keyring[identity] = pub_pem
        self._save_keyring()
        return RSA.import_key(pub_pem)

    def ssl1_handshake_send(self, receiver_identity):
        dh_secret = get_random_bytes(32)  # 256-bit secret

        # Sign dh_secret with own private key
        h = SHA256.new(dh_secret)
        signature = pkcs1_15.new(self.private_key).sign(h)

        # Encrypt dh_secret with receiver's public key
        receiver_pub = self.get_public_key(receiver_identity)
        if receiver_pub is None:
            print(f'[{self.identity}] Cannot get receiver public key')
            return None, None, None

        cipher_rsa = PKCS1_OAEP.new(receiver_pub)
        try:
            encrypted_dh_secret = cipher_rsa.encrypt(dh_secret)
        except ValueError as e:
            print(f'[{self.identity}] Encryption error: {str(e)}')
            return None, None, None

        return encrypted_dh_secret, dh_secret, signature

    def ssl1_handshake_receive(self, sender_identity, encrypted_dh_secret, signature):
        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        try:
            dh_secret = cipher_rsa.decrypt(encrypted_dh_secret)
        except ValueError:
            print(f'[{self.identity}] Incorrect decryption of handshake secret')
            return None

        sender_pub = self.get_public_key(sender_identity)
        if sender_pub is None:
            print(f'[{self.identity}] Could not get sender public key')
            return None

        # Verify signature over dh_secret
        h = SHA256.new(dh_secret)
        try:
            pkcs1_15.new(sender_pub).verify(h, signature)
            print(f'[{self.identity}] Signature from {sender_identity} verified')
        except (ValueError, TypeError):
            print(f'[{self.identity}] Signature verification failed')
            return None

        return dh_secret

    def derive_symmetric_key(self, dh_secret):
        # Derive AES key by hashing dh_secret
        h = SHA256.new(dh_secret)
        return h.digest()[:32]  # 256-bit AES key

    def encrypt_message(self, sym_key, plaintext):
        cipher = AES.new(sym_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

        msg = {
            'nonce': b64encode(cipher.nonce).decode(),
            'ciphertext': b64encode(ciphertext).decode(),
            'tag': b64encode(tag).decode()
        }
        return json.dumps(msg)

    def decrypt_message(self, sym_key, encrypted_json):
        try:
            msg = json.loads(encrypted_json)
            nonce = b64decode(msg['nonce'])
            ciphertext = b64decode(msg['ciphertext'])
            tag = b64decode(msg['tag'])
            cipher = AES.new(sym_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode()
        except (ValueError, KeyError):
            print(f'[{self.identity}] Decryption failed')
            return None

    def sign_message(self, msg):
        h = SHA256.new(msg.encode() if isinstance(msg, str) else msg)
        signature = pkcs1_15.new(self.private_key).sign(h)
        return b64encode(signature).decode()

    def verify_message_signature(self, sender_identity, msg, signature_b64):
        sender_pub = self.get_public_key(sender_identity)
        if sender_pub is None:
            print(f'[{self.identity}] Could not get sender public key')
            return False

        signature = b64decode(signature_b64)
        h = SHA256.new(msg.encode() if isinstance(msg, str) else msg)
        try:
            pkcs1_15.new(sender_pub).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False