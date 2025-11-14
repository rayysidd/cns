from peer_base import Peer
import os
import sys
import re

TPE_URL = 'http://127.0.0.1:5000'
PEER_NAMES = ['Alice', 'Bob', 'Charlie', 'David']
KEYRING_PATH = lambda name: f'{name.lower()}_keyring.json'

peers = {}
shared_keys = {}

def setup_peers():
    for name in PEER_NAMES:
        peer = Peer(name, TPE_URL, KEYRING_PATH(name))
        peer.register_with_tpe()
        peers[name] = peer
    print("\nAll peers registered with TPE.")

def ensure_handshake(sender: Peer, receiver: Peer):
    pair = (sender.identity, receiver.identity)
    if pair not in shared_keys:
        try:
            encrypted_dh_secret, dh_secret_sender, signature = sender.ssl1_handshake_send(receiver.identity)
            dh_secret_receiver = receiver.ssl1_handshake_receive(sender.identity, encrypted_dh_secret, signature)
            sym_key_sender = sender.derive_symmetric_key(dh_secret_sender)
            sym_key_receiver = receiver.derive_symmetric_key(dh_secret_receiver)
            shared_keys[pair] = (sym_key_sender, sym_key_receiver)
            print(f"[Handshake] Shared key established between {sender.identity} and {receiver.identity}")
        except Exception as e:
            print(f"Handshake failed: {e}")
            return None, None
    return shared_keys[pair]

OUTPUT_LOG = 'output.txt'

def log_communication(sender_name, receiver_name, message, encrypted_msg, signature, valid_sig, decrypted_msg):
    with open(OUTPUT_LOG, 'a', encoding='utf-8') as f:
        f.write(f"Sender: {sender_name}\n")
        f.write(f"Receiver: {receiver_name}\n")
        f.write(f"Plain Text: {message}\n")
        f.write(f"Encrypted Message: {encrypted_msg}\n")
        f.write(f"Digital Signature: {signature}\n")
        f.write(f"Signature Verified: {valid_sig}\n")
        f.write(f"Decrypted Text: {decrypted_msg if valid_sig else 'N/A'}\n")
        f.write('-' * 50 + '\n')

def send_secure_message(sender_name, receiver_name, message):
    sender = peers.get(sender_name)
    receiver = peers.get(receiver_name)

    if not sender or not receiver:
        print(f"Invalid sender or receiver: {sender_name}, {receiver_name}")
        return

    sym_key_sender, sym_key_receiver = ensure_handshake(sender, receiver)
    if not sym_key_sender:
        print(f"[Error] Could not establish shared key between {sender_name} and {receiver_name}")
        return

    encrypted_msg = sender.encrypt_message(sym_key_sender, message)
    signature = sender.sign_message(encrypted_msg)

    print(f"\n[{sender_name} ➡ {receiver_name}] Message sent and logged.")

    valid_sig = receiver.verify_message_signature(sender_name, encrypted_msg, signature)
    decrypted_msg = receiver.decrypt_message(sym_key_receiver, encrypted_msg) if valid_sig else None

    log_communication(sender_name, receiver_name, message, encrypted_msg, signature, valid_sig, decrypted_msg)


def parse_messages_file(filename):
    """
    Parse input file to extract list of (sender, receiver, message) tuples.

    Expected format (repeated blocks):
    Sender: Alice
    Receiver: Bob
    Message: <message text>
    (blank line between blocks)
    """
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()

    # Split by blank lines
    blocks = [blk.strip() for blk in content.split('\n\n') if blk.strip()]

    messages = []
    for block in blocks:
        sender_match = re.search(r'Sender:\s*(.+)', block)
        receiver_match = re.search(r'Receiver:\s*(.+)', block)
        message_match = re.search(r'Message:\s*(.+)', block, re.DOTALL)

        if not sender_match or not receiver_match or not message_match:
            print(f"Skipping invalid block:\n{block}\n")
            continue

        sender = sender_match.group(1).strip()
        receiver = receiver_match.group(1).strip()
        message = message_match.group(1).strip()
        messages.append( (sender, receiver, message) )

    return messages

def main():
    setup_peers()

    if len(sys.argv) < 2:
        print("Usage: python simulate_communication.py messages.txt")
        sys.exit(1)

    filename = sys.argv[1]

    try:
        messages = parse_messages_file(filename)
    except Exception as e:
        print(f"Failed to parse file {filename}: {e}")
        sys.exit(1)

    for sender_name, receiver_name, message in messages:
        print(f"\n--- Sending message from {sender_name} to {receiver_name} ---")
        send_secure_message(sender_name, receiver_name, message)

if __name__ == '__main__':
    main()