# Third Party
import socket
import threading
import json

# Dictionary to store registered public keys
public_keys = {}

def handle_client(conn):
    try:
        data = conn.recv(2048).decode()
        if not data:
            conn.close()
            return

        request = json.loads(data)
        action = request.get("action")
        identity = request.get("identity")

        if action == "register":
            public_key = request.get("public_key")
            if identity and public_key:
                public_keys[identity] = public_key
                response = {"status": "success", "message": f"{identity} registered successfully."}
            else:
                response = {"status": "error", "message": "Invalid registration data."}
        elif action == "get_key":
            key = public_keys.get(identity)
            if key:
                response = {"status": "success", "public_key": key}
            else:
                response = {"status": "error", "message": f"Public key for {identity} not found."}
        else:
            response = {"status": "error", "message": "Invalid action."}
        
        conn.send(json.dumps(response).encode())
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        conn.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 4444)) # Listen on all network interfaces, port 4444
    server.listen(5)
    print("Third Party Server listening on port 4444...")
    
    while True:
        conn, addr = server.accept()
        print(f"Connection from {addr}")
        client_thread = threading.Thread(target=handle_client, args=(conn,))
        client_thread.start()

if __name__ == "__main__":
    main()