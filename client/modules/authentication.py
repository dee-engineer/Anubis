from .encryption import encrypt_data, decrypt_data, cipher
import json

def authenticate_with_server(sock):
    try:
        with open('config/auth_secret.txt', 'r') as f:
            auth_secret = f.read().strip()
        sock.send(encrypt_data(auth_secret))
        response = recv_data(sock)
        if response and response.get("status") == "auth_success":
            print("[+] Authentication successful.")
            return True
        else:
            print("[-] Authentication failed.")
            return False
    except Exception as e:
        print(f"[-] Authentication error: {e}")
        return False

def recv_data(sock):
    try:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        decrypted_data = decrypt_data(chunk)
        if decrypted_data:
            return json.loads(decrypted_data)
        return None
    except Exception as e:
        print(f"[-] Recv_data error: {e}")
        return None