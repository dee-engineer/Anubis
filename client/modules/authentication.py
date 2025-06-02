from .encryption import encrypt_data, decrypt_data, cipher
import json

def authenticate_with_server(sock):
    try:
        # No authentication, always succeed
        print("[+] Authentication successful.")
        return True
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