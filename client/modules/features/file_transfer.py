import os
from ..communication import send_data, recv_data
from ..encryption import encrypt_data, decrypt_data

def download_file(sock, file_name_to_save):
    try:
        metadata = recv_data(sock)
        if not metadata or 'file_size_for_upload' not in metadata:
            send_data(sock, {"status": "error", "message": "Missing file metadata for client download"})
            return
        encrypted_size = metadata['file_size_for_upload']
        with open(file_name_to_save, 'wb') as f:
            received_encrypted_bytes = b''
            while len(received_encrypted_bytes) < encrypted_size:
                chunk = sock.recv(min(4096, encrypted_size - len(received_encrypted_bytes)))
                if not chunk:
                    send_data(sock, {"status": "error", "message": "Connection lost during client download"})
                    return
                received_encrypted_bytes += chunk
            decrypted_data = decrypt_data(received_encrypted_bytes)
            if decrypted_data:
                f.write(decrypted_data.encode('utf-8') if isinstance(decrypted_data, str) else decrypted_data)
                send_data(sock, {"status": "success", "message": f"File {file_name_to_save} downloaded."})
    except Exception as e:
        print(f"[!] Error in client download_file: {e}")
        send_data(sock, {"status": "error", "message": f"Client download_file exception: {str(e)}"})

def upload_file(sock, file_name_to_send):
    try:
        if not os.path.exists(file_name_to_send):
            send_data(sock, {"status": "error", "message": f"File {file_name_to_send} not found on client."})
            return
        with open(file_name_to_send, 'rb') as f:
            data = f.read()
        encrypted_data = encrypt_data(data)
        if encrypted_data:
            send_data(sock, {'file_size_for_download': len(encrypted_data)})
            sock.sendall(encrypted_data)
    except Exception as e:
        print(f"[!] Error in client upload_file: {e}")
        send_data(sock, {"status": "error", "message": f"Client upload_file exception: {str(e)}"})