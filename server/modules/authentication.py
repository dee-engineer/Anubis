from .encryption import encrypt_data, decrypt_data
from .logging_config import logging

def authenticate_client(client_socket):
    try:
        with open('config/auth_secret.txt', 'r') as f:
            auth_secret = f.read().strip()
        received_secret = decrypt_data(client_socket.recv(4096))
        if received_secret == auth_secret:
            send_data(client_socket, {"status": "auth_success"})
            return True
        else:
            send_data(client_socket, {"status": "auth_failed"})
            logging.error(f"Authentication failed for client", extra={'session_id': 'N/A'})
            return False
    except Exception as e:
        logging.error(f"Authentication error: {e}", extra={'session_id': 'N/A'})
        return False