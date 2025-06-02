# modules/authentication.py

# REMOVE THIS LINE: from .communication import send_data

from .logging_config import logging

# Add send_response_func as an argument
def authenticate_client(client_socket, cipher, send_response_func): # <--- Added send_response_func
    """
    Authenticates the client using the provided Fernet cipher for encryption/decryption.
    send_response_func: A callable that takes (target_socket, command_dict) and sends data.
    """
    try:
        # No authentication, always succeed
        send_response_func(client_socket, {"status": "auth_success"})
        logging.info(f"Authentication successful for client {client_socket.getpeername()}", extra={'session_id': 'N/A'})
        return True
    except Exception as e:
        logging.error(f"Authentication error: {e}", extra={'session_id': 'N/A'})
        return False