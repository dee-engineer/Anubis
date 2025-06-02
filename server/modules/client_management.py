from .logging_config import logging
from pystyle import Colors, Box
from .state import client_info_map, targets, ips

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
        logging.info(f"Client {client_info_map[disconnected_ip_str].get('user', 'Unknown')}@{disconnected_ip_str} (Session {session_id_to_remove}) disconnected.", extra={'session_id': session_id_to_remove})
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

def list_sessions():
    global client_info_map
    if not client_info_map:
        print(f"\n{Colors.yellow}[-] No active client connections.{Colors.reset}")
        return
    header = " ID | USERNAME@HOSTNAME        | MAC ADDRESS         | IP ADDRESS         | CONNECTED SINCE"
    print(f"\n{Colors.light_blue}{Box.Lines(header)}{Colors.reset}")
    print(f"{Colors.light_blue}{'-' * len(header)}{Colors.reset}")
    sorted_clients = sorted(client_info_map.values(), key=lambda x: x['session_id'])
    for info in sorted_clients:
        session_id_str = f"{info['session_id']:<3}"
        user_host = f"{info.get('user', 'N/A')}@{info.get('hostname', 'N/A')}"
        user_host_str = f"{user_host[:24]:<26}" if len(user_host) > 24 else f"{user_host:<26}"
        mac_str = f"{info.get('mac', 'N/A'):<17}"
        ip_str = f"{info.get('ip_str', 'N/A'):<19}"
        connected_at_str = f"{info.get('connected_at', 'N/A')}"
        print(f"{Colors.cyan}{session_id_str}{Colors.reset} | {Colors.green}{user_host_str}{Colors.reset}| {Colors.yellow}{mac_str}{Colors.reset}| {Colors.purple}{ip_str}{Colors.reset}| {Colors.cyan}{connected_at_str}{Colors.reset}")