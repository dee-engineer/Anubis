# server/modules/state.py

# Shared global state for server modules
client_info_map = {}
targets = []
ips = []
next_session_id = 0
stop_threads = False
server_socket = None
