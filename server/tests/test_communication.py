import pytest
import json

from server.modules.communication import send_data

@pytest.fixture
def mock_client_info_map(mocker):
    # Patch the global client_info_map in the communication module
    return mocker.patch('server.modules.communication.client_info_map', {})

@pytest.fixture
def mock_logging(mocker):
    return mocker.patch('server.modules.communication.logging')

class DummyCipher:
    def __init__(self):
        self.last_data = None
    def encrypt(self, data):
        self.last_data = data
        return b'encrypted_data'

def test_send_data_successful_encryption_and_send(mocker, mock_client_info_map, mock_logging):
    target_socket = mocker.Mock()
    cipher = mocker.Mock()
    cipher.encrypt.return_value = b'encrypted_data'
    mock_client_info_map.update({
        '127.0.0.1:1234': {'socket': target_socket, 'cipher': cipher}
    })
    command_dict = {'cmd': 'test'}
    send_data(target_socket, command_dict)
    cipher.encrypt.assert_called_once_with(json.dumps(command_dict).encode('utf-8'))
    target_socket.send.assert_called_once_with(b'encrypted_data')
    mock_logging.error.assert_not_called()

def test_send_data_logs_error_when_no_cipher(mocker, mock_client_info_map, mock_logging):
    target_socket = mocker.Mock()
    mock_client_info_map.update({
        '127.0.0.1:1234': {'socket': target_socket}
    })
    command_dict = {'cmd': 'test'}
    send_data(target_socket, command_dict)
    mock_logging.error.assert_called_once()
    assert "No cipher found for client" in mock_logging.error.call_args[0][0]
    target_socket.send.assert_not_called()

def test_send_data_finds_client_by_socket(mocker, mock_client_info_map, mock_logging):
    target_socket = mocker.Mock()
    cipher = DummyCipher()
    mock_client_info_map.update({
        '10.0.0.1:5555': {'socket': mocker.Mock(), 'cipher': DummyCipher()},
        '192.168.1.2:8888': {'socket': target_socket, 'cipher': cipher}
    })
    command_dict = {'cmd': 'findme'}
    send_data(target_socket, command_dict)
    assert cipher.last_data == json.dumps(command_dict).encode('utf-8')

def test_send_data_exception_triggers_logging_and_disconnection(mocker, mock_client_info_map, mock_logging):
    target_socket = mocker.Mock()
    cipher = mocker.Mock()
    cipher.encrypt.return_value = b'encrypted_data'
    target_socket.send.side_effect = RuntimeError("send failed")
    mock_client_info_map.update({
        '127.0.0.1:1234': {'socket': target_socket, 'cipher': cipher}
    })
    mock_handle_disc = mocker.patch('server.modules.communication.handle_client_disconnection')
    command_dict = {'cmd': 'fail_send'}
    send_data(target_socket, command_dict)
    mock_logging.error.assert_any_call(
        pytest.helpers.any_string_containing("Error sending data"),
        extra={'session_id': 'N/A'}
    )
    mock_handle_disc.assert_called_once_with(target_socket)

def test_send_data_socket_not_in_client_info_map(mocker, mock_client_info_map, mock_logging):
    target_socket = mocker.Mock()
    # client_info_map is empty, so socket is not present
    command_dict = {'cmd': 'notfound'}
    send_data(target_socket, command_dict)
    mock_logging.error.assert_called_once()
    assert "No cipher found for client" in mock_logging.error.call_args[0][0]
    target_socket.send.assert_not_called()

def test_send_data_encryption_failure(mocker, mock_client_info_map, mock_logging):
    target_socket = mocker.Mock()
    cipher = mocker.Mock()
    cipher.encrypt.side_effect = ValueError("encryption error")
    mock_client_info_map.update({
        '127.0.0.1:1234': {'socket': target_socket, 'cipher': cipher}
    })
    mock_handle_disc = mocker.patch('server.modules.communication.handle_client_disconnection')
    command_dict = {'cmd': 'fail_encrypt'}
    send_data(target_socket, command_dict)
    mock_logging.error.assert_any_call(
        pytest.helpers.any_string_containing("Error sending data"),
        extra={'session_id': 'N/A'}
    )
    mock_handle_disc.assert_called_once_with(target_socket)