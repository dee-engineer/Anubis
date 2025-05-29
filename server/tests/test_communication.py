import pytest
from modules.communication import send_data, recv_data
import socket

def test_send_data(mocker):
    mock_socket = mocker.Mock()
    send_data(mock_socket, {"cmd": "test"})
    assert mock_socket.send.called

def test_recv_data(mocker):
    mock_socket = mocker.Mock()
    mock_socket.recv.return_value = b''
    assert recv_data(mock_socket) is None