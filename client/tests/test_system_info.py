import pytest
from modules.features.system_info import get_initial_info, gather_detailed_sysinfo
import socket
import platform
import uuid

def test_get_initial_info():
    hostname = socket.gethostname()
    mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0, 8 * 6, 8)][::-1])
    username = os.environ.get("USER") or os.environ.get("USERNAME") or "Unknown"
    assert get_initial_info() == f"{hostname},{mac_address},{username}"

def test_gather_detailed_sysinfo(mocker):
    mock_sock = mocker.Mock()
    gather_detailed_sysinfo(mock_sock)
    assert mock_sock.send.called