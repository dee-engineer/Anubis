import json
import base64
import os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

# Load DH parameters from PEM file in the project root
DH_PARAMS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'dh_params.pem')
with open(DH_PARAMS_PATH, 'rb') as f:
    parameters = serialization.load_pem_parameters(f.read(), backend=default_backend())

def initialize_encryption(client_socket):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    client_public_key_bytes = client_socket.recv(4096)
    client_public_key = serialization.load_pem_public_key(client_public_key_bytes, backend=default_backend())
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.send(public_key_bytes)
    shared_key = private_key.exchange(client_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake',
        backend=default_backend()
    ).derive(shared_key)
    return Fernet(base64.urlsafe_b64encode(derived_key))