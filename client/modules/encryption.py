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

# Global cipher
cipher = None

def initialize_encryption(sock):
    global cipher
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sock.send(public_key_bytes)
    server_public_key_bytes = sock.recv(4096)
    server_public_key = serialization.load_pem_public_key(server_public_key_bytes, backend=default_backend())
    shared_key = private_key.exchange(server_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake',
        backend=default_backend()
    ).derive(shared_key)
    cipher = Fernet(base64.urlsafe_b64encode(derived_key))
    return cipher

def encrypt_data(data):
    global cipher
    if not cipher:
        print("[-] Encryption unavailable. Data will not be encrypted.")
        return data if isinstance(data, bytes) else data.encode('utf-8')
    try:
        if isinstance(data, dict):
            data = json.dumps(data)
        if isinstance(data, str):
            data = data.encode('utf-8')
        return cipher.encrypt(data)
    except Exception as e:
        print(f"[-] Encryption error: {e}")
        return None

def decrypt_data(encrypted_data):
    global cipher
    if not cipher:
        print("[-] Decryption unavailable. Assuming data is unencrypted.")
        return encrypted_data.decode('utf-8', errors='ignore') if isinstance(encrypted_data, bytes) else encrypted_data
    try:
        decrypted = cipher.decrypt(encrypted_data)
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"[-] Decryption error: {e}")
        return None