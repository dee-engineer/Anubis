import json
import base64
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

def initialize_encryption(client_socket):
    private_key, public_key = parameters.generate_private_key(), parameters.generate_private_key().public_key()
    client_public_key_bytes = client_socket.recv(4096)
    client_public_key = serialization.load_pem_public_key(client_public_key_bytes, backend=default_backend())
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKey
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

def encrypt_data(data):
    # Note: Per-client cipher is stored in client_info_map
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
    try:
        decrypted = cipher.decrypt(encrypted_data)
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"[-] Decryption error: {e}")
        return None