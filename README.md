# Anubis - Modular Remote Access Tool (RAT)

**Disclaimer**: Anubis is intended strictly for educational purposes and ethical security research. Unauthorized use on systems without explicit permission is illegal and unethical.

Anubis is a modular Remote Access Tool (RAT) with a client-server architecture. It enables remote system control and monitoring with robust encryption and authentication. A React-based GUI is available for streamlined management.

## Features

- System Information Gathering
- File Upload/Download with Encryption
- Screenshot & Webcam Capture
- Keylogging
- Process Management
- Clipboard Monitoring
- File Encryption/Decryption
- Persistence Across Reboots
- Screen Locking
- Custom Message Display
- URL Opening
- Network Information Retrieval
- Command Queue for Offline Clients

## Security

- Diffie-Hellman key exchange for secure communications
- Authentication with a pre-shared secret
- Rate limiting and exponential backoff to prevent abuse

## Project Setup


### 1. Clone the Repository
```bash
git clone https://github.com/dee-engineer/Anubis.git
cd Anubis

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

pip install -r client/requirements.txt
pip install -r server/requirements.txt

```

# Start project

```bash
python server/server.py # For GUI: python server/server_gui.py
python client/client.py
```
