# Anubis - Modular Remote Access Tool (RAT)

Anubis is a modular Remote Access Tool (RAT) with a client-server architecture. It provides powerful capabilities for remote system control and monitoring, enhanced by strong encryption and authentication. A React-based GUI is also available for easy management.

---

## 🚀 Features

- 🔍 System Information Gathering
- 🔐 File Upload/Download with Encryption
- 📸 Screenshot & Webcam Capture
- 🧠 Keylogging
- 🧩 Process Management
- 📋 Clipboard Monitoring
- 🗃️ File Encryption/Decryption
- 🔁 Persistence Across Reboots
- 🔒 Screen Locking
- 💬 Custom Message Display
- 🌐 URL Opening
- 🌐 Network Information Retrieval
- 🧾 Command Queue for Offline Clients

---

## 🔐 Security

- **Diffie-Hellman key exchange** for secure communications
- **Authentication** with a pre-shared secret
- **Rate limiting** and **exponential backoff** to prevent abuse

---

## ⚙️ Project Setup

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
