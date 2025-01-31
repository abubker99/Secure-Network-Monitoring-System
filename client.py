import socket
import json
import psutil
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
import os

# Watcher Configuration

CPU_THRESHOLD = 80  # CPU usage percentage threshold
MEMORY_THRESHOLD = 80  # Memory usage percentage threshold
WATCHER_ID = "watcher1"  # Change to "watcher2" if needed
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 65432
SECRET_KEY = b"hewivls824l12493"  # Must be 16 bytes

def encrypt_message(message, key):
    nonce = os.urandom(12)  # 12-byte nonce for AES-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

    # Compute HMAC for integrity
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(ciphertext)
    hmac_value = h.finalize()

    return {
        "watcher_id": WATCHER_ID,
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": encryptor.tag.hex(),
        "hmac": hmac_value.hex()
    }

def check_system_usage():
    """Check CPU and memory usage."""
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_usage = psutil.virtual_memory().percent
    return cpu_usage, memory_usage

def send_alert(message):
    """Encrypt and send an alert to the security monitor."""
    print(f"Connecting to {SERVER_HOST}:{SERVER_PORT}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        try:
            client.connect((SERVER_HOST, SERVER_PORT))
            print("Connected to the server.")

            encrypted_message = encrypt_message(message, SECRET_KEY)
            # Ensure that the message is properly serialized into JSON and sent as bytes
            client.send(json.dumps(encrypted_message).encode())
            print("✅ Alert sent successfully.")

        except Exception as e:
            print(f"❌ Connection error: {e}")

            
if __name__ == "__main__":
    print("Security Watcher is running...")
    while True:

        cpu, memory = check_system_usage()
        if cpu > CPU_THRESHOLD or memory > MEMORY_THRESHOLD:
            alert_message = f"High resource usage detected! CPU: {cpu}%, Memory: {memory}%"
            send_alert(alert_message)
        time.sleep(5)  # Check system usage every 5 seconds
