import socket
import json
import time
import os
import psutil
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# Watcher Configuration
WATCHER_ID = "watcher3"
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 65432
CPU_THRESHOLD = 80   # CPU usage percentage threshold
MEMORY_THRESHOLD = 80  # Memory usage percentage threshold

# Load Watcher's Private Key (for signing alerts)
with open("watcher3_private.pem", "rb") as f:
    WATCHER_PRIVATE_KEY = serialization.load_pem_private_key(f.read(), password=None)

# Load Server's Public Key (for verifying integrity of the AES key package)
with open("server_public.pem", "rb") as f:
    SERVER_PUBLIC_KEY = serialization.load_pem_public_key(f.read())

AES_KEY = None  # AES key received from server (if needed for other purposes)

def request_aes_key():
    """Request and verify the AES key package from the server."""
    global AES_KEY
    print("[+] Requesting AES Key from Server...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect((SERVER_HOST, SERVER_PORT))
            # Step 1: Identify this watcher
            client.send(WATCHER_ID.encode())
            # Step 2: Receive the package containing the AES key and signature
            response = client.recv(2048).decode()
            package = json.loads(response)
            aes_key_hex = package.get("aes_key", "")
            signature_hex = package.get("signature", "")
            if not aes_key_hex or not signature_hex:
                print("[-] Invalid package received.")
                exit()
            aes_key = bytes.fromhex(aes_key_hex)
            signature = bytes.fromhex(signature_hex)
            # Step 3: Verify the AES key signature using the Server's Public Key.
            try:
                SERVER_PUBLIC_KEY.verify(
                    signature,
                    aes_key,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print("[✅] AES key integrity verified.")
                AES_KEY = aes_key  # Save AES key if needed
            except Exception as e:
                print("[-] AES key integrity verification failed:", e)
                exit()
    except Exception as e:
        print("[-] Error requesting AES key:", e)
        exit()

def sign_alert(message):
    """Sign the alert message using the Watcher's Private Key."""
    signature = WATCHER_PRIVATE_KEY.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature.hex()

def check_system_usage():
    """Check system resource usage."""
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_usage = psutil.virtual_memory().percent
    return cpu_usage, memory_usage

def send_alert(message):
    """Send an alert with a digital signature to the server."""
    print(f"[📡] Sending alert: {message}")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect((SERVER_HOST, SERVER_PORT))
            # Sign the alert message using the watcher's private key
            signature = sign_alert(message)
            alert_packet = {
                "watcher_id": WATCHER_ID,
                "alert": message,
                "signature": signature
            }
            client.send(json.dumps(alert_packet).encode())
            print("[✅] Alert sent successfully.")
    except Exception as e:
        print("[-] Connection error:", e)

if __name__ == "__main__":
    print("[🔍] Security Watcher is running...")
    request_aes_key()  # Request and verify the AES key package from the server

    while True:
        cpu, memory = check_system_usage()
        if cpu > CPU_THRESHOLD or memory > MEMORY_THRESHOLD:
            alert_message = f"High resource usage detected! CPU: {cpu}%, Memory: {memory}%"
            send_alert(alert_message)
        time.sleep(5)
