import socket
import json
import time
import psutil
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# Watcher Configuration
WATCHER_ID = "watcher3"
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 65432
CPU_THRESHOLD = 80    # CPU usage percentage threshold
MEMORY_THRESHOLD = 80 # Memory usage percentage threshold

# Load Watcher's Private Key (for signing alerts)
with open("watcher3_private.pem", "rb") as f:
    WATCHER_PRIVATE_KEY = serialization.load_pem_private_key(f.read(), password=None)

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
            # First, send the watcher identification as plain text.
            client.send(WATCHER_ID.encode())
            # Now, prepare and send the alert packet.
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
    while True:
        cpu, memory = check_system_usage()
        if cpu > CPU_THRESHOLD or memory > MEMORY_THRESHOLD:
            alert_message = f"High resource usage detected! CPU: {cpu}%, Memory: {memory}%"
            send_alert(alert_message)
        time.sleep(5)
