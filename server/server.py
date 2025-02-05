import socket
import json
import os
import threading
import time
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# Server Configuration
HOST = "127.0.0.1"
PORT = 65432
ALERT_THRESHOLD = 3   # Number of alerts to trigger a DDoS warning
ALERT_TIMEFRAME = 10  # Time window for detecting DDoS

alerts_received = {}

# Load Server's Private Key (not used for key exchange anymore)
with open("server_private.pem", "rb") as f:
    SERVER_PRIVATE_KEY = serialization.load_pem_private_key(f.read(), password=None)

# Load Watcher Public Keys
with open("watcher1_public.pem", "rb") as f:
    WATCHER1_PUBLIC_KEY = serialization.load_pem_public_key(f.read())
with open("watcher2_public.pem", "rb") as f:
    WATCHER2_PUBLIC_KEY = serialization.load_pem_public_key(f.read())
with open("watcher3_public.pem", "rb") as f:
    WATCHER3_PUBLIC_KEY = serialization.load_pem_public_key(f.read())

def handle_watcher(conn):
    global alerts_received
    print("[+] New connection from a watcher.")

    try:
        # Step 1: Receive plain-text watcher identification.
        watcher_id = conn.recv(1024).decode().strip()
        print(f"[+] Received watcher identification: {watcher_id}")
        if watcher_id not in ["watcher1", "watcher2", "watcher3"]:
            print("[-] Unknown watcher.")
            conn.close()
            return

        print(f"[+] Connection established with {watcher_id}. Waiting for alerts...")

        # Now continuously receive alerts from the watcher.
        while True:
            data = conn.recv(4096)
            if not data:
                break

            alert_data = json.loads(data.decode())
            # Expected alert_data format:
            #   {"watcher_id": "<id>", "alert": "<alert message>", "signature": "<signature>"}
            alert_message = alert_data.get("alert", "")
            alert_signature = bytes.fromhex(alert_data.get("signature", ""))
            sender_id = alert_data.get("watcher_id", "unknown")

            # Determine the correct public key for the sender.
            if sender_id == "watcher1":
                watcher_pub = WATCHER1_PUBLIC_KEY
            elif sender_id == "watcher2":
                watcher_pub = WATCHER2_PUBLIC_KEY
            elif sender_id == "watcher3":
                watcher_pub = WATCHER3_PUBLIC_KEY
            else:
                print("[-] Unknown sender for alert.")
                continue

            # Verify the alert's signature using the sender's public key.
            try:
                watcher_pub.verify(
                    alert_signature,
                    alert_message.encode(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print(f"[ALERT] Verified alert from {sender_id}: {alert_message}")
            except Exception as e:
                print(f"[-] Alert signature verification failed from {sender_id}: {e}")

            # Track alerts for potential DDoS detection.
            alerts_received.setdefault(sender_id, []).append(time.time())
            # Remove alerts older than ALERT_TIMEFRAME.
            for key in list(alerts_received.keys()):
                alerts_received[key] = [t for t in alerts_received[key] if time.time() - t < ALERT_TIMEFRAME]
            active_alerts = sum(1 for times in alerts_received.values() if times)
            if active_alerts >= ALERT_THRESHOLD:
                print("🚨 ALERT: Possible Distributed Denial-of-Service (DDoS) Attack Detected! 🚨")
                alerts_received.clear()

    except Exception as e:
        print("[-] Error handling watcher:", e)
    finally:
        conn.close()

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((HOST, PORT))
        server.listen()
        print("[+] Security Monitor Running...")
        while True:
            conn, _ = server.accept()
            threading.Thread(target=handle_watcher, args=(conn,)).start()

if __name__ == "__main__":
    start_server()
