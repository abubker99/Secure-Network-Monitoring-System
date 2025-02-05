import socket
import threading
import json
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
import os

# Monitor configuration
HOST = "127.0.0.1"
PORT = 65432
ALERT_THRESHOLD = 3  # Number of alerts in short time to trigger admin alert
ALERT_TIMEFRAME = 10  # Seconds

# Simulated authentication - predefined watcher keys
WATCHERS = {
    "watcher1": b"hewivls824l12493",
    "watcher2": os.urandom(16),
}

alerts_received = {}

def decrypt_message(enc_data, key):
    nonce = bytes.fromhex(enc_data["nonce"])
    ciphertext = bytes.fromhex(enc_data["ciphertext"])
    tag = bytes.fromhex(enc_data["tag"])
    hmac_value = bytes.fromhex(enc_data["hmac"])
    
    # Verify HMAC integrity
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(ciphertext)
    try:
        h.verify(hmac_value)  # This will raise an exception if verification fails
    except Exception as e:
        print("HMAC verification failed:", e)
        return None
    
    # Decrypt the message using AES-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    try:
        decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_message.decode()
    except Exception as e:
        print("Decryption failed:", e)
        return None

def handle_watcher(conn, addr):
    global alerts_received
    print(f"New connection from {addr}\n")
    try:
        data = b""
        while True:
            part = conn.recv(1024)
            data += part
            if len(part) < 1024:
                break
        
        data = data.decode()
        print("Received data:", data)
        
        enc_data = json.loads(data)
        if "watcher_id" not in enc_data:
            print("Error: Missing watcher_id in the received data")
            return
        
        watcher_id = enc_data["watcher_id"]
        if watcher_id in WATCHERS:
            key = WATCHERS[watcher_id]
            decrypted_message = decrypt_message(enc_data, key)
            if decrypted_message:
                print(f"Alert received from {watcher_id}: {decrypted_message}\n")
                alerts_received.setdefault(watcher_id, []).append(time.time())
                
                # Remove old alerts (outside the timeframe)
                for w in list(alerts_received.keys()):
                    alerts_received[w] = [t for t in alerts_received[w] if time.time() - t < ALERT_TIMEFRAME]
                
                # Count unique watchers who sent alerts recently
                active_watchers = sum(1 for times in alerts_received.values() if times)
                
                if active_watchers >= ALERT_THRESHOLD:
                    print("\U0001F6A8 ALERT: Possible Distributed DoS (DDoS) Attack Detected! \U0001F6A8")
                    alerts_received.clear()
        else:
            print("Unauthorized watcher.")
    except Exception as e:
        print("Error handling watcher:", e)
    finally:
        conn.close()

def monitor_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((HOST, PORT))
        server.listen()
        print("Security monitor is running...\n")
        while True:
            conn, addr = server.accept()
            print(f"Connection established with {addr}\n")
            threading.Thread(target=handle_watcher, args=(conn, addr)).start()

if __name__ == "__main__":
    monitor_server()
