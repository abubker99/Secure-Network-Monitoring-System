import socket
import threading
import json
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
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

alerts_received = []

def decrypt_message(enc_data, key):
    nonce = bytes.fromhex(enc_data["nonce"])  # Convert nonce from hex to bytes
    ciphertext = bytes.fromhex(enc_data["ciphertext"])  # Convert ciphertext from hex to bytes
    tag = bytes.fromhex(enc_data["tag"])  # Convert tag from hex to bytes
    hmac_value = bytes.fromhex(enc_data["hmac"])  # Convert HMAC from hex to bytes
    
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
        return decrypted_message.decode()  # Return decrypted message as string
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
                break  # Assuming the message is smaller than 1024 bytes
            
        # Now decode the entire message properly
        data = data.decode()

        print("Received data:", data )  # Debugging line to see the actual content received
        
        enc_data = json.loads(data)  # Parse the JSON into a dictionary

        if "watcher_id" not in enc_data:  # Check if 'watcher_id' is in the received data
            print("Error: Missing watcher_id in the received data")
            return
        
        watcher_id = enc_data["watcher_id"]  # Retrieve the watcher_id
        if watcher_id in WATCHERS:
            key = WATCHERS[watcher_id]
            decrypted_message = decrypt_message(enc_data, key)
            if decrypted_message:
                print(f"Alert received from {watcher_id}: {decrypted_message}\n")
                alerts_received.append(time.time())
                
                recent_alerts = [t for t in alerts_received if time.time() - t < 16]
                if len(recent_alerts) >= ALERT_THRESHOLD:
                    print("ALERT: Possible DoS attack detected! 🚨🚨🚨\n")
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
