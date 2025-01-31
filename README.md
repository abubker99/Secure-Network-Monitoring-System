Secure Network Monitoring System
This project is a secure network monitoring system where watchers monitor CPU and memory usage on different hosts. If the usage exceeds a set threshold, the watcher sends an encrypted alert to the security monitor. The monitor ensures message integrity and alerts the administrator in case of suspicious activity like Denial of Service (DoS) attacks, based on alerts received from multiple watchers in a short time.
Features
- **Encrypted Communication**: Watchers encrypt alert messages before sending them to the security monitor.
- **Message Integrity**: HMAC is used to ensure that messages are not tampered with during transmission.
- **Alert Handling**: The monitor verifies messages, decrypts them, and detects potential Denial of Service (DoS) attacks based on the number of alerts in a short timeframe.
- **Threshold-Based Monitoring**: The system monitors CPU and memory usage, triggering alerts when usage exceeds specified thresholds.
Requirements
1. Python 3.x
2. Required Python packages:
   ```bash
   pip install cryptography psutil
   ```
Project Structure
- `client.py`: The security watcher that monitors CPU and memory usage. If thresholds are exceeded, it sends encrypted alerts to the server.
- `server.py`: The security monitor that listens for incoming alerts, decrypts messages, verifies integrity, and detects potential DoS attacks.
Setup
1. Clone the repository:
   ```bash
   git clone <repository_url>
   cd <project_directory>
   ```
2. Install necessary Python packages:
   ```bash
   pip install cryptography psutil
   ```
3. Run the security monitor (server):
   ```bash
   python server.py
   ```
4. Run the watcher (client):
   ```bash
   python client.py
   ```
How it Works
1. **Watchers**: Each watcher monitors the CPU and memory usage of the local machine.
   - If usage exceeds the threshold (80% for both CPU and memory), the watcher encrypts an alert message and sends it to the server.
   - The alert includes the watcher ID, encrypted message data (using AES-GCM), and a HMAC for integrity verification.
2. **Server (Monitor)**: The server listens for incoming messages, decrypts them using the predefined secret key, and verifies the integrity using HMAC.
   - If multiple alerts are received within a short time period (indicating a possible DoS attack), the server prints an alert and clears the recent alerts.
How to Test
1. Start the server by running `python server.py`.
2. Start the client by running `python client.py`.
3. Watch the server console for alerts when the client detects high CPU or memory usage.
