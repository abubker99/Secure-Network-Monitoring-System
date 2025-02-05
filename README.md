<h1>Secure Network Monitoring System</h1>

<p>This project is a secure network monitoring system composed of a centralized security monitor and multiple security watchers. The watchers monitor CPU and memory usage on the networked hosts. If the usage exceeds a specified threshold, the watchers send encrypted alerts to the security monitor. The monitor validates the integrity of the messages and generates alerts for administrators in case of suspicious activity, such as a potential DoS attack.</p>

<h2>Table of Contents</h2>
<ol>
    <li><a href="#overview">Overview</a></li>
    <li><a href="#installation">Setup and Usage</a></li>
    <li><a href="#features">Features</a></li>
    <li><a href="#design">Design</a></li>
    <li><a href="#conclusion">Conclusion</a></li>
</ol>

<h2 id="overview">Overview</h2>
<p>The system monitors the CPU and memory usage of networked machines and sends alerts if certain thresholds are exceeded. The security monitor listens for incoming connections from authenticated watchers, decrypts and verifies the integrity of the alerts, and identifies possible Denial of Service (DoS) attacks based on multiple alerts received within a short time period.</p>

<h2 id="installation">Setup and Usage</h2>
<p>To set up and use the Secure Network Monitoring System, follow these steps:</p>
<ol>
    <li><strong>Clone the repository:</strong>
        <pre><code>git clone https://github.com/abubker99/Secure-Network-Monitoring-System.git</code></pre>
    </li>
    <li><strong>Install the necessary Python packages:</strong>
        <pre><code>pip install cryptography psutil</code></pre>
    </li>
    <li><strong>Run the server (Security Monitor):</strong>
        <pre><code>python server.py</code></pre>
        <pre> <img src="https://github.com/user-attachments/assets/3f0d6de6-6eff-4410-8322-0dac30a09692"/> </pre>
    </li>
    <li><strong>Run Watcher 1:</strong>
        <pre><code>python watcher_1.py</code></pre>
       <pre> <img src="https://github.com/user-attachments/assets/c8fbfa05-4325-4a23-accc-150cfe81c5b6"/> </pre>
    </li>
    <li><strong>Run Watcher 2:</strong>
        <pre><code>python watcher_2.py</code></pre>
        <pre> <img src="https://github.com/user-attachments/assets/95bc51bd-4a73-4d6c-9344-4d6c9ddfb9cf"/> </pre>
    </li>
    <li><strong>Run Watcher 3:</strong>
        <pre><code>python watcher_3.py</code></pre>
        <pre> <img src="https://github.com/user-attachments/assets/73722943-e953-48f2-b460-1e480f8e69e3"/> </pre>
    </li>
    <li><strong>Test : Multiple Alerts Triggering a DoS Attack Detection</strong>        
        <p><strong>Server Output:</strong></p>
        <pre> <img src="https://github.com/user-attachments/assets/4015b177-a1de-4643-8c21-64220fcaf3f3"/> </pre>
        <p><strong>Explanation:</strong> In this test, multiple watchers send alerts in a short time to simulate high resource usage, which triggers a Denial of Service (DoS) attack detection on the server. The server identifies multiple alerts in a short timeframe, logs the event, and triggers the appropriate alert mechanism (e.g., admin notification). This test demonstrates the system's ability to detect potential DoS attacks based on unusual patterns of alerts.</p>
    </li>
</ol>
<h2 id="features">Features</h2>
<ul>
    <li>Secure encryption of messages using AES-GCM.</li>
    <li>Integrity checking of messages using HMAC.</li>
    <li>Detection of possible Denial of Service (DoS) attacks based on alert frequency.</li>
    <li>Authentication of watchers based on predefined keys.</li>
</ul>

<h2 id="design">Design</h2>
<h3>1. Architecture</h3>
<p>The system consists of two main components:</p>
<ul>
    <li><strong>Security Monitor (Server):</strong> This listens for incoming connections from watchers, decrypts the alerts, verifies their integrity, and checks for potential DoS attacks.</li>
    <li><strong>Security Watchers (Clients):</strong> These monitor the system's CPU and memory usage and send encrypted alerts to the security monitor when thresholds are exceeded.</li>
</ul>

<h3>2. Security</h3>
<p>The messages sent between the clients and the server are encrypted using AES-GCM and authenticated using HMAC. This ensures the confidentiality and integrity of the messages, preventing tampering and eavesdropping.</p>

<h2 id="conclusion">Conclusion</h2>
<p>This project provides a secure method for monitoring the resource usage of networked hosts. The use of AES-GCM and HMAC ensures that the messages are both confidential and tamper-proof. Additionally, the security monitor can detect potential Denial of Service (DoS) attacks based on alert frequency.</p>
