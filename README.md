<h1>Secure Network Monitoring System</h1>

<p>This project is a secure network watching system composed of a centralized security monitor and multiple security watchers. The watchers monitor CPU and memory usage on the networked hosts. If the usage exceeds a specified threshold, the watchers send encrypted alerts to the security monitor. The monitor validates the integrity of the messages and generates alerts for administrators in the case of suspicious activity, such as a potential DoS attack.</p>

<h2>Table of Contents</h2>
<ol>
    <li><a href="#overview">Overview</a></li>
    <li><a href="#requirements">Requirements</a></li>
    <li><a href="#installation">Installation</a></li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#features">Features</a></li>
    <li><a href="#design">Design</a></li>
    <li><a href="#security">Security</a></li>
    <li><a href="#conclusion">Conclusion</a></li>
</ol>

<h2 id="overview">Overview</h2>
<p>The system is designed to monitor the CPU and memory usage of networked machines and send alerts if certain thresholds are exceeded. The security monitor listens for incoming connections from authenticated watchers, decrypts and verifies the integrity of the alerts, and identifies possible Denial of Service (DoS) attacks based on multiple alerts within a short time period.</p>

<h2 id="requirements">Requirements</h2>
<ul>
    <li>Python 3.x</li>
    <li>Cryptography library</li>
    <li>Psutil library</li>
</ul>

<h2 id="setup">Setup and Usage</h2>
<p>To set up and use the Secure Network Monitoring System, follow these steps:</p>
<ol>
    <li><strong>Clone the repository:</strong>
        <pre><code>git clone https://github.com/abubker99/Secure-Network-Monitoring-System.git</code></pre>
    </li>
    <li><strong>Install the necessary Python packages:</strong>
        <pre><code>pip install cryptography psutil</code></pre>
    </li>
    <li><strong>Run the server:</strong>
        <pre><code>python server.py</code></pre>
        <img src="https://github.com/user-attachments/assets/9fd0143c-7c2c-463e-9f38-d69da47ea5ac" alt="server running" />
    </li>
    <li><strong>Run the client:</strong>
        <pre><code>python client.py</code></pre>
        <img src="https://github.com/user-attachments/assets/161bc1d0-a3fa-4806-af2f-8e00a9742b6c" alt="client running" />
    </li>
    <li><strong>How it works:</strong> 
        <p>The security monitor (server) listens for incoming encrypted messages from the watchers (clients). The clients send alerts when the CPU or memory usage exceeds the predefined thresholds. The server validates the integrity of the messages and detects potential Denial of Service (DoS) attacks if multiple alerts are received in a short timeframe. Once the server and client are running, the system will begin monitoring and alerting as specified.</p>
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
