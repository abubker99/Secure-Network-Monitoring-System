<h1>Secure Network Monitoring System</h1>

<p>This project is a secure network monitoring system composed of a centralized security monitor and multiple security watchers. The watchers monitor CPU and memory usage on the networked hosts. If usage exceeds a specified threshold, the watchers send digitally signed alerts to the security monitor. The monitor verifies the integrity of these messages using public‐key cryptography and generates alerts for administrators in case of suspicious activity, such as a potential DoS attack.</p>

<h2>Table of Contents</h2>
<ol>
    <li><a href="#overview">Overview</a></li>
    <li><a href="#installation">Setup and Usage</a></li>
    <li><a href="#features">Features</a></li>
    <li><a href="#design">Design</a></li>
    <li><a href="#conclusion">Conclusion</a></li>
</ol>

<h2 id="overview">Overview</h2>
<p>The system monitors the CPU and memory usage of networked machines and sends alerts if certain thresholds are exceeded. The security monitor listens for incoming connections from authenticated watchers and verifies the integrity of the received alerts using digital signatures. Based on multiple alerts received within a short period, the system is capable of detecting potential Denial of Service (DoS) attacks.</p>

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
    <li><strong>Run Watchers:</strong>
        <pre><code>python watcher_2.py</code></pre>
       <pre> <img src="https://github.com/user-attachments/assets/d24cfe9b-c497-4bb5-acdc-6e678e486a34"/> </pre>
    <li><strong>Test : Multiple Alerts Triggering a DoS Attack Detection</strong>        
        <p><strong>Server Output:</strong></p>
        <pre> <img src="https://github.com/user-attachments/assets/4015b177-a1de-4643-8c21-64220fcaf3f3"/> </pre>
        <p><strong>Explanation:</strong> In this test, multiple watchers send alerts in a short time to simulate high resource usage, which triggers a Denial of Service (DoS) attack detection on the server. The server identifies multiple alerts in a short timeframe, logs the event, and triggers the appropriate alert mechanism (e.g., admin notification). This test demonstrates the system's ability to detect potential DoS attacks based on unusual patterns of alerts.</p>
    </li>
</ol>

<h2 id="features">Features</h2>
<ul>
    <li>Digital signature verification for message integrity using public‐key cryptography.</li>
    <li>Detection of possible Denial of Service (DoS) attacks based on alert frequency.</li>
    <li>Authentication of watchers based on predefined public/private key pairs.</li>
</ul>

<h2 id="design">Design</h2>
<h3>1. Architecture</h3>
<p>The system consists of two main components:</p>
<ul>
    <li><strong>Security Monitor (Server):</strong> This component listens for incoming connections from watchers, verifies the digital signatures of the received alerts, and monitors alert frequency to detect potential DoS attacks.</li>
    <li><strong>Security Watchers (Clients):</strong> These components monitor the system's CPU and memory usage and send digitally signed alerts to the security monitor when thresholds are exceeded.</li>
</ul>

<h3>2. Security</h3>
<p>The messages exchanged between the watchers and the server are protected by digital signatures, which ensure their integrity. The server verifies each alert's signature using the corresponding watcher's public key. This approach prevents tampering and guarantees that the alerts originate from authenticated sources. with  focuse on using public‐key cryptography for ensuring message integrity.</p>

<h2 id="conclusion">Conclusion</h2>
<p>This project provides a secure method for monitoring resource usage on networked hosts. By relying on digital signatures for integrity verification, the system ensures that alerts are authentic and untampered. Additionally, it can detect potential Denial of Service (DoS) attacks based on unusual alert patterns, thereby providing administrators with critical early warning signals.</p>
