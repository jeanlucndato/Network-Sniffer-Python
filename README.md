# 🕵️ Network Packet Sniffer - CodeAlpha Cybersecurity Internship Project

[![Resultat](img/netsniffer.png)](img/netsniffer.png)
[![Resultat](img/NetS.png)](img/NetS.png)

This repository holds a foundational **Network Packet Sniffer** that I developed during my cybersecurity internship at **CodeAlpha**. This project gave me practical experience in network monitoring, data analysis, and the core principles of Intrusion Detection Systems (IDS).

---

## 🚀 Project Overview & Script Functionality

The `network_sniffer.py` script is a simple yet powerful tool built using **Scapy**, a robust Python library for packet manipulation. Its main function is to capture and log network traffic on a specified interface.

Here's how it works:

- **Packet Capture:** It uses Scapy's sniffing capabilities to intercept packets flowing through a designated network interface (like `eth0` or `wlan0`).
- **Layer-by-Layer Analysis:** For each captured packet, the script intelligently dissects it to identify key layers:
  - **Ethernet Layer:** Extracts Source and Destination MAC addresses.
  - **IP Layer:** Identifies Source and Destination IP addresses.
  - **Transport Layer (TCP/UDP/ICMP):** Determines the protocol (TCP, UDP, or ICMP) and, for TCP/UDP, extracts the respective Source and Destination port numbers.
- **Structured Logging:** All relevant packet information (timestamp, MACs, IPs, protocol, ports) is then formatted into a clear, human-readable log entry and saved to a dedicated `.log` file. This structured output makes it easier to review captured traffic for anomalies or specific events.
- **Real-time Monitoring:** The script operates in real-time, continuously capturing and logging packets until manually stopped.

This project provided hands-on experience in understanding network communication flows and served as a foundational step toward more advanced network security monitoring techniques.

---

## 🔧 How to Use the Script

Follow these steps to run the `network_sniffer.py` script and start capturing network traffic:

1.  **Ensure Prerequisites are Met:**

    - **Python 3 Installed:** Verify your Python installation by running `python3 --version` in your terminal.
    - **`scapy` Library Installed:** Install the necessary Scapy library. If you haven't already, run:
      ```bash
      pip install scapy
      # You might need sudo on some systems for system-wide installation:
      # sudo pip install scapy
      ```

2.  **Save the Script:**
    Save the provided Python code into a file named `network_sniffer.py`. Choose a convenient directory, like `~/Desktop/network_sniffer/`.

3.  **Open Your Terminal & Navigate:**
    Open your terminal or command prompt and change your current directory to where you saved the script:

    ```bash
    cd ~/Desktop/network_sniffer/ # Or your chosen path
    ```

4.  **Identify Your Network Interface:**
    You'll need the exact name of the network interface you want to monitor. Common names include `eth0`, `wlan0` (Linux), `Ethernet`, or `Wi-Fi` (Windows).

    - **Linux/macOS:** Use `ip a` or `ifconfig -a`.
    - **Windows (Command Prompt/PowerShell):** Use `ipconfig /all`.

5.  **Execute the Script:**
    Run the `network_sniffer.py` script, providing the network interface name as an argument. **Administrator or root privileges are typically required for network sniffing.**

    - **Linux/macOS:**

      ```bash
      sudo python3 network_sniffer.py <your_interface_name>
      ```

      _(Example: `sudo python3 network_sniffer.py eth0`)_

    - **Windows (Run Command Prompt or PowerShell as Administrator):**
      ```bash
      python network_sniffer.py "<Your Interface Name>"
      ```
      _(Example: `python network_sniffer.py "Wi-Fi"` - Use quotes if the interface name has spaces)_

6.  **Observe & Stop:**
    The script will display a message confirming it's sniffing traffic. To **stop** the capture, just press `Ctrl + C` in your terminal.

7.  **View the Log File:**
    After stopping, a log file named `network_sniffer_<your_interface_name>_<timestamp>.log` (e.g., `network_sniffer_wlan0_20250521_123000.log`) will be created in the same directory. Open it with any text editor to review the captured packet details. Each entry includes a timestamp, MAC addresses, IP addresses, protocol, and port numbers (where applicable).

---

## 🏷️ Tags

`Python`, `Scapy`, `Network Sniffer`, `Packet Capture`, `Cybersecurity`, `Internship Project`, `CodeAlpha`, `Network Monitoring`, `IDS`, `Linux`, `Windows`, `Network Forensics`
