# DNS Tunneling & Firewall Proof-of-Concept (PoC)

## 🚨 Overview
This project demonstrates how data can be exfiltrated from a network using **DNS Tunneling**, bypassing standard firewalls. It includes a custom **Client** to send hidden messages via Google DNS and a **Next-Gen Firewall** that detects these tunnels using **Shannon Entropy**.

## 🛠️ Technology Stack
* **Language:** Python 3
* **Libraries:** `socket`, `scapy`, `binascii`
* **Concepts:** UDP Sockets, Hex Encoding, Recursion, Anomaly Detection.

## ⚙️ How It Works
### 1. The Attack (Tunneling)
Standard firewalls block TCP/HTTP, but often allow DNS (Port 53).
* The **Client** encodes a secret message into Hexadecimal.
* It attaches this hex string to a domain (e.g., `68656c6c6f.tunnel.karthicknetwork.in`).
* It queries **Google DNS (8.8.8.8)**.
* Google forwards the query to the **Attacker's Server**, bypassing the victim's firewall.

### 2. The Defense (Entropy Firewall)
How do we stop this? We can't just block DNS.
* The **Firewall** analyzes the mathematical "randomness" (Shannon Entropy) of every domain query.
* **Legitimate Domains** (e.g., `google.com`) have **Low Entropy**.
* **Encrypted Tunnels** (e.g., `8f3a1c9d...`) have **High Entropy**.
* The system flags and blocks high-entropy queries in real-time.

## 🚀 How to Run

### Prerequisite
You need `scapy` installed:
```bash
pip install scapy
1. Run the Server/Firewall (On AWS/Linux)
Bash

sudo python3 firewall.py
2. Run the Client (On Laptop)
Bash

python3 client.py
⚠️ Disclaimer
This tool is for Educational Purposes Only. Do not use this on networks you do not own.
Created by Ashwin Karthick.
