# 0xMew-toolkit

**Advanced Red Team Toolkit** for Linux.
Designed for penetration testing, network reconnaissance, and security auditing.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux-orange)

## 🔥 Features

* **MITM Attacks:** ARP Spoofing, DNS Redirection.
* **Recon:** Passive OS Fingerprinting, Nmap Wrapper.
* **Wi-Fi:** Beacon Flood (Fake AP), WPA Handshake Hunter.
* **OSINT:** Mr. Holmes (Username search).
* **OpSec:** MAC Address Spoofing & Identity Check.
* **Panic Button:** Emergency log/trace cleaner.

## 🚀 Installation

### 🟢 Arch Linux (Recommended)
You can install it directly from the AUR using your favorite helper:
```bash
yay -S 0xmew-toolkit
# or
paru -S 0xmew-toolkit
```

### 🐉 Kali Linux / Debian / Ubuntu
1. Download the latest **.deb** file from [Releases](https://github.com/0xMewhx/0xMew-toolkit/releases).
2. Install it via terminal:
```bash
sudo dpkg -i 0xmew-toolkit_3.4_all.deb
sudo apt-get install -f  # Fix dependencies if needed
```

### 🎩 Fedora / CentOS / RHEL
1. Download the latest **.rpm** file from [Releases](https://github.com/0xMewhx/0xMew-toolkit/releases).
2. Install it:
```bash
sudo rpm -ivh 0xmew-toolkit-3.4-1.noarch.rpm
```

### 🐍 Manual Install (Any Distro)
If you prefer running from source:
```bash
git clone https://github.com/0xMewhx/0xMew-toolkit.git
cd 0xMew-toolkit
sudo python3 wow.py
```

## 💀 Usage

Once installed via package manager, simply run the toolkit from anywhere:

```bash
sudo 0xmew-toolkit
```

## ⚠️ Disclaimer
**For educational purposes only.**
The author (0xMew) is not responsible for any misuse of this toolkit. Do not attack networks or systems you do not own or have explicit permission to test.
