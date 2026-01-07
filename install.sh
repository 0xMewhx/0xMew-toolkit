#!/bin/bash

# Проверка на root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit
fi

echo "[*] Installing dependencies..."

# Определение пакетного менеджера (apt или pacman)
if command -v apt-get &> /dev/null; then
    apt-get update
    apt-get install -y python3 python3-pip nmap aircrack-ng ethtool macchanger tcpdump
elif command -v pacman &> /dev/null; then
    pacman -Sy --noconfirm python python-pip nmap aircrack-ng ethtool macchanger tcpdump
fi

echo "[*] Installing Python libraries..."
pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt

echo "[*] Installing Tool to /opt/0xmew..."
mkdir -p /opt/0xmew
cp wow.py /opt/0xmew/wow.py
chmod +x /opt/0xmew/wow.py

# Создание лаунчера
echo "#!/bin/bash" > /usr/bin/0xmew-tool
echo "sudo python3 /opt/0xmew/wow.py \"\$@\"" >> /usr/bin/0xmew-tool
chmod +x /usr/bin/0xmew-tool

echo ""
echo "=========================================="
echo " [+] Installation Complete!"
echo " Type '0xmew-tool' to start hacking."
echo "=========================================="
