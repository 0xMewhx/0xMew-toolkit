#!/bin/bash
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo ./start.sh"
    exit
fi

# Проверка зависимостей Python
pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt

# Запуск
python3 wow.py
