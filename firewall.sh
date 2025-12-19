#!/bin/bash
#
# IoT Honeypot Firewall Rules
# SENG 484 - Ethical Hacking Project
# TED University - Team 06
#
# Kullanım: sudo ./firewall.sh
#

echo "╔════════════════════════════════════════════════════╗"
echo "║   IoT Honeypot Firewall Configuration              ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""

# Root kontrolü
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Please run as root: sudo $0"
    exit 1
fi

echo "[*] Flushing existing rules..."
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

echo "[*] Setting default policies..."
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

echo "[*] Allowing loopback..."
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

echo "[*] Allowing established connections..."
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

echo "[*] Configuring honeypot ports..."

# Honeypot portlarına gelen trafiğe izin ver
iptables -A INPUT -p tcp --dport 22 -j ACCEPT    # SSH
iptables -A INPUT -p tcp --dport 23 -j ACCEPT    # Telnet
iptables -A INPUT -p tcp --dport 80 -j ACCEPT    # HTTP

# Cowrie port yönlendirme (22 -> 2222, 23 -> 2223)
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223

# Cowrie internal portlar
iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
iptables -A INPUT -p tcp --dport 2223 -j ACCEPT

# Dashboard
iptables -A INPUT -p tcp --dport 5000 -j ACCEPT

echo "[*] Configuring output restrictions..."

# DNS (log sunucusu için)
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# NTP (zaman senkronizasyonu)
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT

# İzole ağ içinde çıkışa izin ver
iptables -A OUTPUT -d 172.20.10.0/24 -j ACCEPT

# Dashboard bağlantısı
iptables -A OUTPUT -p tcp --dport 5000 -j ACCEPT

echo "[*] Enabling logging for dropped packets..."
iptables -A INPUT -j LOG --log-prefix "[HONEYPOT-IN-DROP] " --log-level 4
iptables -A OUTPUT -j LOG --log-prefix "[HONEYPOT-OUT-DROP] " --log-level 4

echo "[*] Saving rules..."
if command -v netfilter-persistent &> /dev/null; then
    netfilter-persistent save
else
    iptables-save > /etc/iptables.rules
    echo "iptables-restore < /etc/iptables.rules" >> /etc/rc.local 2>/dev/null || true
fi

echo ""
echo "╔════════════════════════════════════════════════════╗"
echo "║   Firewall Configuration Complete!                 ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""
echo "Current INPUT rules:"
iptables -L INPUT -n -v --line-numbers
echo ""
echo "Current NAT rules:"
iptables -t nat -L -n -v
