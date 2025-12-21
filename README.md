# IoT Honeypot Projesi - Kapsamlı Kurulum Rehberi

## 📋 Proje Özeti

Raporuna göre projen şu bileşenlerden oluşuyor:

| Bileşen | Açıklama |
|---------|----------|
| ESP32 | Fake IoT cihazı (HTTP/Telnet/SSH banner) |
| Kali Linux VM | Cowrie honeypot + log analizi |
| İzole Ağ | 172.20.10.0/24 subnet |
| Dashboard | Log görselleştirme |
| Firewall | iptables kuralları |

---

## 🔧 BÖLÜM 1: Kali Linux VM Kurulumu

### 1.1 VM Ağ Ayarları

VirtualBox veya VMware'de:

```
Network Adapter 1: NAT (internet erişimi için)
Network Adapter 2: Host-Only veya Internal Network (izole ağ için)
```

### 1.2 İzole Ağ Yapılandırması

```bash
# Kali'de ikinci ağ arayüzünü yapılandır
sudo nano /etc/network/interfaces
```

Ekle:
```
auto eth1
iface eth1 inet static
    address 172.20.10.13
    netmask 255.255.255.0
```

```bash
# Ağı yeniden başlat
sudo systemctl restart networking

# IP'yi kontrol et
ip addr show eth1
```

### 1.3 Gerekli Paketlerin Kurulumu

```bash
# Sistem güncellemesi
sudo apt update && sudo apt upgrade -y

# Python ve pip
sudo apt install python3 python3-pip python3-venv -y

# Ağ araçları
sudo apt install tcpdump wireshark nmap -y

# Log analizi için
sudo apt install jq sqlite3 -y

# Flask dashboard için
pip3 install flask flask-socketio pandas matplotlib --break-system-packages
```

---

## 🐮 BÖLÜM 2: Cowrie Honeypot Kurulumu

### 2.1 Cowrie Kurulumu

```bash
# Cowrie için kullanıcı oluştur
sudo adduser --disabled-password cowrie
sudo su - cowrie

# Cowrie'yi indir
cd /home/cowrie
git clone https://github.com/cowrie/cowrie.git
cd cowrie

# Virtual environment oluştur
python3 -m venv cowrie-env
source cowrie-env/bin/activate

# Bağımlılıkları kur
pip install --upgrade pip
pip install -r requirements.txt
```

### 2.2 Cowrie Yapılandırması

```bash
# Konfigürasyon dosyasını kopyala
cp etc/cowrie.cfg.dist etc/cowrie.cfg

# Düzenle
nano etc/cowrie.cfg
```

**cowrie.cfg içeriği:**
```ini
[honeypot]
hostname = iot-device
log_path = var/log/cowrie
download_path = var/lib/cowrie/downloads
ttylog_path = var/lib/cowrie/tty

# Simüle edilen dosya sistemi
filesystem = share/cowrie/fs.pickle

# IoT cihazı gibi görünmesi için
kernel_version = 4.4.0
kernel_build_string = Linux version 4.4.0-iot-rpi

[ssh]
enabled = true
listen_endpoints = tcp:2222:interface=0.0.0.0
version = SSH-2.0-OpenSSH_7.4

[telnet]
enabled = true
listen_endpoints = tcp:2223:interface=0.0.0.0

[output_jsonlog]
enabled = true
logfile = var/log/cowrie/cowrie.json

[output_textlog]
enabled = true
logfile = var/log/cowrie/cowrie.log
```

### 2.3 Zayıf Credential'lar Ekleme

```bash
# userdb dosyasını düzenle
nano etc/userdb.txt
```

**userdb.txt içeriği:**
```
# Format: username:uid:password
root:0:root
root:0:admin
root:0:12345
root:0:123456
root:0:password
admin:1000:admin
admin:1000:admin123
admin:1000:12345
admin:1000:password
user:1001:user
user:1001:123456
pi:1002:raspberry
ubnt:1003:ubnt
```

### 2.4 Port Yönlendirme (Root olmadan çalıştırma)

```bash
# Cowrie'den çık
exit

# Root olarak iptables kuralları ekle
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223

# Kuralları kaydet
sudo apt install iptables-persistent -y
sudo netfilter-persistent save
```

### 2.5 Cowrie'yi Başlat

```bash
sudo su - cowrie
cd cowrie
source cowrie-env/bin/activate
bin/cowrie start

# Logları kontrol et
tail -f var/log/cowrie/cowrie.log
```

---

## 📡 BÖLÜM 3: ESP32 Firmware

### 3.1 Arduino IDE Kurulumu

1. Arduino IDE'yi aç
2. File > Preferences > Additional Board Manager URLs:
   ```
   https://dl.espressif.com/dl/package_esp32_index.json
   ```
3. Tools > Board > Boards Manager > "esp32" ara ve kur

### 3.2 ESP32 Honeypot Kodu

Arduino IDE'de iot_honeypot projesini aç:


### 3.3 ESP32'ye Yükleme

1. ESP32'yi USB ile bağla
2. Tools > Board > ESP32 Dev Module
3. Tools > Port > COMx (ESP32'nin portu)
4. Upload butonuna tıkla

---

## 🖥️ BÖLÜM 4: Flask Log Sunucusu ve Dashboard

### 4.1 Dizin Yapısı

```bash
mkdir -p ~/honeypot-dashboard/{logs,static,templates}
cd ~/honeypot-dashboard
```

### 4.2 Flask Sunucu Kodu



### 4.3 Dashboard HTML Template



---

## 🔥 BÖLÜM 5: Firewall (iptables) Kuralları

### 5.1 Firewall Script'i


chmod +x ~/honeypot-dashboard/firewall.sh
sudo ~/honeypot-dashboard/firewall.sh
```

---

## 📊 BÖLÜM 6: Log Analizi Scriptleri

### 6.1 Python Analiz Scripti



```bash
chmod +x ~/honeypot-dashboard/analyze_logs.py
```

---

## 🚀 BÖLÜM 7: Başlatma ve Test

### 7.1 Servisleri Başlat

```bash
# Terminal 1: Cowrie başlat
sudo su - cowrie
cd cowrie
source cowrie-env/bin/activate
bin/cowrie start

# Terminal 2: Flask Dashboard başlat
cd ~/honeypot-dashboard
python3 app.py

# Terminal 3: tcpdump ile trafik yakala
sudo tcpdump -i eth1 -w ~/honeypot-dashboard/logs/capture.pcap
```

### 7.2 Test Komutları (Ayrı bir makineden)

```bash
# Nmap port tarama
nmap -sV -p 22,23,80 172.20.10.9

# Hydra brute-force testi
hydra -L users.txt -P passwords.txt 172.20.10.9 ssh
hydra -L users.txt -P passwords.txt 172.20.10.9 telnet

# HTTP login testi
curl -X POST http://172.20.10.9/login \
     -d "username=admin&password=admin"

# Telnet bağlantı testi
telnet 172.20.10.9
```

### 7.3 Kontrol Listesi

| Adım | Açıklama | Durum |
|------|----------|-------|
| 1 | Kali VM kuruldu | ☐ |
| 2 | İzole ağ yapılandırıldı | ☐ |
| 3 | Cowrie kuruldu ve yapılandırıldı | ☐ |
| 4 | ESP32 kodu yüklendi | ☐ |
| 5 | Flask dashboard çalışıyor | ☐ |
| 6 | Firewall kuralları aktif | ☐ |
| 7 | Log toplama çalışıyor | ☐ |
| 8 | Test saldırıları yapıldı | ☐ |

---

## 📁 Proje Dosya Yapısı

```
honeypot-project/
├── esp32/
│   └── iot_honeypot.ino          # ESP32 Arduino kodu
├── kali/
│   ├── cowrie/                    # Cowrie kurulum dizini
│   └── honeypot-dashboard/
│       ├── app.py                 # Flask sunucu
│       ├── templates/
│       │   └── dashboard.html     # Dashboard arayüzü
│       ├── logs/
│       │   ├── honeypot.db        # SQLite veritabanı
│       │   └── capture.pcap       # Paket yakalama
│       ├── firewall.sh            # iptables kuralları
│       └── analyze_logs.py        # Log analiz scripti
└── docs/
    └── SENG_484_Final_Report.pdf
```

---

## ⚠️ Önemli Notlar

1. **WiFi bilgilerini güncelle**: ESP32 kodunda `WIFI_SSID` ve `WIFI_PASSWORD` değerlerini değiştir

2. **IP adreslerini kontrol et**: 
   - ESP32: 172.20.10.9
   - Kali VM: 172.20.10.5
   - Bu değerleri kendi ağ yapına göre düzenle

3. **İzolasyon kritik**: Honeypot'u asla ana ağında açık bırakma

4. **Demo için**: Tarayıcıda http://172.20.10.5:5000 adresinden dashboard'a eriş

