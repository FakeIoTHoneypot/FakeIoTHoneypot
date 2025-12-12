# IoT Honeypot Projesi - Kapsamlı Kurulum Rehberi

## 📋 Proje Özeti

Raporuna göre projen şu bileşenlerden oluşuyor:

| Bileşen | Açıklama |
|---------|----------|
| ESP32 | Fake IoT cihazı (HTTP/Telnet/SSH banner) |
| Kali Linux VM | Cowrie honeypot + log analizi |
| İzole Ağ | 192.168.100.0/24 subnet |
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
    address 192.168.100.10
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

Arduino IDE'de yeni dosya oluştur ve aşağıdaki kodu yapıştır:

```cpp
/*
 * ESP32 Fake IoT Honeypot
 * SENG 484 - Ethical Hacking Project
 * 
 * Bu kod ESP32'yi sahte bir IoT cihazı olarak yapılandırır
 * ve tüm bağlantı denemelerini loglar.
 */

#include <WiFi.h>
#include <WebServer.h>
#include <HTTPClient.h>
#include <SPIFFS.h>
#include <time.h>

// ====== YAPILANDIRMA ======
const char* WIFI_SSID = "YOUR_WIFI_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";

// Kali VM IP adresi (log gönderimi için)
const char* LOG_SERVER = "http://192.168.100.10:5000/log";

// Statik IP (opsiyonel)
IPAddress local_IP(192, 168, 100, 50);
IPAddress gateway(192, 168, 100, 1);
IPAddress subnet(255, 255, 255, 0);

// ====== SUNUCU TANIMLARI ======
WebServer httpServer(80);
WiFiServer telnetServer(23);
WiFiServer sshServer(22);

// ====== LOG BUFFER ======
#define MAX_LOGS 100
String logBuffer[MAX_LOGS];
int logIndex = 0;

// ====== FONKSIYON PROTOTIPLERI ======
void setupWiFi();
void setupServers();
void handleRoot();
void handleLogin();
void handleAdmin();
void handleNotFound();
void handleTelnet();
void handleSSH();
void logEvent(String eventType, String sourceIP, String payload);
void sendLogToServer(String logEntry);
String getTimestamp();

void setup() {
    Serial.begin(115200);
    delay(1000);
    
    Serial.println("\n========================================");
    Serial.println("  ESP32 IoT Honeypot Starting...");
    Serial.println("========================================\n");
    
    // SPIFFS başlat
    if (!SPIFFS.begin(true)) {
        Serial.println("[ERROR] SPIFFS mount failed!");
    } else {
        Serial.println("[OK] SPIFFS mounted");
    }
    
    setupWiFi();
    setupServers();
    
    Serial.println("\n[READY] Honeypot is active and listening...");
    Serial.println("========================================\n");
}

void loop() {
    httpServer.handleClient();
    handleTelnet();
    handleSSH();
    delay(10);
}

// ====== WiFi KURULUMU ======
void setupWiFi() {
    Serial.print("[WiFi] Connecting to ");
    Serial.println(WIFI_SSID);
    
    // Statik IP yapılandır (opsiyonel)
    // WiFi.config(local_IP, gateway, subnet);
    
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    
    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 30) {
        delay(500);
        Serial.print(".");
        attempts++;
    }
    
    if (WiFi.status() == WL_CONNECTED) {
        Serial.println("\n[OK] WiFi connected!");
        Serial.print("[INFO] IP Address: ");
        Serial.println(WiFi.localIP());
    } else {
        Serial.println("\n[ERROR] WiFi connection failed!");
    }
    
    // NTP ile zaman senkronizasyonu
    configTime(3 * 3600, 0, "pool.ntp.org");
}

// ====== SUNUCU KURULUMU ======
void setupServers() {
    // HTTP sunucusu
    httpServer.on("/", handleRoot);
    httpServer.on("/login", HTTP_POST, handleLogin);
    httpServer.on("/admin", handleAdmin);
    httpServer.on("/config.php", handleNotFound);
    httpServer.on("/.env", handleNotFound);
    httpServer.on("/wp-config.php", handleNotFound);
    httpServer.onNotFound(handleNotFound);
    httpServer.begin();
    Serial.println("[OK] HTTP server started on port 80");
    
    // Telnet sunucusu
    telnetServer.begin();
    Serial.println("[OK] Telnet server started on port 23");
    
    // SSH banner sunucusu
    sshServer.begin();
    Serial.println("[OK] SSH banner server started on port 22");
}

// ====== HTTP İŞLEYİCİLERİ ======

// Ana sayfa - IoT login paneli
void handleRoot() {
    String clientIP = httpServer.client().remoteIP().toString();
    logEvent("HTTP_ACCESS", clientIP, "GET /");
    
    String html = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
    <title>IoT Device - Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.5);
            width: 320px;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            color: #333;
            font-size: 24px;
        }
        .logo p {
            color: #666;
            font-size: 12px;
        }
        input {
            width: 100%;
            padding: 12px;
            margin: 8px 0;
            border: 1px solid #ddd;
            border-radius: 5px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #0066cc;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover {
            background: #0052a3;
        }
        .footer {
            text-align: center;
            margin-top: 20px;
            color: #999;
            font-size: 11px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>🌐 Smart IoT Gateway</h1>
            <p>Model: SGW-2000 | Firmware: v2.1.4</p>
        </div>
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <div class="footer">
            Default credentials: admin / admin<br>
            © 2024 Smart IoT Solutions
        </div>
    </div>
</body>
</html>
)rawliteral";
    
    httpServer.send(200, "text/html", html);
}

// Login denemesi
void handleLogin() {
    String clientIP = httpServer.client().remoteIP().toString();
    String username = httpServer.arg("username");
    String password = httpServer.arg("password");
    
    String payload = "username=" + username + "&password=" + password;
    logEvent("HTTP_LOGIN", clientIP, payload);
    
    // Her zaman başarısız göster (honeypot)
    String html = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
    <title>Login Failed</title>
    <style>
        body { font-family: Arial; background: #1a1a2e; color: white; text-align: center; padding-top: 100px; }
        .error { background: #ff4444; padding: 20px; border-radius: 5px; display: inline-block; }
        a { color: #66ccff; }
    </style>
</head>
<body>
    <div class="error">
        <h2>⚠️ Authentication Failed</h2>
        <p>Invalid username or password.</p>
        <p><a href="/">Try again</a></p>
    </div>
</body>
</html>
)rawliteral";
    
    httpServer.send(401, "text/html", html);
}

// Admin sayfası
void handleAdmin() {
    String clientIP = httpServer.client().remoteIP().toString();
    logEvent("HTTP_ADMIN_ATTEMPT", clientIP, "GET /admin");
    
    httpServer.send(401, "text/html", "<h1>401 Unauthorized</h1>");
}

// 404 ve vulnerability tarama denemeleri
void handleNotFound() {
    String clientIP = httpServer.client().remoteIP().toString();
    String path = httpServer.uri();
    logEvent("HTTP_SCAN", clientIP, "GET " + path);
    
    httpServer.send(404, "text/html", "<h1>404 Not Found</h1>");
}

// ====== TELNET İŞLEYİCİSİ ======
void handleTelnet() {
    WiFiClient client = telnetServer.available();
    
    if (client) {
        String clientIP = client.remoteIP().toString();
        logEvent("TELNET_CONNECT", clientIP, "New connection");
        
        // Banner gönder
        client.println("\r\n*******************************************");
        client.println("*     Smart IoT Gateway - SGW-2000        *");
        client.println("*     Firmware Version: 2.1.4             *");
        client.println("*******************************************\r\n");
        
        unsigned long timeout = millis() + 30000; // 30 saniye timeout
        String inputBuffer = "";
        int loginAttempts = 0;
        bool authenticated = false;
        
        while (client.connected() && millis() < timeout && loginAttempts < 3) {
            // Username iste
            client.print("login: ");
            String username = "";
            while (client.connected() && millis() < timeout) {
                if (client.available()) {
                    char c = client.read();
                    if (c == '\n' || c == '\r') break;
                    username += c;
                }
            }
            username.trim();
            
            // Password iste
            client.print("Password: ");
            String password = "";
            while (client.connected() && millis() < timeout) {
                if (client.available()) {
                    char c = client.read();
                    if (c == '\n' || c == '\r') break;
                    password += c;
                }
            }
            password.trim();
            
            // Credential'ları logla
            String payload = "username=" + username + "&password=" + password;
            logEvent("TELNET_LOGIN", clientIP, payload);
            
            // Her zaman başarısız
            client.println("\r\nLogin incorrect\r\n");
            loginAttempts++;
        }
        
        client.println("\r\nToo many failed attempts. Connection closed.\r\n");
        client.stop();
        
        logEvent("TELNET_DISCONNECT", clientIP, "Connection closed after " + String(loginAttempts) + " attempts");
    }
}

// ====== SSH BANNER İŞLEYİCİSİ ======
void handleSSH() {
    WiFiClient client = sshServer.available();
    
    if (client) {
        String clientIP = client.remoteIP().toString();
        logEvent("SSH_CONNECT", clientIP, "Banner probe");
        
        // SSH banner gönder
        client.print("SSH-2.0-OpenSSH_7.4\r\n");
        
        // Kısa süre bekle ve kapat
        delay(1000);
        client.stop();
    }
}

// ====== LOGLAMA ======
void logEvent(String eventType, String sourceIP, String payload) {
    String timestamp = getTimestamp();
    
    // JSON formatında log
    String logEntry = "{";
    logEntry += "\"timestamp\":\"" + timestamp + "\",";
    logEntry += "\"type\":\"" + eventType + "\",";
    logEntry += "\"source_ip\":\"" + sourceIP + "\",";
    logEntry += "\"payload\":\"" + payload + "\"";
    logEntry += "}";
    
    // Serial'e yazdır
    Serial.println("[LOG] " + logEntry);
    
    // Buffer'a ekle
    logBuffer[logIndex % MAX_LOGS] = logEntry;
    logIndex++;
    
    // Sunucuya gönder
    sendLogToServer(logEntry);
    
    // SPIFFS'e yaz (backup)
    File logFile = SPIFFS.open("/logs.jsonl", FILE_APPEND);
    if (logFile) {
        logFile.println(logEntry);
        logFile.close();
    }
}

void sendLogToServer(String logEntry) {
    if (WiFi.status() == WL_CONNECTED) {
        HTTPClient http;
        http.begin(LOG_SERVER);
        http.addHeader("Content-Type", "application/json");
        
        int httpCode = http.POST(logEntry);
        
        if (httpCode > 0) {
            Serial.printf("[HTTP] Log sent, response code: %d\n", httpCode);
        } else {
            Serial.printf("[HTTP] Log send failed: %s\n", http.errorToString(httpCode).c_str());
        }
        
        http.end();
    }
}

String getTimestamp() {
    struct tm timeinfo;
    if (!getLocalTime(&timeinfo)) {
        return "1970-01-01T00:00:00Z";
    }
    
    char buffer[30];
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &timeinfo);
    return String(buffer);
}
```

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

```bash
nano ~/honeypot-dashboard/app.py
```

```python
#!/usr/bin/env python3
"""
IoT Honeypot Dashboard
SENG 484 - Ethical Hacking Project

Bu sunucu ESP32'den gelen logları toplar ve
gerçek zamanlı dashboard sunar.
"""

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from datetime import datetime
import json
import os
import sqlite3
from collections import Counter
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = 'honeypot-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

# ====== VERİTABANI ======
DB_PATH = 'logs/honeypot.db'

def init_db():
    """Veritabanını oluştur"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            source_ip TEXT,
            payload TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def save_log(log_data):
    """Log'u veritabanına kaydet"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO logs (timestamp, event_type, source_ip, payload)
        VALUES (?, ?, ?, ?)
    ''', (
        log_data.get('timestamp', datetime.utcnow().isoformat()),
        log_data.get('type', 'UNKNOWN'),
        log_data.get('source_ip', 'unknown'),
        log_data.get('payload', '')
    ))
    conn.commit()
    conn.close()

def get_stats():
    """İstatistikleri getir"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    stats = {}
    
    # Toplam log sayısı
    c.execute('SELECT COUNT(*) FROM logs')
    stats['total_events'] = c.fetchone()[0]
    
    # Benzersiz IP sayısı
    c.execute('SELECT COUNT(DISTINCT source_ip) FROM logs')
    stats['unique_ips'] = c.fetchone()[0]
    
    # Event türüne göre dağılım
    c.execute('SELECT event_type, COUNT(*) FROM logs GROUP BY event_type')
    stats['event_types'] = dict(c.fetchall())
    
    # En çok deneyen IP'ler
    c.execute('''
        SELECT source_ip, COUNT(*) as count 
        FROM logs 
        GROUP BY source_ip 
        ORDER BY count DESC 
        LIMIT 10
    ''')
    stats['top_ips'] = [{'ip': row[0], 'count': row[1]} for row in c.fetchall()]
    
    # Son 24 saat aktivite
    c.execute('''
        SELECT strftime('%H', created_at) as hour, COUNT(*) 
        FROM logs 
        WHERE created_at >= datetime('now', '-24 hours')
        GROUP BY hour
    ''')
    stats['hourly_activity'] = dict(c.fetchall())
    
    # En çok denenen credential'lar
    c.execute('''
        SELECT payload, COUNT(*) as count 
        FROM logs 
        WHERE event_type IN ('HTTP_LOGIN', 'TELNET_LOGIN')
        GROUP BY payload 
        ORDER BY count DESC 
        LIMIT 10
    ''')
    stats['top_credentials'] = [{'payload': row[0], 'count': row[1]} for row in c.fetchall()]
    
    conn.close()
    return stats

def get_recent_logs(limit=50):
    """Son logları getir"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT id, timestamp, event_type, source_ip, payload, created_at
        FROM logs
        ORDER BY id DESC
        LIMIT ?
    ''', (limit,))
    
    logs = []
    for row in c.fetchall():
        logs.append({
            'id': row[0],
            'timestamp': row[1],
            'type': row[2],
            'source_ip': row[3],
            'payload': row[4],
            'created_at': row[5]
        })
    
    conn.close()
    return logs

# ====== ROUTES ======

@app.route('/')
def dashboard():
    """Ana dashboard"""
    return render_template('dashboard.html')

@app.route('/log', methods=['POST'])
def receive_log():
    """ESP32'den log al"""
    try:
        log_data = request.get_json()
        save_log(log_data)
        
        # WebSocket ile dashboard'a gönder
        socketio.emit('new_log', log_data)
        
        print(f"[LOG] {log_data.get('type')}: {log_data.get('source_ip')} - {log_data.get('payload')}")
        
        return jsonify({'status': 'ok'}), 200
    except Exception as e:
        print(f"[ERROR] {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/api/stats')
def api_stats():
    """İstatistik API"""
    return jsonify(get_stats())

@app.route('/api/logs')
def api_logs():
    """Log listesi API"""
    limit = request.args.get('limit', 50, type=int)
    return jsonify(get_recent_logs(limit))

@app.route('/api/logs/export')
def export_logs():
    """Logları JSON olarak export et"""
    logs = get_recent_logs(10000)
    return jsonify(logs)

# ====== WEBSOCKET ======

@socketio.on('connect')
def handle_connect():
    print('[WS] Client connected')
    emit('stats_update', get_stats())

@socketio.on('request_stats')
def handle_stats_request():
    emit('stats_update', get_stats())

# ====== MAIN ======

if __name__ == '__main__':
    init_db()
    print("\n" + "="*50)
    print("  IoT Honeypot Dashboard")
    print("  http://0.0.0.0:5000")
    print("="*50 + "\n")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
```

### 4.3 Dashboard HTML Template

```bash
nano ~/honeypot-dashboard/templates/dashboard.html
```

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IoT Honeypot Dashboard</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.5.4/socket.io.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a3e 100%);
            color: #fff;
            min-height: 100vh;
        }
        
        .header {
            background: rgba(0,0,0,0.3);
            padding: 20px;
            text-align: center;
            border-bottom: 1px solid #333;
        }
        
        .header h1 {
            color: #00ff88;
            font-size: 28px;
        }
        
        .header p {
            color: #888;
            margin-top: 5px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }
        
        .stat-card h3 {
            color: #888;
            font-size: 14px;
            margin-bottom: 10px;
        }
        
        .stat-card .value {
            font-size: 36px;
            font-weight: bold;
            color: #00ff88;
        }
        
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .chart-card {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 10px;
            padding: 20px;
        }
        
        .chart-card h3 {
            color: #fff;
            margin-bottom: 15px;
            font-size: 16px;
        }
        
        .log-section {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 10px;
            padding: 20px;
        }
        
        .log-section h3 {
            color: #fff;
            margin-bottom: 15px;
        }
        
        .log-list {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .log-item {
            background: rgba(0,0,0,0.3);
            border-left: 3px solid #00ff88;
            padding: 10px 15px;
            margin-bottom: 8px;
            border-radius: 0 5px 5px 0;
            font-family: monospace;
            font-size: 13px;
        }
        
        .log-item.http { border-left-color: #00aaff; }
        .log-item.telnet { border-left-color: #ffaa00; }
        .log-item.ssh { border-left-color: #ff5555; }
        
        .log-item .time {
            color: #666;
            margin-right: 10px;
        }
        
        .log-item .type {
            color: #00ff88;
            font-weight: bold;
            margin-right: 10px;
        }
        
        .log-item .ip {
            color: #ff8800;
            margin-right: 10px;
        }
        
        .log-item .payload {
            color: #aaa;
        }
        
        .status-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            background: #00ff88;
            border-radius: 50%;
            margin-right: 8px;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .top-list {
            list-style: none;
        }
        
        .top-list li {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        
        .top-list li:last-child {
            border-bottom: none;
        }
        
        .top-list .count {
            background: rgba(0,255,136,0.2);
            color: #00ff88;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ IoT Honeypot Dashboard</h1>
        <p><span class="status-indicator"></span>Real-time Threat Monitoring</p>
    </div>
    
    <div class="container">
        <!-- İstatistik Kartları -->
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Events</h3>
                <div class="value" id="total-events">0</div>
            </div>
            <div class="stat-card">
                <h3>Unique IPs</h3>
                <div class="value" id="unique-ips">0</div>
            </div>
            <div class="stat-card">
                <h3>Login Attempts</h3>
                <div class="value" id="login-attempts">0</div>
            </div>
            <div class="stat-card">
                <h3>Scans Detected</h3>
                <div class="value" id="scans-detected">0</div>
            </div>
        </div>
        
        <!-- Grafikler -->
        <div class="charts-grid">
            <div class="chart-card">
                <h3>📊 Attack Types Distribution</h3>
                <canvas id="eventTypeChart"></canvas>
            </div>
            <div class="chart-card">
                <h3>🌍 Top Attacking IPs</h3>
                <ul class="top-list" id="top-ips-list"></ul>
            </div>
            <div class="chart-card">
                <h3>🔑 Top Credential Attempts</h3>
                <ul class="top-list" id="top-creds-list"></ul>
            </div>
            <div class="chart-card">
                <h3>📈 24-Hour Activity</h3>
                <canvas id="hourlyChart"></canvas>
            </div>
        </div>
        
        <!-- Log Listesi -->
        <div class="log-section">
            <h3>📜 Live Event Stream</h3>
            <div class="log-list" id="log-list"></div>
        </div>
    </div>
    
    <script>
        const socket = io();
        let eventTypeChart, hourlyChart;
        
        // Grafikleri başlat
        function initCharts() {
            const ctx1 = document.getElementById('eventTypeChart').getContext('2d');
            eventTypeChart = new Chart(ctx1, {
                type: 'doughnut',
                data: {
                    labels: [],
                    datasets: [{
                        data: [],
                        backgroundColor: [
                            '#00ff88', '#00aaff', '#ffaa00', '#ff5555', 
                            '#aa55ff', '#55ffaa', '#ff55aa', '#5555ff'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            labels: { color: '#fff' }
                        }
                    }
                }
            });
            
            const ctx2 = document.getElementById('hourlyChart').getContext('2d');
            hourlyChart = new Chart(ctx2, {
                type: 'bar',
                data: {
                    labels: Array.from({length: 24}, (_, i) => i + ':00'),
                    datasets: [{
                        label: 'Events',
                        data: Array(24).fill(0),
                        backgroundColor: '#00ff88'
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: { color: '#fff' },
                            grid: { color: 'rgba(255,255,255,0.1)' }
                        },
                        x: {
                            ticks: { color: '#fff' },
                            grid: { color: 'rgba(255,255,255,0.1)' }
                        }
                    },
                    plugins: {
                        legend: { display: false }
                    }
                }
            });
        }
        
        // İstatistikleri güncelle
        function updateStats(stats) {
            document.getElementById('total-events').textContent = stats.total_events || 0;
            document.getElementById('unique-ips').textContent = stats.unique_ips || 0;
            
            const loginAttempts = (stats.event_types?.HTTP_LOGIN || 0) + 
                                  (stats.event_types?.TELNET_LOGIN || 0);
            document.getElementById('login-attempts').textContent = loginAttempts;
            document.getElementById('scans-detected').textContent = stats.event_types?.HTTP_SCAN || 0;
            
            // Event type chart güncelle
            if (stats.event_types) {
                eventTypeChart.data.labels = Object.keys(stats.event_types);
                eventTypeChart.data.datasets[0].data = Object.values(stats.event_types);
                eventTypeChart.update();
            }
            
            // Hourly chart güncelle
            if (stats.hourly_activity) {
                const hourlyData = Array(24).fill(0);
                Object.entries(stats.hourly_activity).forEach(([hour, count]) => {
                    hourlyData[parseInt(hour)] = count;
                });
                hourlyChart.data.datasets[0].data = hourlyData;
                hourlyChart.update();
            }
            
            // Top IPs
            const ipsList = document.getElementById('top-ips-list');
            ipsList.innerHTML = '';
            (stats.top_ips || []).forEach(item => {
                ipsList.innerHTML += `<li><span>${item.ip}</span><span class="count">${item.count}</span></li>`;
            });
            
            // Top Credentials
            const credsList = document.getElementById('top-creds-list');
            credsList.innerHTML = '';
            (stats.top_credentials || []).slice(0, 10).forEach(item => {
                const payload = item.payload.replace(/username=|password=/g, '').replace('&', ' / ');
                credsList.innerHTML += `<li><span style="font-family:monospace;font-size:12px">${payload}</span><span class="count">${item.count}</span></li>`;
            });
        }
        
        // Yeni log ekle
        function addLogItem(log) {
            const logList = document.getElementById('log-list');
            const logType = log.type.toLowerCase();
            let typeClass = '';
            if (logType.includes('http')) typeClass = 'http';
            else if (logType.includes('telnet')) typeClass = 'telnet';
            else if (logType.includes('ssh')) typeClass = 'ssh';
            
            const logItem = document.createElement('div');
            logItem.className = `log-item ${typeClass}`;
            logItem.innerHTML = `
                <span class="time">${log.timestamp || new Date().toISOString()}</span>
                <span class="type">${log.type}</span>
                <span class="ip">${log.source_ip}</span>
                <span class="payload">${log.payload}</span>
            `;
            
            logList.insertBefore(logItem, logList.firstChild);
            
            // Max 100 log tut
            while (logList.children.length > 100) {
                logList.removeChild(logList.lastChild);
            }
        }
        
        // WebSocket olayları
        socket.on('connect', () => {
            console.log('Connected to server');
        });
        
        socket.on('stats_update', (stats) => {
            updateStats(stats);
        });
        
        socket.on('new_log', (log) => {
            addLogItem(log);
            socket.emit('request_stats');
        });
        
        // Başlangıç
        document.addEventListener('DOMContentLoaded', () => {
            initCharts();
            
            // İlk verileri yükle
            fetch('/api/stats')
                .then(r => r.json())
                .then(stats => updateStats(stats));
            
            fetch('/api/logs?limit=50')
                .then(r => r.json())
                .then(logs => logs.reverse().forEach(log => addLogItem(log)));
            
            // Periyodik güncelleme
            setInterval(() => {
                socket.emit('request_stats');
            }, 5000);
        });
    </script>
</body>
</html>
```

---

## 🔥 BÖLÜM 5: Firewall (iptables) Kuralları

### 5.1 Firewall Script'i

```bash
nano ~/honeypot-dashboard/firewall.sh
```

```bash
#!/bin/bash
#
# IoT Honeypot Firewall Rules
# SENG 484 - Ethical Hacking Project
#

echo "=========================================="
echo "  Configuring Honeypot Firewall Rules"
echo "=========================================="

# Mevcut kuralları temizle
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Varsayılan politikalar
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Loopback izin ver
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Kurulu bağlantılara izin ver
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

echo "[+] Allowing honeypot ports..."

# Honeypot portlarına gelen trafiğe izin ver
iptables -A INPUT -p tcp --dport 22 -j ACCEPT    # SSH
iptables -A INPUT -p tcp --dport 23 -j ACCEPT    # Telnet
iptables -A INPUT -p tcp --dport 80 -j ACCEPT    # HTTP

# Cowrie port yönlendirme
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223

# Cowrie portlarına izin ver
iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
iptables -A INPUT -p tcp --dport 2223 -j ACCEPT

# Dashboard portuna izin ver
iptables -A INPUT -p tcp --dport 5000 -j ACCEPT

echo "[+] Configuring output restrictions..."

# DNS çıkışına izin ver (log sunucusu için)
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# NTP'ye izin ver (zaman senkronizasyonu)
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT

# İzole ağ içinde çıkışa izin ver (ESP32 ile iletişim)
iptables -A OUTPUT -d 192.168.100.0/24 -j ACCEPT

# Dashboard'a bağlantı için (ESP32'den log alma)
iptables -A OUTPUT -p tcp --dport 5000 -j ACCEPT

echo "[+] Logging dropped packets..."

# Drop edilen paketleri logla
iptables -A INPUT -j LOG --log-prefix "[HONEYPOT-IN-DROP] " --log-level 4
iptables -A OUTPUT -j LOG --log-prefix "[HONEYPOT-OUT-DROP] " --log-level 4

echo "[+] Saving rules..."

# Kuralları kaydet
if command -v netfilter-persistent &> /dev/null; then
    netfilter-persistent save
else
    iptables-save > /etc/iptables.rules
    echo "iptables-restore < /etc/iptables.rules" >> /etc/rc.local
fi

echo ""
echo "=========================================="
echo "  Firewall configuration complete!"
echo "=========================================="
echo ""
echo "Current rules:"
iptables -L -n -v
echo ""
echo "NAT rules:"
iptables -t nat -L -n -v
```

```bash
chmod +x ~/honeypot-dashboard/firewall.sh
sudo ~/honeypot-dashboard/firewall.sh
```

---

## 📊 BÖLÜM 6: Log Analizi Scriptleri

### 6.1 Python Analiz Scripti

```bash
nano ~/honeypot-dashboard/analyze_logs.py
```

```python
#!/usr/bin/env python3
"""
Honeypot Log Analyzer
SENG 484 - Ethical Hacking Project
"""

import sqlite3
import json
from collections import Counter
from datetime import datetime
import os

DB_PATH = 'logs/honeypot.db'

def analyze_logs():
    """Ana analiz fonksiyonu"""
    
    if not os.path.exists(DB_PATH):
        print("[ERROR] Database not found!")
        return
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    print("\n" + "="*60)
    print("  IoT HONEYPOT - LOG ANALYSIS REPORT")
    print("  Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("="*60 + "\n")
    
    # 1. Genel İstatistikler
    print("📊 GENERAL STATISTICS")
    print("-"*40)
    
    c.execute('SELECT COUNT(*) FROM logs')
    total = c.fetchone()[0]
    print(f"Total Events: {total}")
    
    c.execute('SELECT COUNT(DISTINCT source_ip) FROM logs')
    unique_ips = c.fetchone()[0]
    print(f"Unique Source IPs: {unique_ips}")
    
    c.execute('SELECT MIN(created_at), MAX(created_at) FROM logs')
    dates = c.fetchone()
    print(f"Date Range: {dates[0]} to {dates[1]}")
    
    # 2. Event Türleri
    print("\n📈 EVENT TYPE BREAKDOWN")
    print("-"*40)
    
    c.execute('''
        SELECT event_type, COUNT(*) as count 
        FROM logs 
        GROUP BY event_type 
        ORDER BY count DESC
    ''')
    
    for row in c.fetchall():
        pct = (row[1] / total) * 100 if total > 0 else 0
        bar = "█" * int(pct / 2)
        print(f"{row[0]:<25} {row[1]:>6} ({pct:5.1f}%) {bar}")
    
    # 3. En Aktif Saldırganlar
    print("\n🌍 TOP 10 ATTACKING IPs")
    print("-"*40)
    
    c.execute('''
        SELECT source_ip, COUNT(*) as count,
               MIN(created_at) as first_seen,
               MAX(created_at) as last_seen
        FROM logs 
        GROUP BY source_ip 
        ORDER BY count DESC 
        LIMIT 10
    ''')
    
    print(f"{'IP Address':<18} {'Count':>8} {'First Seen':<20} {'Last Seen':<20}")
    print("-"*70)
    for row in c.fetchall():
        print(f"{row[0]:<18} {row[1]:>8} {row[2]:<20} {row[3]:<20}")
    
    # 4. En Çok Denenen Credential'lar
    print("\n🔑 TOP CREDENTIAL ATTEMPTS")
    print("-"*40)
    
    c.execute('''
        SELECT payload, COUNT(*) as count 
        FROM logs 
        WHERE event_type IN ('HTTP_LOGIN', 'TELNET_LOGIN')
        GROUP BY payload 
        ORDER BY count DESC 
        LIMIT 15
    ''')
    
    credentials = Counter()
    for row in c.fetchall():
        payload = row[0]
        count = row[1]
        
        # Parse username/password
        parts = {}
        for item in payload.split('&'):
            if '=' in item:
                k, v = item.split('=', 1)
                parts[k] = v
        
        username = parts.get('username', 'N/A')
        password = parts.get('password', 'N/A')
        
        print(f"  {username:<15} / {password:<15} : {count} attempts")
    
    # 5. Saldırı Zaman Dağılımı
    print("\n⏰ HOURLY ATTACK DISTRIBUTION (Last 24h)")
    print("-"*40)
    
    c.execute('''
        SELECT strftime('%H', created_at) as hour, COUNT(*) as count
        FROM logs 
        WHERE created_at >= datetime('now', '-24 hours')
        GROUP BY hour
        ORDER BY hour
    ''')
    
    hourly = {f"{i:02d}": 0 for i in range(24)}
    for row in c.fetchall():
        hourly[row[0]] = row[1]
    
    max_count = max(hourly.values()) if hourly.values() else 1
    for hour, count in hourly.items():
        bar_len = int((count / max_count) * 30) if max_count > 0 else 0
        bar = "█" * bar_len
        print(f"{hour}:00 {count:>5} {bar}")
    
    # 6. HTTP Scan Paths
    print("\n🔍 TOP SCANNED PATHS")
    print("-"*40)
    
    c.execute('''
        SELECT payload, COUNT(*) as count 
        FROM logs 
        WHERE event_type = 'HTTP_SCAN'
        GROUP BY payload 
        ORDER BY count DESC 
        LIMIT 10
    ''')
    
    for row in c.fetchall():
        path = row[0].replace('GET ', '')
        print(f"  {path:<40} : {row[1]} times")
    
    # 7. Özet ve Öneriler
    print("\n" + "="*60)
    print("  SECURITY RECOMMENDATIONS")
    print("="*60)
    
    print("""
Based on the observed attack patterns:

1. ✅ DISABLE TELNET - Use SSH with key-based authentication only
2. ✅ CHANGE DEFAULT CREDENTIALS immediately after deployment
3. ✅ IMPLEMENT FAIL2BAN to auto-block brute-force attackers
4. ✅ USE NETWORK SEGMENTATION - Isolate IoT devices
5. ✅ ENABLE LOGGING AND MONITORING for all IoT devices
6. ✅ KEEP FIRMWARE UPDATED to patch known vulnerabilities
7. ✅ DISABLE UNNECESSARY SERVICES (HTTP admin if not needed)
""")
    
    conn.close()

if __name__ == '__main__':
    analyze_logs()
```

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
nmap -sV -p 22,23,80 192.168.100.50

# Hydra brute-force testi
hydra -L users.txt -P passwords.txt 192.168.100.50 ssh
hydra -L users.txt -P passwords.txt 192.168.100.50 telnet

# HTTP login testi
curl -X POST http://192.168.100.50/login \
     -d "username=admin&password=admin"

# Telnet bağlantı testi
telnet 192.168.100.50
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
   - ESP32: 192.168.100.50
   - Kali VM: 192.168.100.10
   - Bu değerleri kendi ağ yapına göre düzenle

3. **İzolasyon kritik**: Honeypot'u asla ana ağında açık bırakma

4. **Demo için**: Tarayıcıda http://192.168.100.10:5000 adresinden dashboard'a eriş

---

Sorularım var mı? Herhangi bir adımda yardım istersen söyle!
