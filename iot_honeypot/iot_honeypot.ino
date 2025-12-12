/*
 * ESP32 Fake IoT Honeypot
 * SENG 484 - Ethical Hacking and Countermeasures
 * TED University - Team 06
 * 
 * Bu kod ESP32'yi sahte bir IoT cihazı olarak yapılandırır
 * ve tüm bağlantı denemelerini loglar.
 * 
 * Portlar:
 *   - Port 80:  HTTP - Fake login page
 *   - Port 23:  Telnet - Login prompt
 *   - Port 22:  SSH - Banner only
 */

#include <WiFi.h>
#include <WebServer.h>
#include <HTTPClient.h>
#include <SPIFFS.h>
#include <time.h>

// ==========================================
// YAPILANDIRMA - BU DEĞERLERI DÜZENLE!
// ==========================================
const char* WIFI_SSID = "YOUR_WIFI_SSID";           // WiFi adı
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";    // WiFi şifresi

// Kali VM IP adresi (log gönderimi için)
const char* LOG_SERVER = "http://192.168.100.10:5000/log";

// Statik IP ayarları (opsiyonel - uncomment to enable)
// IPAddress local_IP(192, 168, 100, 50);
// IPAddress gateway(192, 168, 100, 1);
// IPAddress subnet(255, 255, 255, 0);

// ==========================================
// SUNUCU TANIMLARI
// ==========================================
WebServer httpServer(80);
WiFiServer telnetServer(23);
WiFiServer sshServer(22);

// ==========================================
// LOG BUFFER
// ==========================================
#define MAX_LOGS 100
String logBuffer[MAX_LOGS];
int logIndex = 0;

// ==========================================
// FONKSIYON PROTOTIPLERI
// ==========================================
void setupWiFi();
void setupServers();
void handleRoot();
void handleLogin();
void handleAdmin();
void handleConfig();
void handleEnv();
void handleNotFound();
void handleTelnet();
void handleSSH();
void logEvent(String eventType, String sourceIP, String payload);
void sendLogToServer(String logEntry);
String getTimestamp();
String escapeJson(String input);

// ==========================================
// SETUP
// ==========================================
void setup() {
    Serial.begin(115200);
    delay(1000);
    
    Serial.println("\n");
    Serial.println("╔════════════════════════════════════════╗");
    Serial.println("║    ESP32 IoT Honeypot v1.0             ║");
    Serial.println("║    SENG 484 - Ethical Hacking          ║");
    Serial.println("╚════════════════════════════════════════╝");
    Serial.println();
    
    // SPIFFS başlat (log backup için)
    if (!SPIFFS.begin(true)) {
        Serial.println("[ERROR] SPIFFS mount failed!");
    } else {
        Serial.println("[OK] SPIFFS mounted successfully");
        
        // Disk kullanımını göster
        Serial.printf("[INFO] SPIFFS Total: %d bytes\n", SPIFFS.totalBytes());
        Serial.printf("[INFO] SPIFFS Used:  %d bytes\n", SPIFFS.usedBytes());
    }
    
    setupWiFi();
    setupServers();
    
    Serial.println("\n╔════════════════════════════════════════╗");
    Serial.println("║    Honeypot is ACTIVE                  ║");
    Serial.println("║    Waiting for connections...          ║");
    Serial.println("╚════════════════════════════════════════╝\n");
}

// ==========================================
// MAIN LOOP
// ==========================================
void loop() {
    httpServer.handleClient();
    handleTelnet();
    handleSSH();
    
    // Her 30 saniyede bir heartbeat
    static unsigned long lastHeartbeat = 0;
    if (millis() - lastHeartbeat > 30000) {
        Serial.printf("[HEARTBEAT] Uptime: %lu sec, Free heap: %d bytes\n", 
                      millis() / 1000, ESP.getFreeHeap());
        lastHeartbeat = millis();
    }
    
    delay(10);
}

// ==========================================
// WiFi KURULUMU
// ==========================================
void setupWiFi() {
    Serial.print("[WiFi] Connecting to ");
    Serial.println(WIFI_SSID);
    
    // Statik IP yapılandır (opsiyonel)
    // WiFi.config(local_IP, gateway, subnet);
    
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    
    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 60) {
        delay(500);
        Serial.print(".");
        attempts++;
    }
    
    Serial.println();
    
    if (WiFi.status() == WL_CONNECTED) {
        Serial.println("[OK] WiFi connected!");
        Serial.print("[INFO] IP Address: ");
        Serial.println(WiFi.localIP());
        Serial.print("[INFO] MAC Address: ");
        Serial.println(WiFi.macAddress());
        Serial.print("[INFO] Signal Strength: ");
        Serial.print(WiFi.RSSI());
        Serial.println(" dBm");
    } else {
        Serial.println("[ERROR] WiFi connection failed!");
        Serial.println("[INFO] Restarting in 10 seconds...");
        delay(10000);
        ESP.restart();
    }
    
    // NTP ile zaman senkronizasyonu
    configTime(3 * 3600, 0, "pool.ntp.org", "time.nist.gov");
    Serial.println("[OK] NTP time sync configured");
}

// ==========================================
// SUNUCU KURULUMU
// ==========================================
void setupServers() {
    // HTTP sunucusu - route'lar
    httpServer.on("/", HTTP_GET, handleRoot);
    httpServer.on("/login", HTTP_POST, handleLogin);
    httpServer.on("/login", HTTP_GET, handleRoot);  // GET login -> ana sayfa
    httpServer.on("/admin", handleAdmin);
    httpServer.on("/admin.php", handleAdmin);
    httpServer.on("/administrator", handleAdmin);
    httpServer.on("/config.php", handleConfig);
    httpServer.on("/wp-config.php", handleConfig);
    httpServer.on("/configuration.php", handleConfig);
    httpServer.on("/.env", handleEnv);
    httpServer.on("/.git/config", handleEnv);
    httpServer.on("/backup.sql", handleEnv);
    httpServer.onNotFound(handleNotFound);
    
    httpServer.begin();
    Serial.println("[OK] HTTP server started on port 80");
    
    // Telnet sunucusu
    telnetServer.begin();
    telnetServer.setNoDelay(true);
    Serial.println("[OK] Telnet server started on port 23");
    
    // SSH banner sunucusu
    sshServer.begin();
    sshServer.setNoDelay(true);
    Serial.println("[OK] SSH banner server started on port 22");
}

// ==========================================
// HTTP İŞLEYİCİLERİ
// ==========================================

// Ana sayfa - IoT login paneli
void handleRoot() {
    String clientIP = httpServer.client().remoteIP().toString();
    logEvent("HTTP_ACCESS", clientIP, "GET /");
    
    String html = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IoT Device - Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .login-container {
            background: #ffffff;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
            width: 360px;
            animation: fadeIn 0.5s ease;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo-icon {
            font-size: 48px;
            margin-bottom: 10px;
        }
        .logo h1 {
            color: #1a1a2e;
            font-size: 22px;
            font-weight: 600;
        }
        .logo .model {
            color: #666;
            font-size: 12px;
            margin-top: 5px;
        }
        .logo .version {
            color: #999;
            font-size: 11px;
            margin-top: 3px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            color: #333;
            font-size: 13px;
            margin-bottom: 6px;
            font-weight: 500;
        }
        input {
            width: 100%;
            padding: 14px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s, box-shadow 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #0066cc;
            box-shadow: 0 0 0 3px rgba(0,102,204,0.1);
        }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #0066cc 0%, #0052a3 100%);
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(0,102,204,0.4);
        }
        button:active {
            transform: translateY(0);
        }
        .footer {
            text-align: center;
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }
        .footer .hint {
            color: #888;
            font-size: 11px;
            margin-bottom: 8px;
        }
        .footer .hint code {
            background: #f5f5f5;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: monospace;
        }
        .footer .copyright {
            color: #aaa;
            font-size: 10px;
        }
        .status {
            display: flex;
            align-items: center;
            justify-content: center;
            margin-top: 10px;
            font-size: 11px;
            color: #28a745;
        }
        .status-dot {
            width: 8px;
            height: 8px;
            background: #28a745;
            border-radius: 50%;
            margin-right: 6px;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <div class="logo-icon">🌐</div>
            <h1>Smart IoT Gateway</h1>
            <p class="model">Model: SGW-2000 Pro</p>
            <p class="version">Firmware v2.1.4 (Build 20241201)</p>
        </div>
        <form action="/login" method="POST">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" placeholder="Enter username" required autocomplete="off">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter password" required>
            </div>
            <button type="submit">Sign In</button>
        </form>
        <div class="footer">
            <p class="hint">Default: <code>admin</code> / <code>admin</code></p>
            <p class="copyright">&copy; 2024 Smart IoT Solutions Ltd.</p>
            <div class="status">
                <span class="status-dot"></span>
                Device Online
            </div>
        </div>
    </div>
</body>
</html>
)rawliteral";
    
    httpServer.send(200, "text/html", html);
}

// Login denemesi işleyicisi
void handleLogin() {
    String clientIP = httpServer.client().remoteIP().toString();
    String username = httpServer.arg("username");
    String password = httpServer.arg("password");
    
    // Payload'ı güvenli hale getir
    username.replace("\"", "\\\"");
    password.replace("\"", "\\\"");
    
    String payload = "username=" + username + "&password=" + password;
    logEvent("HTTP_LOGIN", clientIP, payload);
    
    Serial.printf("[ALERT] Login attempt from %s - user: %s, pass: %s\n", 
                  clientIP.c_str(), username.c_str(), password.c_str());
    
    // Her zaman başarısız göster (honeypot davranışı)
    String html = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Failed</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            color: white;
        }
        .error-box {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            padding: 40px;
            border-radius: 12px;
            text-align: center;
            border: 1px solid rgba(255,68,68,0.3);
            max-width: 400px;
        }
        .error-icon {
            font-size: 64px;
            margin-bottom: 20px;
        }
        h2 {
            color: #ff6b6b;
            margin-bottom: 15px;
        }
        p {
            color: #ccc;
            margin-bottom: 25px;
            line-height: 1.6;
        }
        a {
            display: inline-block;
            padding: 12px 30px;
            background: #0066cc;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            transition: background 0.3s;
        }
        a:hover {
            background: #0052a3;
        }
        .attempts {
            margin-top: 20px;
            font-size: 12px;
            color: #888;
        }
    </style>
</head>
<body>
    <div class="error-box">
        <div class="error-icon">⚠️</div>
        <h2>Authentication Failed</h2>
        <p>The username or password you entered is incorrect.<br>Please check your credentials and try again.</p>
        <a href="/">← Back to Login</a>
        <p class="attempts">Remaining attempts: 2</p>
    </div>
</body>
</html>
)rawliteral";
    
    httpServer.send(401, "text/html", html);
}

// Admin sayfası
void handleAdmin() {
    String clientIP = httpServer.client().remoteIP().toString();
    String path = httpServer.uri();
    logEvent("HTTP_ADMIN_ATTEMPT", clientIP, "GET " + path);
    
    Serial.printf("[SCAN] Admin page probe from %s: %s\n", clientIP.c_str(), path.c_str());
    
    // 401 Unauthorized
    httpServer.send(401, "text/html", 
        "<html><head><title>401 Unauthorized</title></head>"
        "<body><h1>401 Unauthorized</h1>"
        "<p>Authentication required to access this resource.</p>"
        "<hr><address>Apache/2.4.41 (Ubuntu) Server</address></body></html>");
}

// Config dosyaları
void handleConfig() {
    String clientIP = httpServer.client().remoteIP().toString();
    String path = httpServer.uri();
    logEvent("HTTP_CONFIG_PROBE", clientIP, "GET " + path);
    
    Serial.printf("[SCAN] Config file probe from %s: %s\n", clientIP.c_str(), path.c_str());
    
    httpServer.send(403, "text/html",
        "<html><head><title>403 Forbidden</title></head>"
        "<body><h1>403 Forbidden</h1>"
        "<p>You don't have permission to access this resource.</p>"
        "<hr><address>Apache/2.4.41 (Ubuntu) Server</address></body></html>");
}

// .env ve hassas dosyalar
void handleEnv() {
    String clientIP = httpServer.client().remoteIP().toString();
    String path = httpServer.uri();
    logEvent("HTTP_SENSITIVE_PROBE", clientIP, "GET " + path);
    
    Serial.printf("[ALERT] Sensitive file probe from %s: %s\n", clientIP.c_str(), path.c_str());
    
    httpServer.send(404, "text/html",
        "<html><head><title>404 Not Found</title></head>"
        "<body><h1>Not Found</h1>"
        "<p>The requested URL was not found on this server.</p>"
        "<hr><address>Apache/2.4.41 (Ubuntu) Server</address></body></html>");
}

// 404 ve vulnerability tarama denemeleri
void handleNotFound() {
    String clientIP = httpServer.client().remoteIP().toString();
    String path = httpServer.uri();
    String method = (httpServer.method() == HTTP_GET) ? "GET" : "POST";
    
    logEvent("HTTP_SCAN", clientIP, method + " " + path);
    
    Serial.printf("[SCAN] 404 from %s: %s %s\n", clientIP.c_str(), method.c_str(), path.c_str());
    
    httpServer.send(404, "text/html",
        "<html><head><title>404 Not Found</title></head>"
        "<body><h1>Not Found</h1>"
        "<p>The requested URL was not found on this server.</p>"
        "<hr><address>Apache/2.4.41 (Ubuntu) Server</address></body></html>");
}

// ==========================================
// TELNET İŞLEYİCİSİ
// ==========================================
void handleTelnet() {
    WiFiClient client = telnetServer.available();
    
    if (client) {
        String clientIP = client.remoteIP().toString();
        logEvent("TELNET_CONNECT", clientIP, "New connection");
        
        Serial.printf("[TELNET] New connection from %s\n", clientIP.c_str());
        
        // IoT cihazı gibi görünen banner
        client.println("\r\n");
        client.println("*************************************************");
        client.println("*                                               *");
        client.println("*     Smart IoT Gateway - SGW-2000 Pro          *");
        client.println("*     Firmware Version: 2.1.4                   *");
        client.println("*     Build: 20241201-stable                    *");
        client.println("*                                               *");
        client.println("*     WARNING: Unauthorized access prohibited   *");
        client.println("*                                               *");
        client.println("*************************************************");
        client.println("\r\n");
        
        unsigned long timeout = millis() + 60000; // 60 saniye timeout
        int loginAttempts = 0;
        const int maxAttempts = 3;
        
        while (client.connected() && millis() < timeout && loginAttempts < maxAttempts) {
            // Username iste
            client.print("SGW-2000 login: ");
            client.flush();
            
            String username = "";
            unsigned long inputTimeout = millis() + 30000;
            
            while (client.connected() && millis() < inputTimeout) {
                if (client.available()) {
                    char c = client.read();
                    if (c == '\n' || c == '\r') {
                        if (username.length() > 0) break;
                    } else if (c >= 32 && c <= 126) {
                        username += c;
                        client.print(c); // Echo
                    }
                }
                delay(1);
            }
            client.println();
            username.trim();
            
            if (username.length() == 0) continue;
            
            // Password iste
            client.print("Password: ");
            client.flush();
            
            String password = "";
            inputTimeout = millis() + 30000;
            
            while (client.connected() && millis() < inputTimeout) {
                if (client.available()) {
                    char c = client.read();
                    if (c == '\n' || c == '\r') break;
                    else if (c >= 32 && c <= 126) {
                        password += c;
                        // Password için echo yok (güvenlik)
                    }
                }
                delay(1);
            }
            client.println();
            password.trim();
            
            // Credential'ları logla
            String payload = "username=" + username + "&password=" + password;
            logEvent("TELNET_LOGIN", clientIP, payload);
            
            Serial.printf("[TELNET] Login attempt from %s - user: %s, pass: %s\n",
                         clientIP.c_str(), username.c_str(), password.c_str());
            
            // Her zaman başarısız (honeypot)
            delay(1000); // Gerçekçi gecikme
            client.println("\r\nLogin incorrect");
            client.println();
            
            loginAttempts++;
            
            if (loginAttempts < maxAttempts) {
                client.printf("Attempts remaining: %d\r\n\r\n", maxAttempts - loginAttempts);
            }
        }
        
        if (loginAttempts >= maxAttempts) {
            client.println("\r\nToo many failed login attempts.");
            client.println("Connection will be closed.\r\n");
            logEvent("TELNET_BLOCKED", clientIP, "Max attempts reached");
        } else if (millis() >= timeout) {
            client.println("\r\nSession timeout. Goodbye.\r\n");
            logEvent("TELNET_TIMEOUT", clientIP, "Session timeout");
        }
        
        delay(100);
        client.stop();
        
        Serial.printf("[TELNET] Connection from %s closed (%d attempts)\n", 
                     clientIP.c_str(), loginAttempts);
    }
}

// ==========================================
// SSH BANNER İŞLEYİCİSİ
// ==========================================
void handleSSH() {
    WiFiClient client = sshServer.available();
    
    if (client) {
        String clientIP = client.remoteIP().toString();
        logEvent("SSH_CONNECT", clientIP, "SSH banner probe");
        
        Serial.printf("[SSH] Banner probe from %s\n", clientIP.c_str());
        
        // Gerçekçi SSH banner
        client.print("SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n");
        client.flush();
        
        // Kısa süre bekle (gerçek SSH handshake simülasyonu)
        unsigned long start = millis();
        while (client.connected() && millis() - start < 2000) {
            if (client.available()) {
                // Gelen veriyi oku ve logla
                String data = "";
                while (client.available() && data.length() < 256) {
                    data += (char)client.read();
                }
                if (data.length() > 0) {
                    logEvent("SSH_DATA", clientIP, "Received " + String(data.length()) + " bytes");
                }
            }
            delay(10);
        }
        
        client.stop();
    }
}

// ==========================================
// LOGLAMA FONKSİYONLARI
// ==========================================

void logEvent(String eventType, String sourceIP, String payload) {
    String timestamp = getTimestamp();
    
    // Payload'ı escape et
    payload = escapeJson(payload);
    
    // JSON formatında log
    String logEntry = "{";
    logEntry += "\"timestamp\":\"" + timestamp + "\",";
    logEntry += "\"type\":\"" + eventType + "\",";
    logEntry += "\"source_ip\":\"" + sourceIP + "\",";
    logEntry += "\"device_ip\":\"" + WiFi.localIP().toString() + "\",";
    logEntry += "\"payload\":\"" + payload + "\"";
    logEntry += "}";
    
    // Serial'e yazdır
    Serial.println("[LOG] " + logEntry);
    
    // Buffer'a ekle (circular buffer)
    logBuffer[logIndex % MAX_LOGS] = logEntry;
    logIndex++;
    
    // Kali sunucusuna gönder
    sendLogToServer(logEntry);
    
    // SPIFFS'e yaz (backup)
    File logFile = SPIFFS.open("/logs.jsonl", FILE_APPEND);
    if (logFile) {
        logFile.println(logEntry);
        logFile.close();
        
        // Dosya çok büyürse temizle (basit rotation)
        File f = SPIFFS.open("/logs.jsonl", FILE_READ);
        if (f && f.size() > 100000) { // 100KB limit
            f.close();
            SPIFFS.remove("/logs.jsonl");
            Serial.println("[INFO] Log file rotated");
        }
        if (f) f.close();
    }
}

void sendLogToServer(String logEntry) {
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[WARN] WiFi not connected, log not sent");
        return;
    }
    
    HTTPClient http;
    http.begin(LOG_SERVER);
    http.addHeader("Content-Type", "application/json");
    http.setTimeout(5000); // 5 saniye timeout
    
    int httpCode = http.POST(logEntry);
    
    if (httpCode > 0) {
        if (httpCode == HTTP_CODE_OK) {
            // Başarılı
        } else {
            Serial.printf("[HTTP] Log send got code: %d\n", httpCode);
        }
    } else {
        Serial.printf("[HTTP] Log send failed: %s\n", http.errorToString(httpCode).c_str());
    }
    
    http.end();
}

String getTimestamp() {
    struct tm timeinfo;
    if (!getLocalTime(&timeinfo, 1000)) {
        // NTP sync başarısız, uptime kullan
        unsigned long uptime = millis() / 1000;
        char buffer[32];
        snprintf(buffer, sizeof(buffer), "UPTIME-%lu", uptime);
        return String(buffer);
    }
    
    char buffer[30];
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &timeinfo);
    return String(buffer);
}

String escapeJson(String input) {
    String output = "";
    for (unsigned int i = 0; i < input.length(); i++) {
        char c = input.charAt(i);
        switch (c) {
            case '"':  output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\n': output += "\\n";  break;
            case '\r': output += "\\r";  break;
            case '\t': output += "\\t";  break;
            default:
                if (c >= 32 && c <= 126) {
                    output += c;
                }
                break;
        }
    }
    return output;
}
