#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <HTTPClient.h>
#include <SPIFFS.h>

// AP Ayarları (Saldırganların bağlanacağı sahte IoT ağı)
const char* AP_SSID = "TEDU_Camera_System";
const char* AP_PASSWORD = "";

// STA Ayarları (Kali ile iletişim için gerçek modem)
const char* STA_SSID = "YOUR_WIFI_SSID";
const char* STA_PASSWORD = "YOUR_WIFI_PASSWORD";

// Kali VM
const char* KALI_IP = "192.168.1.110";
const int KALI_PORT = 5000;

// AP IP
IPAddress apIP(192, 168, 4, 1);
IPAddress apGateway(192, 168, 4, 1);
IPAddress apSubnet(255, 255, 255, 0);

WebServer http(80);
WiFiServer telnet(23);
WiFiServer ssh(22);
DNSServer dns;

bool staConnected = false;
int httpLogins = 0;
int telnetLogins = 0;
int sshProbes = 0;

void sendLog(String protocol, String srcIP, String user, String pass, String extra) {
    String json = "{\"protocol\":\"" + protocol + "\",\"source_ip\":\"" + srcIP + "\"";
    if (user.length() > 0) json += ",\"username\":\"" + user + "\"";
    if (pass.length() > 0) json += ",\"password\":\"" + pass + "\"";
    if (extra.length() > 0) json += ",\"extra\":\"" + extra + "\"";
    json += ",\"timestamp\":" + String(millis()/1000) + "}";
    
    Serial.println("[LOG] " + json);
    
    File f = SPIFFS.open("/logs.jsonl", FILE_APPEND);
    if (f) { f.println(json); f.close(); }
    
    if (staConnected && WiFi.status() == WL_CONNECTED) {
        HTTPClient client;
        client.begin("http://" + String(KALI_IP) + ":" + String(KALI_PORT) + "/log");
        client.addHeader("Content-Type", "application/json");
        client.setTimeout(3000);
        int code = client.POST(json);
        if (code > 0) Serial.println("[HTTP] Sent to Kali: " + String(code));
        else Serial.println("[HTTP] Failed: " + client.errorToString(code));
        client.end();
    }
}

void handleRoot() {
    String ip = http.client().remoteIP().toString();
    sendLog("http", ip, "", "", "page_access");
    
    String html = R"(
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smart Camera - Login</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{font-family:Arial,sans-serif;background:linear-gradient(135deg,#1e3c72,#2a5298);min-height:100vh;display:flex;justify-content:center;align-items:center;padding:20px}
        .box{background:#fff;border-radius:12px;box-shadow:0 20px 50px rgba(0,0,0,0.3);width:100%;max-width:360px;overflow:hidden}
        .header{background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;padding:25px;text-align:center}
        .header h1{font-size:20px;margin-bottom:5px}
        .header p{font-size:11px;opacity:0.8}
        .status{background:rgba(0,0,0,0.2);padding:8px;display:flex;justify-content:center;align-items:center;gap:6px;font-size:11px}
        .dot{width:8px;height:8px;background:#4ade80;border-radius:50%;animation:blink 2s infinite}
        @keyframes blink{0%,100%{opacity:1}50%{opacity:0.3}}
        .form{padding:25px}
        .form label{display:block;font-size:12px;color:#555;margin-bottom:6px;font-weight:600}
        .form input{width:100%;padding:12px;border:2px solid #e0e0e0;border-radius:8px;font-size:14px;margin-bottom:15px}
        .form input:focus{outline:none;border-color:#667eea}
        .form button{width:100%;padding:14px;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer}
        .footer{background:#f5f5f5;padding:15px;text-align:center;font-size:11px;color:#888}
        .footer code{background:#e0e0e0;padding:2px 6px;border-radius:3px}
    </style>
</head>
<body>
    <div class="box">
        <div class="header">
            <h1>📷 Smart Camera Pro</h1>
            <p>Model: SC-400X | FW: 3.2.1</p>
            <div class="status"><span class="dot"></span>Online</div>
        </div>
        <div class="form">
            <form action="/login" method="POST">
                <label>Username</label>
                <input type="text" name="username" required>
                <label>Password</label>
                <input type="password" name="password" required>
                <button type="submit">Login</button>
            </form>
        </div>
        <div class="footer">Default: <code>admin</code> / <code>admin</code></div>
    </div>
</body>
</html>
)";
    http.send(200, "text/html", html);
}

void handleLogin() {
    String ip = http.client().remoteIP().toString();
    String user = http.arg("username");
    String pass = http.arg("password");
    httpLogins++;
    
    Serial.println("\n========== HTTP LOGIN ==========");
    Serial.println("IP: " + ip);
    Serial.println("User: " + user);
    Serial.println("Pass: " + pass);
    Serial.println("================================\n");
    
    sendLog("http", ip, user, pass, "login_attempt");
    
    String html = R"(
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Failed</title>
    <style>
        body{font-family:Arial,sans-serif;background:linear-gradient(135deg,#1e3c72,#2a5298);min-height:100vh;display:flex;justify-content:center;align-items:center;color:#fff}
        .box{background:rgba(255,255,255,0.1);padding:40px;border-radius:12px;text-align:center;max-width:350px}
        h2{color:#f87171;margin-bottom:15px}
        p{margin-bottom:20px;opacity:0.9}
        a{display:inline-block;padding:12px 25px;background:#fff;color:#1e3c72;text-decoration:none;border-radius:6px;font-weight:600}
    </style>
</head>
<body>
    <div class="box">
        <h2>⚠ Authentication Failed</h2>
        <p>Invalid credentials. Please try again.</p>
        <a href="/">Back</a>
    </div>
</body>
</html>
)";
    http.send(401, "text/html", html);
}

void handleNotFound() {
    String ip = http.client().remoteIP().toString();
    String path = http.uri();
    sendLog("http", ip, "", "", "scan:" + path);
    
    if (path == "/generate_204" || path == "/gen_204" || path == "/hotspot-detect.html" || path == "/ncsi.txt") {
        http.sendHeader("Location", "http://192.168.4.1/");
        http.send(302, "text/html", "");
    } else {
        http.send(404, "text/html", "<h1>404 Not Found</h1>");
    }
}

void handleTelnet() {
    WiFiClient client = telnet.available();
    if (!client) return;
    
    String ip = client.remoteIP().toString();
    sendLog("telnet", ip, "", "", "connect");
    Serial.println("[TELNET] Connection from " + ip);
    
    client.println("\r\nSmart Camera SC-400X");
    client.println("Firmware 3.2.1\r\n");
    
    int attempts = 0;
    unsigned long timeout = millis() + 60000;
    
    while (client.connected() && millis() < timeout && attempts < 3) {
        client.print("login: ");
        String user = "";
        unsigned long inputTimeout = millis() + 20000;
        while (client.connected() && millis() < inputTimeout) {
            if (client.available()) {
                char c = client.read();
                if (c == '\n' || c == '\r') { if (user.length() > 0) break; }
                else if (c >= 32 && c <= 126) { user += c; client.print(c); }
            }
            delay(1);
        }
        client.println();
        if (user.length() == 0) continue;
        
        client.print("Password: ");
        String pass = "";
        inputTimeout = millis() + 20000;
        while (client.connected() && millis() < inputTimeout) {
            if (client.available()) {
                char c = client.read();
                if (c == '\n' || c == '\r') break;
                else if (c >= 32 && c <= 126) pass += c;
            }
            delay(1);
        }
        client.println();
        
        telnetLogins++;
        Serial.println("\n========== TELNET LOGIN ==========");
        Serial.println("IP: " + ip);
        Serial.println("User: " + user);
        Serial.println("Pass: " + pass);
        Serial.println("==================================\n");
        
        sendLog("telnet", ip, user, pass, "login_attempt");
        
        delay(800);
        client.println("Login incorrect\r\n");
        attempts++;
    }
    
    client.println("Connection closed.");
    client.stop();
}

void handleSSH() {
    WiFiClient client = ssh.available();
    if (!client) return;
    
    String ip = client.remoteIP().toString();
    sshProbes++;
    sendLog("ssh", ip, "", "", "banner_probe");
    Serial.println("[SSH] Probe from " + ip);
    
    client.print("SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n");
    delay(1500);
    client.stop();
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    
    Serial.println("\n[ESP32 IoT Honeypot]");
    Serial.println("====================\n");
    
    SPIFFS.begin(true);
    
    WiFi.mode(WIFI_AP_STA);
    
    WiFi.softAPConfig(apIP, apGateway, apSubnet);
    WiFi.softAP(AP_SSID, AP_PASSWORD);
    Serial.println("[AP] SSID: " + String(AP_SSID));
    Serial.println("[AP] IP: " + WiFi.softAPIP().toString());
    
    Serial.print("[STA] Connecting to " + String(STA_SSID));
    WiFi.begin(STA_SSID, STA_PASSWORD);
    int tries = 0;
    while (WiFi.status() != WL_CONNECTED && tries < 30) {
        delay(500);
        Serial.print(".");
        tries++;
    }
    Serial.println();
    
    if (WiFi.status() == WL_CONNECTED) {
        staConnected = true;
        Serial.println("[STA] IP: " + WiFi.localIP().toString());
        configTime(3 * 3600, 0, "pool.ntp.org");
    } else {
        Serial.println("[STA] Failed - logs saved locally only");
    }
    
    dns.start(53, "*", apIP);
    
    http.on("/", handleRoot);
    http.on("/login", HTTP_POST, handleLogin);
    http.onNotFound(handleNotFound);
    http.begin();
    
    telnet.begin();
    ssh.begin();
    
    Serial.println("\n[READY] Honeypot active");
    Serial.println("HTTP: 80 | Telnet: 23 | SSH: 22\n");
}

void loop() {
    dns.processNextRequest();
    http.handleClient();
    handleTelnet();
    handleSSH();
    
    static int lastClients = 0;
    int clients = WiFi.softAPgetStationNum();
    if (clients != lastClients) {
        if (clients > lastClients) {
            Serial.println("\n[!] New device connected to AP");
            sendLog("wifi", "unknown", "", "", "ap_connect");
        }
        lastClients = clients;
    }
    
    static unsigned long lastStats = 0;
    if (millis() - lastStats > 60000) {
        Serial.printf("\n[STATS] Uptime:%lus | Clients:%d | HTTP:%d | Telnet:%d | SSH:%d\n\n",
                      millis()/1000, clients, httpLogins, telnetLogins, sshProbes);
        lastStats = millis();
    }
    
    delay(10);
}