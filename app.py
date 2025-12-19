#!/usr/bin/env python3
"""
IoT Honeypot Dashboard
SENG 484 - Ethical Hacking and Countermeasures
TED University - Team 06
"""

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from datetime import datetime
import os
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'honeypot-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Log dizini ve veritabanı yolu yapılandırması
LOG_DIR = 'logs'
DB_PATH = os.path.join(LOG_DIR, 'honeypot.db')
os.makedirs(LOG_DIR, exist_ok=True)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Veritabanını ve gerekli tabloları oluşturur"""
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        event_type TEXT,
        source_ip TEXT,
        payload TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')
    # Hızlı sorgulama için indeksler oluşturulur
    c.execute('CREATE INDEX IF NOT EXISTS idx_ip ON logs(source_ip)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_type ON logs(event_type)')
    conn.commit()
    conn.close()

def save_log(data):
    """Gelen log verisini veritabanına kaydeder"""
    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT INTO logs (timestamp, event_type, source_ip, payload) VALUES (?, ?, ?, ?)',
              (data.get('timestamp', ''), data.get('type', ''), data.get('source_ip', ''), data.get('payload', '')))
    conn.commit()
    conn.close()

def get_stats():
    """Dashboard için istatistiksel verileri toplar"""
    conn = get_db()
    c = conn.cursor()
    stats = {}
    
    # Toplam olay sayısı
    c.execute('SELECT COUNT(*) FROM logs')
    stats['total_events'] = c.fetchone()[0]
    
    # Benzersiz saldırgan IP sayısı
    c.execute('SELECT COUNT(DISTINCT source_ip) FROM logs')
    stats['unique_ips'] = c.fetchone()[0]
    
    # Olay türlerine göre dağılım
    c.execute('SELECT event_type, COUNT(*) FROM logs GROUP BY event_type')
    stats['event_types'] = dict(c.fetchall())
    
    # En çok saldırı yapan ilk 10 IP
    c.execute('SELECT source_ip, COUNT(*) as cnt FROM logs GROUP BY source_ip ORDER BY cnt DESC LIMIT 10')
    stats['top_ips'] = [{'ip': r[0], 'count': r[1]} for r in c.fetchall()]
    
    # Son 24 saatlik aktivite dağılımı
    c.execute("SELECT strftime('%H', created_at) as h, COUNT(*) FROM logs WHERE created_at >= datetime('now', '-24 hours') GROUP BY h")
    stats['hourly_activity'] = dict(c.fetchall())
    
    # En çok denenen kullanıcı adı ve şifreler
    c.execute("SELECT payload, COUNT(*) as cnt FROM logs WHERE event_type LIKE '%LOGIN%' GROUP BY payload ORDER BY cnt DESC LIMIT 10")
    stats['top_credentials'] = [{'payload': r[0], 'count': r[1]} for r in c.fetchall()]
    
    conn.close()
    return stats

def get_recent_logs(limit=50):
    """En son kaydedilen logları getirir"""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id, timestamp, event_type, source_ip, payload, created_at FROM logs ORDER BY id DESC LIMIT ?', (limit,))
    logs = [{'id': r[0], 'timestamp': r[1], 'type': r[2], 'source_ip': r[3], 'payload': r[4], 'created_at': r[5]} for r in c.fetchall()]
    conn.close()
    return logs

# --- HTTP ROUTES ---

@app.route('/')
def dashboard():
    """Dashboard ana sayfası"""
    return render_template('dashboard.html')

@app.route('/log', methods=['POST'])
def receive_log():
    """ESP32'den gelen logları kabul eden endpoint"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
            
        save_log(data)
        # Yeni log geldiğinde dashboard'a gerçek zamanlı bildirim gönderir
        socketio.emit('new_log', data)
        print(f"[LOG] {data.get('type')}: {data.get('source_ip')} - {data.get('payload')}")
        return jsonify({'status': 'ok'}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/api/stats')
def api_stats():
    return jsonify(get_stats())

@app.route('/api/logs')
def api_logs():
    limit = request.args.get('limit', 50, type=int)
    return jsonify(get_recent_logs(limit))

# --- SOCKET.IO EVENTS ---

@socketio.on('connect')
def handle_connect():
    """Dashboard bağlandığında güncel istatistikleri gönderir"""
    emit('stats_update', get_stats())

@socketio.on('request_stats')
def handle_stats():
    emit('stats_update', get_stats())

if __name__ == '__main__':
    init_db()
    print("\n" + "="*50)
    print("  IoT Honeypot Dashboard")
    print("  Sunucu adresi: http://0.0.0.0:5000")
    print("="*50 + "\n")
    
    # async_mode='gevent' veya 'threading' ekleyerek çakışmayı önlüyoruz
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
