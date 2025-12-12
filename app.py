#!/usr/bin/env python3
"""
IoT Honeypot Dashboard
SENG 484 - Ethical Hacking and Countermeasures
TED University - Team 06
"""

from flask import Flask, render_template, request, jsonify, Response
from flask_socketio import SocketIO, emit
from datetime import datetime, timedelta
import json
import os
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'honeypot-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

LOG_DIR = 'logs'
DB_PATH = os.path.join(LOG_DIR, 'honeypot.db')
os.makedirs(LOG_DIR, exist_ok=True)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
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
    c.execute('CREATE INDEX IF NOT EXISTS idx_ip ON logs(source_ip)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_type ON logs(event_type)')
    conn.commit()
    conn.close()

def save_log(data):
    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT INTO logs (timestamp, event_type, source_ip, payload) VALUES (?, ?, ?, ?)',
              (data.get('timestamp', ''), data.get('type', ''), data.get('source_ip', ''), data.get('payload', '')))
    conn.commit()
    conn.close()

def get_stats():
    conn = get_db()
    c = conn.cursor()
    stats = {}
    
    c.execute('SELECT COUNT(*) FROM logs')
    stats['total_events'] = c.fetchone()[0]
    
    c.execute('SELECT COUNT(DISTINCT source_ip) FROM logs')
    stats['unique_ips'] = c.fetchone()[0]
    
    c.execute('SELECT event_type, COUNT(*) FROM logs GROUP BY event_type')
    stats['event_types'] = dict(c.fetchall())
    
    c.execute('SELECT source_ip, COUNT(*) as cnt FROM logs GROUP BY source_ip ORDER BY cnt DESC LIMIT 10')
    stats['top_ips'] = [{'ip': r[0], 'count': r[1]} for r in c.fetchall()]
    
    c.execute("SELECT strftime('%H', created_at) as h, COUNT(*) FROM logs WHERE created_at >= datetime('now', '-24 hours') GROUP BY h")
    stats['hourly_activity'] = dict(c.fetchall())
    
    c.execute("SELECT payload, COUNT(*) as cnt FROM logs WHERE event_type LIKE '%LOGIN%' GROUP BY payload ORDER BY cnt DESC LIMIT 10")
    stats['top_credentials'] = [{'payload': r[0], 'count': r[1]} for r in c.fetchall()]
    
    conn.close()
    return stats

def get_recent_logs(limit=50):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id, timestamp, event_type, source_ip, payload, created_at FROM logs ORDER BY id DESC LIMIT ?', (limit,))
    logs = [{'id': r[0], 'timestamp': r[1], 'type': r[2], 'source_ip': r[3], 'payload': r[4], 'created_at': r[5]} for r in c.fetchall()]
    conn.close()
    return logs

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/log', methods=['POST'])
def receive_log():
    try:
        data = request.get_json()
        save_log(data)
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

@socketio.on('connect')
def handle_connect():
    emit('stats_update', get_stats())

@socketio.on('request_stats')
def handle_stats():
    emit('stats_update', get_stats())

if __name__ == '__main__':
    init_db()
    print("\n" + "="*50)
    print("  IoT Honeypot Dashboard")
    print("  http://0.0.0.0:5000")
    print("="*50 + "\n")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
