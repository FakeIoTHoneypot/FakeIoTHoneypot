#!/usr/bin/env python3
"""
Honeypot Log Analyzer
SENG 484 - Ethical Hacking Project
TED University - Team 06

Bu script veritabanındaki logları analiz eder ve rapor üretir.

Kullanım: python3 analyze_logs.py
"""

import sqlite3
import os
from datetime import datetime
from collections import Counter

DB_PATH = 'logs/honeypot.db'

def analyze():
    if not os.path.exists(DB_PATH):
        print("[ERROR] Database not found! Run the dashboard first.")
        return
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    print("\n" + "="*60)
    print("  IoT HONEYPOT - LOG ANALYSIS REPORT")
    print("  Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("="*60)
    
    # Genel istatistikler
    print("\n📊 GENERAL STATISTICS")
    print("-"*40)
    
    c.execute('SELECT COUNT(*) FROM logs')
    total = c.fetchone()[0]
    print(f"Total Events: {total}")
    
    c.execute('SELECT COUNT(DISTINCT source_ip) FROM logs')
    print(f"Unique IPs: {c.fetchone()[0]}")
    
    c.execute('SELECT MIN(created_at), MAX(created_at) FROM logs')
    dates = c.fetchone()
    print(f"Date Range: {dates[0]} to {dates[1]}")
    
    # Event türleri
    print("\n📈 EVENT TYPE BREAKDOWN")
    print("-"*40)
    
    c.execute('SELECT event_type, COUNT(*) as cnt FROM logs GROUP BY event_type ORDER BY cnt DESC')
    for row in c.fetchall():
        pct = (row[1] / total) * 100 if total > 0 else 0
        bar = "█" * int(pct / 2)
        print(f"{row[0]:<25} {row[1]:>6} ({pct:5.1f}%) {bar}")
    
    # Top IP'ler
    print("\n🌍 TOP 10 ATTACKING IPs")
    print("-"*40)
    
    c.execute('SELECT source_ip, COUNT(*) as cnt FROM logs GROUP BY source_ip ORDER BY cnt DESC LIMIT 10')
    print(f"{'IP Address':<18} {'Count':>8}")
    print("-"*30)
    for row in c.fetchall():
        print(f"{row[0]:<18} {row[1]:>8}")
    
    # Top credentials
    print("\n🔑 TOP CREDENTIAL ATTEMPTS")
    print("-"*40)
    
    c.execute("SELECT payload, COUNT(*) as cnt FROM logs WHERE event_type LIKE '%LOGIN%' GROUP BY payload ORDER BY cnt DESC LIMIT 15")
    for row in c.fetchall():
        payload = row[0]
        parts = {}
        for item in payload.split('&'):
            if '=' in item:
                k, v = item.split('=', 1)
                parts[k] = v
        user = parts.get('username', 'N/A')
        pwd = parts.get('password', 'N/A')
        print(f"  {user:<15} / {pwd:<15} : {row[1]} attempts")
    
    # Öneriler
    print("\n" + "="*60)
    print("  SECURITY RECOMMENDATIONS")
    print("="*60)
    print("""
Based on observed attack patterns:

1. ✅ DISABLE TELNET - Use SSH with key-based auth only
2. ✅ CHANGE DEFAULT CREDENTIALS immediately
3. ✅ IMPLEMENT FAIL2BAN for auto-blocking
4. ✅ USE NETWORK SEGMENTATION for IoT devices
5. ✅ ENABLE LOGGING AND MONITORING
6. ✅ KEEP FIRMWARE UPDATED
7. ✅ DISABLE UNNECESSARY SERVICES
""")
    
    conn.close()

if __name__ == '__main__':
    analyze()
