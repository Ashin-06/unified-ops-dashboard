#!/usr/bin/env python3
"""
Server Monitor v15.24 - Database Manager
========================================
- FIX: Enable WAL mode to prevent "database is locked" errors.
- FIX: Batch 'requests' inserts to handle high-speed packet sniffing.
"""

import sqlite3
import threading
import logging
import time
import json
import os
from pathlib import Path
from datetime import datetime

# --- Configuration ---
if os.name == 'nt':
    BASE_DIR = Path(os.getenv('PROGRAMDATA', 'C:/')) / 'ServerMonitor'
else:
    BASE_DIR = Path('/opt/server_monitor')

DEFAULT_DB_PATH = BASE_DIR / 'Data' / 'monitor.db'
CONFIG_PATH = BASE_DIR / 'config.json'

try:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, 'r') as f:
            config = json.load(f)
        DB_PATH = Path(config.get("database", DEFAULT_DB_PATH))
        # Increase batch size for better performance
        BATCH_ENABLED = config.get('performance', {}).get('batch_db_writes', True)
        BATCH_SIZE = config.get('performance', {}).get('batch_size', 50) 
    else:
        raise FileNotFoundError
except Exception:
    DB_PATH = DEFAULT_DB_PATH
    BATCH_ENABLED = True
    BATCH_SIZE = 50

# Ensure directory exists
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("ServerMonitor")

class DatabaseManager:
    def __init__(self, path: str):
        self.path = path
        self.batch_buffer = []
        self.batch_lock = threading.Lock()
        self.batch_enabled = BATCH_ENABLED
        self.batch_size = BATCH_SIZE
        self._init_db()
        
        # Start background writer if batching is enabled
        if self.batch_enabled:
            self._start_batch_writer()

    def _init_db(self):
        """Initializes the database schema and runs migrations."""
        try:
            sqlite3.register_adapter(datetime, lambda d: d.isoformat())
        except Exception:
            pass
            
        with sqlite3.connect(self.path, check_same_thread=False) as conn:
            # Enable Write-Ahead Logging (WAL) for concurrency
            conn.execute('PRAGMA journal_mode=WAL;')
            # Increase cache size
            conn.execute('PRAGMA cache_size=-64000;') 
            
            cur = conn.cursor()
            
            # 1. System Metrics Table
            cur.execute('''
                CREATE TABLE IF NOT EXISTS system_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%f', 'NOW')),
                    hostname TEXT DEFAULT 'localhost',
                    cpu_percent REAL,
                    memory_percent REAL,
                    disk_read INTEGER,
                    disk_write INTEGER,
                    network_sent INTEGER,
                    network_recv INTEGER,
                    request_count INTEGER DEFAULT 0,
                    disk_read_rate REAL DEFAULT 0,
                    disk_write_rate REAL DEFAULT 0,
                    network_sent_rate REAL DEFAULT 0,
                    network_recv_rate REAL DEFAULT 0
                )
            ''')
            
            # Migrations for Rate Columns
            migrations = [
                "ALTER TABLE system_metrics ADD COLUMN disk_read_rate REAL DEFAULT 0",
                "ALTER TABLE system_metrics ADD COLUMN disk_write_rate REAL DEFAULT 0",
                "ALTER TABLE system_metrics ADD COLUMN network_sent_rate REAL DEFAULT 0",
                "ALTER TABLE system_metrics ADD COLUMN network_recv_rate REAL DEFAULT 0",
                "ALTER TABLE system_metrics ADD COLUMN disk_usage REAL DEFAULT 0",
                "ALTER TABLE system_metrics ADD COLUMN uptime INTEGER DEFAULT 0",
                "ALTER TABLE system_metrics ADD COLUMN total_connections INTEGER DEFAULT 0"
            ]
            for sql in migrations:
                try:
                    cur.execute(sql)
                    logger.info(f"✅ Migration executed: {sql.split('ADD COLUMN')[1].split()[0]}")
                except sqlite3.OperationalError as e:
                    if "duplicate column" not in str(e).lower():
                        logger.warning(f"Migration warning: {e}")

            # 2. Requests Table
            cur.execute('''
                CREATE TABLE IF NOT EXISTS requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
                    hostname TEXT DEFAULT 'localhost',
                    method TEXT,
                    path TEXT,
                    status_code INTEGER,
                    response_time REAL,
                    size INTEGER,
                    src_ip TEXT,
                    dst_port INTEGER,
                    protocol TEXT DEFAULT 'HTTP'
                )
            ''')
            try:
                cur.execute("ALTER TABLE requests ADD COLUMN protocol TEXT DEFAULT 'HTTP'")
            except sqlite3.OperationalError: pass

            # 3. Alerts Table
            cur.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT DEFAULT (STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')),
                    hostname TEXT DEFAULT 'localhost',
                    level TEXT,
                    message TEXT,
                    category TEXT DEFAULT 'system'
                )
            ''')
            
            # 4. Agents Table
            cur.execute('''
                CREATE TABLE IF NOT EXISTS agents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT UNIQUE NOT NULL,
                    url TEXT NOT NULL,
                    api_key TEXT NOT NULL
                )
            ''')
            
            # Indexes
            cur.execute('CREATE INDEX IF NOT EXISTS idx_metrics_ts ON system_metrics(timestamp)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_metrics_host ON system_metrics(hostname)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_req_ts ON requests(timestamp)')
            cur.execute('CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp)')
            
            conn.commit()

    def _start_batch_writer(self):
        """Background thread to flush metrics to disk."""
        def writer():
            while True:
                time.sleep(2) # Write every 2 seconds
                self._flush_batch()
        
        t = threading.Thread(target=writer, daemon=True, name="DBBatchWriter")
        t.start()

    def _flush_batch(self):
        """Writes buffered queries to the DB."""
        with self.batch_lock:
            if not self.batch_buffer:
                return
            
            buffer_copy = self.batch_buffer[:]
            self.batch_buffer.clear()
            
        try:
            with sqlite3.connect(self.path, check_same_thread=False) as conn:
                # Ensure WAL is on for this connection too
                conn.execute('PRAGMA journal_mode=WAL;') 
                for sql, params in buffer_copy:
                    conn.execute(sql, params)
                conn.commit()
        except Exception as e:
            logger.error(f"Batch write failed: {e}")

    def execute(self, sql: str, params=()):
        """Executes a write operation."""
        # Batch high-volume inserts (Metrics AND Requests)
        # This is the key fix for the packet sniffer lock
        sql_upper = sql.strip().upper()
        if self.batch_enabled and (
            sql_upper.startswith('INSERT INTO SYSTEM_METRICS') or 
            sql_upper.startswith('INSERT INTO REQUESTS')
        ):
            flush_now = False
            with self.batch_lock:
                self.batch_buffer.append((sql, params))
                if len(self.batch_buffer) >= self.batch_size:
                    # Trigger an immediate flush to prevent unbounded memory growth
                    flush_now = True
            if flush_now:
                self._flush_batch()
        else:
            # Immediate write for alerts, agents, etc.
            try:
                with sqlite3.connect(self.path, check_same_thread=False, timeout=10.0) as conn:
                    conn.execute(sql, params)
                    conn.commit()
            except Exception as e:
                logger.error(f"DB Write Error: {e}")

    def query(self, sql: str, params=()):
        """Executes a read operation."""
        try:
            with sqlite3.connect(self.path, check_same_thread=False, timeout=10.0) as conn:
                cur = conn.cursor()
                cur.execute(sql, params)
                return cur.fetchall()
        except Exception as e:
            logger.error(f"DB Query Error: {e}")
            return []

    def vacuum(self):
        try:
            with sqlite3.connect(self.path, check_same_thread=False) as conn:
                conn.execute('VACUUM')
        except Exception as e:
            logger.error(f"Vacuum error: {e}")

# Create singleton instance
db = DatabaseManager(str(DB_PATH))