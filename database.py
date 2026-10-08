#!/usr/bin/env python3
"""SQLite storage with bounded, retryable write batches."""

import sqlite3
import threading
import logging
import time
import json
import os
from pathlib import Path
from datetime import datetime

# --- Configuration ---
from settings import BASE_DIR, CONFIG_PATH, USER_CONFIG, data_path
DB_PATH = data_path(USER_CONFIG.get('database'), 'Data/monitor.db')
BATCH_ENABLED = USER_CONFIG.get('performance', {}).get('batch_db_writes', True)
BATCH_SIZE = max(1, int(USER_CONFIG.get('performance', {}).get('batch_size', 50)))

# Ensure directory exists
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("ServerMonitor")

from contextlib import contextmanager

@contextmanager
def connection(*args, **kwargs):
    conn = sqlite3.connect(*args, **kwargs)
    try:
        with conn:
            yield conn
    finally:
        conn.close()


class DatabaseManager:
    def __init__(self, path: str):
        self.path = path
        self.batch_buffer = []
        self.batch_lock = threading.Lock()
        self.flush_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.batch_enabled = BATCH_ENABLED
        self.batch_size = BATCH_SIZE
        self.last_write_error = None
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
            
        with connection(self.path, check_same_thread=False) as conn:
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
                    logger.info(f" Migration executed: {sql.split('ADD COLUMN')[1].split()[0]}")
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
        if hasattr(self, 'writer_thread') and self.writer_thread.is_alive():
            return
        self.stop_event.clear()
        def writer():
            while not self.stop_event.wait(2):
                self._flush_batch()
        
        t = threading.Thread(target=writer, daemon=True, name="DBBatchWriter")
        self.writer_thread = t
        t.start()

    def close(self):
        self.stop_event.set()
        if hasattr(self, 'writer_thread'):
            self.writer_thread.join(timeout=12)
        self._flush_batch()

    def _flush_batch(self):
        """Keep failed transactions queued, preserving order for the next retry."""
        with self.flush_lock:
            with self.batch_lock:
                buffer_copy = self.batch_buffer[:]
                self.batch_buffer.clear()
            if not buffer_copy:
                return
            try:
                with connection(self.path, timeout=10.0) as conn:
                    for sql, params in buffer_copy:
                        conn.execute(sql, params)
                self.last_write_error = None
            except sqlite3.Error as exc:
                self.last_write_error = str(exc)
                with self.batch_lock:
                    self.batch_buffer[0:0] = buffer_copy
                logger.exception('Batch write failed; retained for retry')

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
                if len(self.batch_buffer) >= 10000:
                    raise RuntimeError('Database write queue is full; storage needs attention')
                self.batch_buffer.append((sql, params))
                if len(self.batch_buffer) >= self.batch_size:
                    # Trigger an immediate flush to prevent unbounded memory growth
                    flush_now = True
            if flush_now:
                self._flush_batch()
        else:
            # Immediate write for alerts, agents, etc.
            try:
                with connection(self.path, check_same_thread=False, timeout=10.0) as conn:
                    conn.execute(sql, params)
                    conn.commit()
            except Exception as e:
                logger.error(f"DB Write Error: {e}")
                raise

    def execute_many(self, sql, rows):
        """Commit all rows atomically; never acknowledge a partially saved upload."""
        with connection(self.path, timeout=10.0) as conn:
            conn.executemany(sql, rows)

    def health(self):
        with connection(self.path, timeout=1.0) as conn:
            conn.execute('SELECT 1 FROM system_metrics LIMIT 1').fetchall()
        with self.batch_lock:
            pending = len(self.batch_buffer)
        return {'healthy': self.last_write_error is None, 'pending_writes': pending}

    def query(self, sql: str, params=()):
        """Executes a read operation."""
        try:
            with connection(self.path, check_same_thread=False, timeout=10.0) as conn:
                cur = conn.cursor()
                cur.execute(sql, params)
                return cur.fetchall()
        except Exception as e:
            logger.error(f"DB Query Error: {e}")
            raise

    def vacuum(self):
        try:
            with connection(self.path, check_same_thread=False) as conn:
                conn.execute('VACUUM')
        except Exception as e:
            logger.error(f"Vacuum error: {e}")

# Create singleton instance
db = DatabaseManager(str(DB_PATH))