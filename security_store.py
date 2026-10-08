"""Normalized security events and local incident workflow; no vendor response actions."""
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Literal
from pydantic import BaseModel, Field, ConfigDict
from database import db, connection

SOURCES = ('local', 'anomaly', 'detection')
SEVERITIES = {'informational': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

def now():
    return datetime.now(timezone.utc).isoformat()

class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra='forbid')
    source: Literal['local','anomaly','detection']
    external_id: str = Field(min_length=1, max_length=512)
    title: str = Field(min_length=1, max_length=2000)
    asset: str = Field(default='unknown', max_length=255)
    severity: Literal['informational','low','medium','high','critical'] = 'medium'
    category: str = Field(default='security', max_length=100)
    occurred_at: str
    description: str = Field(default='', max_length=8000)
    vendor_status: str = Field(default='unknown', max_length=100)

def event(source, external_id, title, asset='unknown', level='medium', occurred=None, description='', status='observed', category='performance'):
    return SecurityEvent(source=source, external_id=str(external_id), title=title,
        asset=asset or 'unknown', severity=level, occurred_at=occurred or now(),
        description=description or '', vendor_status=status, category=category)

class IncidentUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    status: Literal['new','investigating','resolved'] | None = None
    owner: str | None = Field(default=None, max_length=100)
    note: str | None = Field(default=None, max_length=4000)

class UserCreate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(min_length=3, max_length=80, pattern=r'^[a-zA-Z0-9_.@-]+$')
    role: Literal['viewer','analyst','admin']

class SecurityStore:
    def __init__(self, path):
        self.path = path
        with connection(path) as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS soc_incidents (
                    id INTEGER PRIMARY KEY, title TEXT NOT NULL, asset TEXT NOT NULL, category TEXT NOT NULL,
                    severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'new', owner TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS soc_events (
                    id INTEGER PRIMARY KEY, incident_id INTEGER NOT NULL, source TEXT NOT NULL,
                    external_id TEXT NOT NULL, title TEXT NOT NULL, asset TEXT NOT NULL, severity TEXT NOT NULL,
                    category TEXT NOT NULL, occurred_at TEXT NOT NULL, description TEXT NOT NULL,
                    vendor_status TEXT NOT NULL, ingested_at TEXT NOT NULL, UNIQUE(source, external_id));
                CREATE TABLE IF NOT EXISTS soc_timeline (
                    id INTEGER PRIMARY KEY, incident_id INTEGER NOT NULL, timestamp TEXT NOT NULL,
                    actor TEXT NOT NULL, kind TEXT NOT NULL, message TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS soc_users (
                    id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, role TEXT NOT NULL,
                    token_hash TEXT UNIQUE NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS soc_audit (
                    id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, actor TEXT NOT NULL, role TEXT NOT NULL,
                    action TEXT NOT NULL, target TEXT NOT NULL, outcome INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS soc_sync (
                    source TEXT PRIMARY KEY, last_attempt TEXT, last_success TEXT, status TEXT, message TEXT,
                    imported INTEGER NOT NULL DEFAULT 0, truncated INTEGER NOT NULL DEFAULT 0);
                CREATE INDEX IF NOT EXISTS soc_events_incident ON soc_events(incident_id);
                CREATE INDEX IF NOT EXISTS soc_incident_status ON soc_incidents(status, updated_at);
            ''')

    def ingest(self, events):
        inserted = updated = 0
        stamp = now()
        with connection(self.path, timeout=10) as conn:
            conn.execute('BEGIN IMMEDIATE')
            for event in events:
                row = conn.execute('SELECT id, incident_id FROM soc_events WHERE source=? AND external_id=?', (event.source,event.external_id)).fetchone()
                if row:
                    # Polling the same ID updates evidence without inflating event counts.
                    conn.execute('UPDATE soc_events SET title=?,severity=?,description=?,vendor_status=? WHERE id=?', (event.title,event.severity,event.description,event.vendor_status,row[0]))
                    incident = row[1]
                    updated += 1
                else:
                    cutoff = (datetime.now(timezone.utc)-timedelta(hours=24)).isoformat()
                    group = None
                    if event.asset != 'unknown':
                        group = conn.execute("SELECT id FROM soc_incidents WHERE asset=? AND category=? AND status!='resolved' AND created_at>=? ORDER BY id DESC LIMIT 1", (event.asset,event.category,cutoff)).fetchone()
                    if group:
                        incident = group[0]
                    else:
                        cursor = conn.execute('INSERT INTO soc_incidents(title,asset,category,severity,created_at,updated_at) VALUES(?,?,?,?,?,?)', (event.title,event.asset,event.category,event.severity,stamp,stamp))
                        incident = cursor.lastrowid
                    conn.execute('INSERT INTO soc_events(incident_id,source,external_id,title,asset,severity,category,occurred_at,description,vendor_status,ingested_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)', (incident,event.source,event.external_id,event.title,event.asset,event.severity,event.category,event.occurred_at,event.description,event.vendor_status,stamp))
                    conn.execute('INSERT INTO soc_timeline(incident_id,timestamp,actor,kind,message) VALUES(?,?,?,?,?)', (incident,stamp,event.source,'event',event.title))
                    inserted += 1
                levels = [r[0] for r in conn.execute('SELECT severity FROM soc_events WHERE incident_id=?',(incident,))]
                severity = max(levels, key=lambda x:SEVERITIES.get(x,0))
                conn.execute('UPDATE soc_incidents SET severity=? WHERE id=?',(severity,incident))
                if not row:
                    conn.execute('UPDATE soc_incidents SET updated_at=? WHERE id=?',(stamp,incident))
        return {'inserted':inserted,'updated':updated}

    def incidents(self, status=None, query='', limit=200):
        with connection(self.path) as conn:
            conn.row_factory = __import__('sqlite3').Row
            rows = conn.execute('''SELECT i.*, COUNT(e.id) AS event_count, GROUP_CONCAT(DISTINCT e.source) AS sources
                FROM soc_incidents i LEFT JOIN soc_events e ON e.incident_id=i.id
                WHERE (? IS NULL OR i.status=?) AND (i.title LIKE ? ESCAPE '\\' OR i.asset LIKE ? ESCAPE '\\')
                GROUP BY i.id ORDER BY i.updated_at DESC, i.id DESC LIMIT ?''', (status,status,'%'+query.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%','%'+query.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%',limit)).fetchall()
            return [dict(r) for r in rows]

    def detail(self, incident_id):
        with connection(self.path) as conn:
            conn.row_factory=__import__('sqlite3').Row
            incident=conn.execute('SELECT * FROM soc_incidents WHERE id=?',(incident_id,)).fetchone()
            if not incident:return None
            return {'incident':dict(incident),'events':[dict(r) for r in conn.execute('SELECT * FROM soc_events WHERE incident_id=? ORDER BY occurred_at DESC LIMIT 500',(incident_id,))], 'timeline':[dict(r) for r in conn.execute('SELECT * FROM soc_timeline WHERE incident_id=? ORDER BY id DESC LIMIT 500',(incident_id,))]}

    def update(self, incident_id, change, actor):
        with connection(self.path,timeout=10) as conn:
            conn.execute('BEGIN IMMEDIATE')
            row=conn.execute('SELECT status,owner FROM soc_incidents WHERE id=?',(incident_id,)).fetchone()
            if not row:return False
            messages=[]
            if change.status is not None and change.status!=row[0]:
                conn.execute('UPDATE soc_incidents SET status=? WHERE id=?',(change.status,incident_id))
                messages.append(f'Status: {row[0]} → {change.status}')
            if change.owner is not None and change.owner!=row[1]:
                conn.execute('UPDATE soc_incidents SET owner=? WHERE id=?',(change.owner,incident_id))
                messages.append(f'Owner: {change.owner or "unassigned"}')
            if change.note and change.note.strip():messages.append(change.note.strip())
            for message in messages:
                conn.execute('INSERT INTO soc_timeline(incident_id,timestamp,actor,kind,message) VALUES(?,?,?,?,?)',(incident_id,now(),actor,'update',message))
            if messages:conn.execute('UPDATE soc_incidents SET updated_at=? WHERE id=?',(now(),incident_id))
            return True

    def record_sync(self, source, status, message, imported=0, truncated=False):
        stamp=now()
        with connection(self.path) as conn:
            conn.execute('''INSERT INTO soc_sync(source,last_attempt,last_success,status,message,imported,truncated) VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(source) DO UPDATE SET last_attempt=excluded.last_attempt,
                last_success=CASE WHEN excluded.status='connected' THEN excluded.last_success ELSE soc_sync.last_success END,
                status=excluded.status,message=excluded.message,imported=excluded.imported,truncated=excluded.truncated''', (source,stamp,stamp if status=='connected' else None,status,message,imported,int(truncated)))

    def sync_states(self):
        with connection(self.path) as conn:
            conn.row_factory=__import__('sqlite3').Row
            return {r['source']:dict(r) for r in conn.execute('SELECT * FROM soc_sync')}

    def create_user(self, name, role):
        if name.lower()=='bootstrap-admin':raise ValueError('Reserved user name')
        token=secrets.token_urlsafe(40)
        with connection(self.path) as conn:
            cursor=conn.execute('INSERT INTO soc_users(name,role,token_hash,created_at) VALUES(?,?,?,?)',(name,role,hashlib.sha256(token.encode()).hexdigest(),now()))
            return {'id':cursor.lastrowid,'name':name,'role':role,'api_key':token}

    def user_for_token(self, token):
        with connection(self.path) as conn:
            row=conn.execute('SELECT id,name,role FROM soc_users WHERE token_hash=? AND enabled=1',(hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
            return {'id':row[0],'name':row[1],'role':row[2]} if row else None

    def users(self):
        with connection(self.path) as conn:
            conn.row_factory=__import__('sqlite3').Row
            return [dict(r) for r in conn.execute('SELECT id,name,role,enabled,created_at FROM soc_users ORDER BY id')]

    def revoke(self, user_id):
        with connection(self.path) as conn:
            return conn.execute('UPDATE soc_users SET enabled=0 WHERE id=?',(user_id,)).rowcount>0

    def audit(self, actor, role, action, target, outcome):
        with connection(self.path) as conn:
            conn.execute('INSERT INTO soc_audit(timestamp,actor,role,action,target,outcome) VALUES(?,?,?,?,?,?)',(now(),actor,role,action,target,outcome))

    def audits(self):
        with connection(self.path) as conn:
            conn.row_factory=__import__('sqlite3').Row
            return [dict(r) for r in conn.execute('SELECT * FROM soc_audit ORDER BY id DESC LIMIT 500')]

store=SecurityStore(db.path)
