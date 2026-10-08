"""Explainable, bounded rules over locally observed traffic; no response actions."""
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pydantic import BaseModel, Field
from database import db, connection
from security_store import event

RULES={
 'http_denials':{'name':'Repeated HTTP access denials','threshold':10,'severity':'medium','description':'401/403 responses from one observed source on a host. Can also indicate an expired session or misconfigured client.'},
 'port_fanout':{'name':'Many destination ports','threshold':20,'severity':'high','description':'Distinct destination ports contacted by one observed source on a host. Can also indicate an authorized scanner or shared network address.'},
 'server_errors':{'name':'HTTP server error burst','threshold':20,'severity':'medium','description':'500–599 responses from one observed source on a host. Indicates service failure, not proof of an attack.'}}
with connection(db.path) as conn:
 conn.execute('CREATE TABLE IF NOT EXISTS detection_rules (id TEXT PRIMARY KEY, enabled INTEGER NOT NULL, threshold INTEGER NOT NULL)')

class RuleUpdate(BaseModel):
 enabled:bool
 threshold:int=Field(ge=2,le=10000)

def rules():
 settings={r[0]:r[1:] for r in db.query('SELECT id,enabled,threshold FROM detection_rules')}
 return [{'id':key,**value,'enabled':bool(settings.get(key,(1,value['threshold']))[0]),'threshold':settings.get(key,(1,value['threshold']))[1]} for key,value in RULES.items()]

def save_rule(key,change):
 with connection(db.path) as conn:
  conn.execute('INSERT INTO detection_rules(id,enabled,threshold) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled,threshold=excluded.threshold',(key,int(change.enabled),change.threshold))

def evaluate():
 end=datetime.now(timezone.utc);start=end-timedelta(minutes=15)
 rows=db.query('SELECT id,timestamp,hostname,src_ip,dst_port,status_code FROM requests WHERE julianday(timestamp)>=julianday(?) AND julianday(timestamp)<=julianday(?) ORDER BY id DESC LIMIT 10001',(start.isoformat(),end.isoformat()))
 capped=len(rows)>10000;rows=rows[:10000]
 groups=defaultdict(list)
 for row in rows:
  if row[2] and row[3]:groups[(row[2],row[3])].append(row)
 findings=[];configured=rules()
 for rule in configured:
  if not rule['enabled']:continue
  for (host,source),records in groups.items():
   if rule['id']=='port_fanout':
    evidence=[r for r in records if r[4] is not None and 1<=r[4]<=65535]
    count=len({r[4] for r in evidence});unit='distinct destination ports'
   else:
    evidence=[r for r in records if r[5] is not None and (r[5] in (401,403) if rule['id']=='http_denials' else 500<=r[5]<=599)]
    count=len(evidence);unit='responses'
   if count<rule['threshold']:continue
   # Evidence-based bucket keeps identical observations stable across repeated runs.
   def utc_time(record):
    value=datetime.fromisoformat(str(record[1]).replace('Z','+00:00'))
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
   evidence.sort(key=utc_time,reverse=True)
   parsed=utc_time(evidence[0]);newest=parsed.isoformat()
   key=hashlib.sha256(json.dumps([rule['id'],host,source,int(parsed.timestamp()//900)]).encode()).hexdigest()
   findings.append({'id':key,'rule_id':rule['id'],'title':rule['name'],'hostname':host,'source_ip':source,'severity':rule['severity'],'count':count,'threshold':rule['threshold'],'unit':unit,'timestamp':newest,'evidence_ids':[r[0] for r in evidence[:20]],'explanation':f"Observed {count} {unit} in the last 15 minutes; threshold {rule['threshold']}. "+rule['description']})
 return {'rules':configured,'findings':findings,'records_checked':len(rows),'capped':capped,'window_start':start.isoformat(),'window_end':end.isoformat(),'coverage':'Latest 10,000 traffic records in 15 minutes. HTTP rules require real response status codes. Missing traffic is not an all-clear.'}

def detection_events():
 data=evaluate()
 return [event('detection',r['id'],r['title'],r['hostname'],r['severity'],r['timestamp'],r['explanation']+f" Source: {r['source_ip']}. Evidence record IDs: "+', '.join(map(str,r['evidence_ids'])),category='detection') for r in data['findings']],data['capped']
