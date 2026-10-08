"""Security workspace API: local signals, investigation workflow, and access management."""
import math
import sqlite3
import statistics
import threading
from datetime import datetime, timezone
from fastapi import APIRouter, Request, HTTPException, Query
from database import db
from security_store import store, IncidentUpdate, UserCreate, SOURCES, event

from detections import evaluate, detection_events, RULES, RuleUpdate, save_rule

router=APIRouter(prefix='/api/soc')
locks={source:threading.Lock() for source in SOURCES}


def identity(request):
    return request.state.identity


def analyze_metrics():
    findings=[];warming=[]
    hosts=db.query('SELECT DISTINCT hostname FROM system_metrics ORDER BY hostname LIMIT 50')
    for (host,) in hosts:
        rows=db.query('SELECT timestamp,cpu_percent,memory_percent FROM system_metrics WHERE hostname=? ORDER BY id DESC LIMIT 61',(host,))
        if len(rows)<13:
            warming.append(host);continue
        try:
            stamp=datetime.fromisoformat(rows[0][0].replace('Z','+00:00'))
            if stamp.tzinfo is None:stamp=stamp.replace(tzinfo=timezone.utc)
            age=(datetime.now(timezone.utc)-stamp).total_seconds()
            if not 0<=age<=900:continue
        except (ValueError,TypeError):continue
        for index,metric in [(1,'CPU'),(2,'Memory')]:
            values=[float(r[index]) for r in rows[1:] if r[index] is not None and math.isfinite(float(r[index]))]
            current=float(rows[0][index] or 0)
            if len(values)<12 or not math.isfinite(current):continue
            median=statistics.median(values)
            mad=statistics.median(abs(v-median) for v in values)
            threshold=max(15,3*1.4826*mad)
            if current-median>threshold:
                findings.append({'hostname':host,'metric':metric,'current':round(current,2),'baseline':round(median,2),'deviation':round(current-median,2),'threshold':round(threshold,2),'samples':len(values),'timestamp':rows[0][0], 'explanation':f'{metric} is more than {threshold:.1f} percentage points above its recent median. This is an investigation signal, not a malware verdict.'})
    return {'findings':findings,'warming_up':warming,'method':'Median and median absolute deviation over up to 60 prior samples; at least 12 required. Latest sample must be within 15 minutes.','hosts_checked':len(hosts)}


def local_events():
    rows=db.query('SELECT id,timestamp,hostname,level,message,category FROM alerts ORDER BY id DESC LIMIT 500')
    return [event('local',f'{r[0]}:{r[1]}',r[4],r[2],'high' if r[3]=='error' else 'medium',r[1],r[4],'observed',category='performance') for r in rows],len(rows)>=500


def anomaly_events():
    data=analyze_metrics()
    return [event('anomaly',f"{r['hostname']}:{r['metric']}:{r['timestamp']}",f"Unusual {r['metric']} usage",r['hostname'],'medium',r['timestamp'],r['explanation']+f" Current {r['current']}%; baseline {r['baseline']}%.",'observed',category='performance') for r in data['findings']],False


@router.get('/me')
def me(request:Request):
    who=identity(request)
    return {'name':who['name'],'role':who['role']}


@router.post('/sync/{source}')
def sync(source:str):
    if source not in SOURCES:raise HTTPException(404,'Unknown local signal source')
    if not locks[source].acquire(blocking=False):raise HTTPException(409,'Local signals are already being collected')
    try:
        if source=='local':events,truncated=local_events()
        elif source=='anomaly':events,truncated=anomaly_events()
        elif source=='detection':events,truncated=detection_events()
        result=store.ingest(events)
        message='Recent snapshot imported. Result cap reached; older events may be omitted.' if truncated else 'Recent snapshot imported. This is not a full historical backfill.'
        store.record_sync(source,'connected',message,result['inserted'],truncated)
        return {'status':'success',**result,'received':len(events),'truncated':truncated,'message':message}
    except HTTPException:raise
    except Exception:
        store.record_sync(source,'error','Import failed; check local signal data and storage')
        raise HTTPException(502,'Import failed; check local signal data and storage')
    finally:locks[source].release()


@router.get('/incidents')
def incidents(status:str|None=Query(default=None,pattern='^(new|investigating|resolved)$'),q:str=Query('',max_length=200)):
    return store.incidents(status,q)


@router.get('/incidents/{incident_id}')
def incident(incident_id:int):
    result=store.detail(incident_id)
    if result is None:raise HTTPException(404,'Incident not found')
    return result


@router.patch('/incidents/{incident_id}')
def update_incident(incident_id:int,change:IncidentUpdate,request:Request):
    if not store.update(incident_id,change,identity(request)['name']):raise HTTPException(404,'Incident not found')
    return {'status':'success'}


@router.get('/insights')
def insights():return analyze_metrics()


@router.get('/brief')
def operations_brief():
    """A transparent triage aid, not a probability of compromise."""
    rows=store.incidents(limit=2001)
    capped=len(rows)>2000
    rows=rows[:2000]
    active=[r for r in rows if r['status']!='resolved']
    stamp=datetime.now(timezone.utc)
    queue=[]
    for row in active:
        score={'informational':5,'low':15,'medium':35,'high':60,'critical':80}.get(row['severity'],35)
        reasons=[f"{row['severity'].title()} severity: {score} points"]
        if not row['owner']:
            score+=10;reasons.append('Unassigned: +10')
        if row['event_count']>=3:
            score+=5;reasons.append('At least three signals: +5')
        try:
            created=datetime.fromisoformat(row['created_at'])
            if created.tzinfo is None:created=created.replace(tzinfo=timezone.utc)
            age=max(0,(stamp-created).total_seconds()/3600)
        except (ValueError,TypeError):age=0
        if age>=24:
            score+=5;reasons.append('Open for at least 24 hours: +5')
        steps=[]
        if not row['owner']:steps.append('Assign an owner for this investigation.')
        steps.extend(['Compare current resource usage with the baseline on this host.',
                      'Review processes and logs around the first signal.',
                      'Record evidence and verify recovery before resolving.'])
        queue.append({**row,'priority_score':min(100,score),'reasons':reasons,'next_steps':steps,'age_hours':round(age,1)})
    queue.sort(key=lambda r:(-r['priority_score'],r['created_at'],r['id']))
    return {'generated_at':stamp.isoformat(),'scope':'Latest 2,000 incidents; local workflow state only',
            'capped':capped,'open_count':len(active),'unassigned_count':sum(not r['owner'] for r in active),
            'affected_assets':len({r['asset'] for r in active if r['asset']!='unknown'}),
            'resolved_count':len(rows)-len(active),'queue':queue[:50],
            'method':'Severity + assignment gap + repeated signals + incident age, capped at 100. This is a triage order, not a threat probability. Queue shows the top 50 open incidents.'}


@router.get('/users')
def users():return store.users()


@router.post('/users')
def create_user(user:UserCreate):
    try:return store.create_user(user.name,user.role)
    except sqlite3.IntegrityError:raise HTTPException(409,'That user name already exists')
    except ValueError as exc:raise HTTPException(422,str(exc))


@router.delete('/users/{user_id}')
def revoke_user(user_id:int,request:Request):
    if identity(request).get('id')==user_id:raise HTTPException(409,'Use another administrator to revoke your own key')
    if not store.revoke(user_id):raise HTTPException(404,'User not found')
    return {'status':'success'}


@router.get('/audit')
def audit():return store.audits()


@router.get('/detections')
def detection_preview():
    return evaluate()

@router.patch('/detections/rules/{rule_id}')
def tune_detection(rule_id:str,change:RuleUpdate):
    if rule_id not in RULES:raise HTTPException(404,'Unknown detection rule')
    save_rule(rule_id,change)
    return {'status':'success'}
