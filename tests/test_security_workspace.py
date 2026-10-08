import json
import pytest
from security_store import store, IncidentUpdate
from security_store import event


def test_deduplication_grouping_and_resolution():
    a=event('local','1','Suspicious activity','host-a','high')
    b=event('anomaly','1','Related activity','host-a','critical')
    assert store.ingest([a,b])['inserted']==2
    rows=store.incidents()
    assert len(rows)==1 and rows[0]['event_count']==2 and rows[0]['severity']=='critical'
    assert store.ingest([a,b])=={'inserted':0,'updated':2}
    assert len(store.detail(rows[0]['id'])['timeline'])==2
    store.update(rows[0]['id'],IncidentUpdate(status='resolved',owner='analyst',note='Reviewed'),'operator')
    store.ingest([event('local','2','New activity','host-a')])
    assert len(store.incidents())==2
    assert len(store.incidents('resolved'))==1
    assert store.incidents(query='%')==[]
    store.ingest([event('local','u1','Unknown'),event('local','u2','Unknown')])
    assert len(store.incidents())==4


def test_roles_revocation_and_audit(client,auth):
    assert client.get('/api/soc/incidents').status_code==401
    user=client.post('/api/soc/users',headers=auth,json={'name':'reader','role':'viewer'}).json()
    key={'Authorization':'Bearer '+user['api_key']}
    assert client.get('/api/soc/incidents',headers=key).status_code==200
    assert client.post('/api/soc/sync/local',headers=key).status_code==403
    assert client.get('/api/soc/users',headers=key).status_code==403
    assert client.post('/api/auth/check',headers=key).json()['role']=='viewer'
    analyst=store.create_user('investigator','analyst')
    analyst_key={'Authorization':'Bearer '+analyst['api_key']}
    assert client.post('/api/soc/sync/local',headers=analyst_key).status_code==200
    assert client.delete('/api/alerts',headers=analyst_key).status_code==403
    store.ingest([event('local','1','Test','host')]);ident=store.incidents()[0]['id']
    assert client.patch(f'/api/soc/incidents/{ident}',headers=analyst_key,json={'note':'Checked'}).status_code==200
    assert store.detail(ident)['timeline'][0]['actor']=='investigator'
    audit=client.get('/api/soc/audit',headers=auth).json()
    assert any(r['actor']=='reader' and r['outcome']==403 for r in audit)
    assert user['api_key'] not in json.dumps(audit)
    assert 'token_hash' not in json.dumps(client.get('/api/soc/users',headers=auth).json())
    assert client.delete('/api/soc/users/'+str(user['id']),headers=auth).status_code==200
    assert client.get('/api/soc/me',headers=key).status_code==401
    assert client.post('/api/soc/sync/cortex',headers=auth).status_code==404
    assert client.post('/api/soc/users',headers=auth,json={'name':'bootstrap-admin','role':'admin'}).status_code==422


def test_anomaly_baseline_and_spike(monkeypatch):
    import security_api
    from datetime import datetime,timezone,timedelta
    stamp=datetime.now(timezone.utc).isoformat()
    rows=[(stamp,80,20)]+[(stamp,20,20)]*12
    monkeypatch.setattr(security_api.db,'query',lambda sql,*a:[('host',)] if 'DISTINCT' in sql else rows)
    data=security_api.analyze_metrics()
    assert len(data['findings'])==1 and data['findings'][0]['metric']=='CPU'
    rows[0]=(stamp,20,20)
    assert security_api.analyze_metrics()['findings']==[]
    rows[0]=((datetime.now(timezone.utc)-timedelta(hours=1)).isoformat(),90,20)
    assert security_api.analyze_metrics()['findings']==[]
    rows[:]=rows[:5]
    assert security_api.analyze_metrics()['warming_up']==['host']


def test_removed_vendor_routes(client,auth):
    assert client.get('/api/soc/connectors',headers=auth).status_code==404
    for source in ['cortex','crowdstrike','defender','trellix','wazuh','zabbix','grafana']:
        assert client.post('/api/soc/sync/'+source,headers=auth).status_code==404
    assert client.post('/api/soc/sync/anomaly',headers=auth).status_code==200


def test_brief_priorities_and_resolution(client,auth):
    store.ingest([event('local','1','High priority','host-a','high'),event('local','2','Low priority','host-b','low')])
    result=client.get('/api/soc/brief',headers=auth).json()
    assert result['open_count']==2 and result['unassigned_count']==2
    assert result['queue'][0]['title']=='High priority'
    assert result['queue'][0]['priority_score']==70
    ident=result['queue'][0]['id']
    store.update(ident,IncidentUpdate(owner='analyst'), 'admin')
    assert client.get('/api/soc/brief',headers=auth).json()['queue'][0]['priority_score']==60
    store.update(ident,IncidentUpdate(status='resolved'), 'admin')
    result=client.get('/api/soc/brief',headers=auth).json()
    assert result['open_count']==1 and result['resolved_count']==1
    assert result['queue'][0]['title']=='Low priority'
    assert client.get('/api/soc/brief').status_code==401
