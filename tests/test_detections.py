from datetime import datetime, timezone, timedelta
from database import db
from security_store import store

def add_traffic(count=20,age=0,status=401):
    stamp=(datetime.now(timezone.utc)-timedelta(minutes=age)).isoformat()
    for i in range(count):
        db.execute('INSERT INTO requests(timestamp,hostname,src_ip,dst_port,status_code) VALUES(?,?,?,?,?)',(stamp,'host-a','192.0.2.1',1000+i,status))
    db._flush_batch()

def test_detection_evidence_dedup_and_tuning(client,auth):
    add_traffic()
    data=client.get('/api/soc/detections',headers=auth).json()
    assert {r['rule_id'] for r in data['findings']}=={'http_denials','port_fanout'}
    assert all(len(r['evidence_ids'])==20 for r in data['findings'])
    first=client.post('/api/soc/sync/detection',headers=auth).json()
    second=client.post('/api/soc/sync/detection',headers=auth).json()
    assert first['inserted']==2 and second['inserted']==0 and second['updated']==2
    assert client.patch('/api/soc/detections/rules/http_denials',headers=auth,json={'enabled':False,'threshold':10}).status_code==200
    assert [r['rule_id'] for r in client.get('/api/soc/detections',headers=auth).json()['findings']]==['port_fanout']
    assert client.patch('/api/soc/detections/rules/port_fanout',headers=auth,json={'enabled':True,'threshold':30}).status_code==200
    assert client.get('/api/soc/detections',headers=auth).json()['findings']==[]

def test_detection_no_data_stale_and_http_coverage(client,auth):
    assert client.get('/api/soc/detections',headers=auth).json()['records_checked']==0
    add_traffic(age=20)
    assert client.get('/api/soc/detections',headers=auth).json()['findings']==[]
    add_traffic(count=10,status=0)
    assert client.get('/api/soc/detections',headers=auth).json()['findings']==[]
    add_traffic(count=20,status=503)
    assert 'server_errors' in {r['rule_id'] for r in client.get('/api/soc/detections',headers=auth).json()['findings']}

def test_detection_permissions_and_validation(client,auth):
    assert client.get('/api/soc/detections').status_code==401
    key=store.create_user('analyst-test','analyst')['api_key'];headers={'Authorization':'Bearer '+key}
    assert client.get('/api/soc/detections',headers=headers).status_code==200
    assert client.post('/api/soc/sync/detection',headers=headers).status_code==200
    assert client.patch('/api/soc/detections/rules/http_denials',headers=headers,json={'enabled':False,'threshold':10}).status_code==403
    assert client.patch('/api/soc/detections/rules/http_denials',headers=auth,json={'enabled':True,'threshold':0}).status_code==422
