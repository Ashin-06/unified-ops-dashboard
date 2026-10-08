import sqlite3
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import pytest
import main
from database import db, DatabaseManager
from monitor import monitor
from schemas import PortScanRequest
from wazuh_integration import WazuhAPI
from zabbix_integration import ZabbixAPI

@pytest.mark.parametrize('method,path,payload',[
 ('post','/api/processes/kill',{'pid':999999}),
 ('delete','/api/alerts',None),
 ('post','/api/config/alerts',{'cpu_threshold':80}),
 ('post','/api/security/port-scan',{'target':'127.0.0.1'}),
 ('post','/api/agent/submit',{'hostname':'test'}),
 ('post','/api/agent/submit_requests',[]),
])
def test_mutations_require_auth(client,method,path,payload):
    with patch.object(monitor,'kill_process') as kill:
        assert client.request(method,path,json=payload).status_code == 401
        kill.assert_not_called()

@pytest.mark.parametrize('header',['wrong','Basic abc','Bearer wrong','Bearer a b'])
def test_reject_bad_auth(client,header):
    assert client.post('/api/auth/check',headers={'Authorization':header}).status_code == 401

def test_valid_auth(client,auth):
    assert client.post('/api/auth/check',headers=auth).status_code == 200

def test_placeholder_key_rejected(client):
    with patch.object(main,'CENTRAL_API_KEY','CHANGE_THIS_SECRET_KEY'):
        assert client.post('/api/auth/check',headers={'Authorization':'Bearer CHANGE_THIS_SECRET_KEY'}).status_code == 401

@pytest.mark.parametrize('payload',[{'cpu_threshold':101},{'memory_threshold':-1},{'alert_cooldown_seconds':-1},{'unknown':5}])
def test_alert_settings_validation(client,auth,payload):
    assert client.post('/api/config/alerts',headers=auth,json=payload).status_code == 422

def test_settings_null_does_not_erase_defaults(client,auth):
    before=monitor.get_alert_config().copy()
    assert client.post('/api/config/alerts',headers=auth,json={'cpu_threshold':None}).status_code == 200
    assert monitor.get_alert_config()==before

def test_agent_metrics_roundtrip(client,auth):
    payload={'hostname':'remote-01','cpu_percent':23.4,'memory_percent':61,'disk_usage':42,'network_recv_rate':100,'uptime':123,'total_connections':17}
    assert client.post('/api/agent/submit',headers=auth,json=payload).status_code==200
    db._flush_batch()
    data=monitor.get_system_stats('remote-01')
    assert (data['cpu'],data['disk'],data['total_connections'])==(23.4,42,17)

@pytest.mark.parametrize('payload',[{'hostname':''},{'hostname':'h','cpu_percent':101},{'hostname':'h','uptime':-1},{'hostname':'h','disk_read_rate':'nan'}])
def test_agent_invalid_metrics(client,auth,payload):
    assert client.post('/api/agent/submit',headers=auth,json=payload).status_code==422

@pytest.mark.parametrize('ports',['0','65536','abc','80,','80,'*129+'443'])
def test_port_validation(ports):
    with pytest.raises(ValueError): PortScanRequest(target='localhost',ports=ports)

def test_port_normalization():
    assert PortScanRequest(target='localhost',ports=' 80, 443 ').ports=='80,443'

def test_local_alert_filter():
    for host in [monitor.hostname,'other-host']:
        db.execute('INSERT INTO alerts(hostname,level,message) VALUES(?,?,?)',(host,'warning','test'))
    assert len(monitor.get_alerts())==2
    assert [a['hostname'] for a in monitor.get_alerts(monitor.hostname)]==[monitor.hostname]

def test_history_filters_utc_and_legacy_timestamps():
    now=datetime.now(timezone.utc)
    for time in [now.isoformat(),now.replace(tzinfo=None).isoformat(sep=' '),(now-timedelta(hours=2)).isoformat()]:
        db.execute('INSERT INTO system_metrics(timestamp,hostname,cpu_percent) VALUES(?,?,?)',(time,'history-host',22))
    db._flush_batch()
    result=monitor.get_historical_metrics('10m','history-host')
    assert len(result)==2
    assert all(r['timestamp'].endswith('+00:00') for r in result)

def test_failed_batch_is_retained_and_retried(tmp_path):
    database=DatabaseManager(str(tmp_path/'test.db'))
    database.execute('INSERT INTO system_metrics(hostname,cpu_percent) VALUES (?,?)',('retry-host',12))
    with patch('database.sqlite3.connect',side_effect=sqlite3.OperationalError('locked')):
        database._flush_batch()
    assert len(database.batch_buffer)==1
    database._flush_batch()
    assert database.query('SELECT hostname FROM system_metrics')==[('retry-host',)]
    database.close()

def test_direct_db_failures_propagate():
    with pytest.raises(sqlite3.OperationalError):db.execute('INSERT INTO missing_table VALUES(1)')

@pytest.mark.parametrize('cls,prefix',[(WazuhAPI,'wazuh'),(ZabbixAPI,'zabbix')])
def test_integration_config_names(cls,prefix):
    client=cls({'enabled':False,f'{prefix}_url':'https://example.invalid','username':'operator','password':'test'})
    assert client.user=='operator' and client.password=='test'
    assert not client.enabled and client.verify_ssl

@pytest.mark.parametrize('endpoint',['/api/requests?limit=-1','/api/processes?limit=100000','/api/connections?limit=0'])
def test_list_limit_validation(client,endpoint):
    assert client.get(endpoint).status_code==422

def test_optional_read_auth(client,auth):
    with patch.dict(main.CONFIG,{'require_auth_for_reads':True}):
        assert client.get('/api/servers').status_code==401
        assert client.get('/api/servers',headers=auth).status_code==200
        assert client.get('/').status_code==200

def test_local_assets_and_headers(client):
    page=client.get('/')
    assert page.status_code==200 and '{{ poll_interval_ms }}' not in page.text
    assert page.headers['x-content-type-options']=='nosniff'
    for path in ['dashboard.js','dashboard.css','favicon.svg']:
        assert client.get('/static/'+path).status_code==200

def test_remote_process_schema_and_sort():
    import agent
    class Proc:
        def __init__(self,pid,cpu):self.info={'pid':pid,'name':'test','cpu_percent':cpu,'memory_percent':5,'username':'user'}
        def ppid(self):return 1
    with patch.object(agent.psutil,'process_iter',return_value=[Proc(2,1),Proc(3,25)]):
        data=agent.get_procs()
    assert [p['pid'] for p in data]==[3,2]
    assert data[0]['cpu']==25 and data[0]['memory']==5 and data[0]['ppid']==1
