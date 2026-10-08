import asyncio
import sqlite3
from types import SimpleNamespace
from unittest.mock import Mock, AsyncMock, patch
import httpx
import pytest
import main
from database import db, DatabaseManager
from monitor import monitor


def packet(**overrides):
    return {'timestamp':'2026-10-08T12:00:00+00:00','hostname':'audit-host','dst_port':443,**overrides}

@pytest.mark.parametrize('bad',[{'path':{'nested':True}},{'timestamp':'yesterday'},{'timestamp':'2026-10-08T12:00:00'},{'dst_port':70000},{'size':2**64},{'response_time':'NaN'}])
def test_bad_traffic_never_enters_database(client,auth,bad):
    before=len(db.batch_buffer)
    assert client.post('/api/agent/submit_requests',headers=auth,json=[packet(),packet(**bad)]).status_code==422
    assert db.query('SELECT COUNT(*) FROM requests')[0][0]==0
    assert len(db.batch_buffer)==before
    response=client.post('/api/agent/submit_requests',headers=auth,json=[packet()])
    assert response.status_code==200 and response.json()['saved']==1
    assert db.query('SELECT COUNT(*) FROM requests')[0][0]==1


def test_traffic_batch_size_limit(client,auth):
    assert client.post('/api/agent/submit_requests',headers=auth,json=[packet()]*1001).status_code==422


def test_traffic_storage_error_returns_retryable_status(client,auth):
    with patch.object(db,'execute_many',side_effect=sqlite3.OperationalError('locked')):
        assert client.post('/api/agent/submit_requests',headers=auth,json=[packet()]).status_code==503


def test_batch_transaction_rolls_back(tmp_path):
    database=DatabaseManager(str(tmp_path/'atomic.db'))
    try:
        database.execute('CREATE TABLE atomic_test(value INTEGER CHECK(value>0))')
        with pytest.raises(sqlite3.IntegrityError):
            database.execute_many('INSERT INTO atomic_test VALUES(?)',[(1,),(-1,)])
        assert database.query('SELECT * FROM atomic_test')==[]
    finally:database.close()


def test_agent_retains_failed_uploads_and_removes_only_acknowledged_batch():
    import agent
    agent.REQUEST_BUFFER[:]=[packet()]
    session=Mock()
    session.post.side_effect=httpx.ConnectError('offline')
    with pytest.raises(httpx.ConnectError):agent.flush_request_batch(session)
    assert len(agent.REQUEST_BUFFER)==1
    session.post.side_effect=None
    session.post.return_value.json.return_value={'status':'error'}
    with pytest.raises(RuntimeError):agent.flush_request_batch(session)
    assert len(agent.REQUEST_BUFFER)==1
    session.post.return_value.json.return_value={'status':'success'}
    assert agent.flush_request_batch(session)==1
    assert agent.REQUEST_BUFFER==[]


def test_health_reports_storage_failure(client):
    with patch.object(main.threading,'enumerate',return_value=[SimpleNamespace(name='ResourceMonitor')]), patch.object(db,'health',side_effect=sqlite3.OperationalError('broken')):
        data=client.get('/api/health').json()
    assert data['status']=='degraded' and not data['storage']['healthy']


def test_health_reports_pending_flush_error(client):
    with patch.object(db,'last_write_error','disk full'):
        data=client.get('/api/health').json()
    assert not data['storage']['healthy']


def test_unicode_auth_fails_cleanly():
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        asyncio.run(main.verify_api_key('Bearer \u2603'))
    assert exc.value.status_code==401


def test_cannot_kill_parent_tree_of_monitor():
    fake=Mock();fake.parents.return_value=[SimpleNamespace(pid=987)]
    with patch('monitor.psutil.Process',return_value=fake):
        result=monitor.kill_process(987,True)
    assert result['status']=='error'
    fake.kill.assert_not_called()


def test_cannot_kill_parent_tree_of_agent():
    import agent
    from schemas import KillRequest
    fake=Mock();fake.parents.return_value=[SimpleNamespace(pid=987)]
    with patch.object(agent.psutil,'Process',return_value=fake):
        result=agent.kill_proc(KillRequest(pid=987,kill_tree=True))
    assert result['status']=='error'
    fake.kill.assert_not_called()


def test_agent_stops_workers_on_shutdown():
    import agent
    from fastapi.testclient import TestClient
    finished=__import__('threading').Event()
    def worker():
        agent.STOP_EVENT.wait(5)
        finished.set()
    with patch.object(agent,'push_system_metrics',worker),patch.dict(agent.CONFIG,{'enable_packet_sniffing':False}):
        with TestClient(agent.app):pass
    assert finished.is_set()


def test_remote_fallback_is_labelled(client):
    db.execute('INSERT INTO system_metrics(hostname,cpu_percent,timestamp) VALUES(?,?,?)',('offline',22,'2026-10-08T12:00:00+00:00'))
    db._flush_batch()
    with patch.object(main.agent_client,'proxy_get',new=AsyncMock(return_value={'error':'offline'})):
        data=client.get('/api/stats?hostname=offline').json()
    assert data['source']=='stored' and data['last_seen']=='2026-10-08T12:00:00+00:00'

@pytest.mark.parametrize('status,body',[(404,'{"detail":"Not found"}'),(200,'not json')])
def test_remote_proxy_rejects_error_pages(status,body):
    response=httpx.Response(status,text=body,request=httpx.Request('GET','http://agent/api/stats'))
    with patch.object(main.agent_client,'get_agent',new=AsyncMock(return_value={'url':'http://agent','api_key':'test'})), patch.object(main.agent_client.client,'get',new=AsyncMock(return_value=response)):
        data=asyncio.run(main.agent_client.proxy_get('agent','/api/stats'))
    assert data['status']=='unreachable' and 'error' in data

def test_remote_metrics_raise_host_scoped_alerts(client,auth):
    monitor.alert_cooldown.clear()
    response=client.post('/api/agent/submit',headers=auth,json={'hostname':'hot-agent','cpu_percent':99,'memory_percent':99,'disk_usage':99})
    assert response.status_code==200
    alerts=monitor.get_alerts('hot-agent')
    assert alerts and all(a['hostname']=='hot-agent' for a in alerts)


def test_master_lifecycle_can_restart_cleanly():
    from fastapi.testclient import TestClient
    with patch.object(monitor,'start_background_threads'),patch.object(monitor,'stop_background_threads'):
        for _ in range(2):
            with TestClient(main.app) as client:
                assert not main.agent_client.client.is_closed
                assert db.writer_thread.is_alive()
                assert client.get('/api/servers').status_code==200
            assert main.agent_client.client.is_closed
            assert not db.writer_thread.is_alive()
    db._start_batch_writer()


def test_agent_scanner_handles_dns_failure():
    import agent
    import socket
    from schemas import PortScanRequest
    with patch.object(agent.socket,'gethostbyname',side_effect=socket.gaierror('not found')):
        result=agent.api_port_scan(PortScanRequest(target='missing.invalid'))
    assert result['status']=='error' and result['results']==[]

def test_website_fallback_pages(client):
    response=client.get('/missing-page')
    assert response.status_code==404 and 'Back to Overview' in response.text
    assert client.get('/api/missing-page').json()=={'detail':'Not found'}
    assert 'Disallow: /' in client.get('/robots.txt').text
    assert client.get('/static/workspace.js').status_code==200
    html=client.get('/').text
    assert '<noscript>' in html and 'noindex' in html
