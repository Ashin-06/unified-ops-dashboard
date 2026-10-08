import sqlite3
from unittest.mock import patch
import main
from database import db, DatabaseManager

def test_failed_read_is_not_empty_result(client,auth):
    with patch.object(db,'query',side_effect=sqlite3.OperationalError('secret disk detail')):
        response=client.get('/api/soc/detections',headers=auth)
    assert response.status_code==503
    assert 'secret' not in response.text
    assert response.headers['cache-control']=='no-store'

def test_completed_mutation_reports_audit_failure(client,auth):
    with patch.object(main.store,'audit',side_effect=sqlite3.OperationalError('disk full')):
        response=client.post('/api/auth/check',headers=auth)
    assert response.status_code==200
    assert response.headers['x-audit-status']=='failed'

def test_denial_remains_denied_when_audit_storage_fails(client):
    with patch.object(main.store,'audit',side_effect=sqlite3.OperationalError('disk full')):
        response=client.post('/api/auth/check')
    assert response.status_code==401
    assert response.headers['cache-control']=='no-store'

def test_database_query_does_not_swallow_errors():
    with patch('database.connection',side_effect=sqlite3.OperationalError('failed')):
        try:db.query('SELECT 1')
        except sqlite3.OperationalError:pass
        else:raise AssertionError('Read errors must propagate')
