import os
from pathlib import Path
import tempfile

# Never touch the operator's database or configuration during tests.
_test_dir = tempfile.TemporaryDirectory(prefix='ops-tests-')
os.environ['OPS_DATA_DIR'] = _test_dir.name
os.environ['OPS_API_KEY'] = 'test-only-key-do-not-deploy'

import pytest
from fastapi.testclient import TestClient
import main
from database import db

@pytest.fixture
def client():
    return TestClient(main.app)

@pytest.fixture
def auth():
    return {'Authorization': 'Bearer test-only-key-do-not-deploy'}

@pytest.fixture(autouse=True)
def clean_database():
    db._flush_batch()
    for name in ['detection_rules','soc_timeline','soc_events','soc_incidents','soc_users','soc_audit','soc_sync','alerts', 'system_metrics', 'requests', 'agents']:
        db.execute(f'DELETE FROM {name}')
    yield
    db._flush_batch()


def pytest_sessionfinish(session, exitstatus):
    db.close()
    import logging
    logging.shutdown()
    _test_dir.cleanup()
