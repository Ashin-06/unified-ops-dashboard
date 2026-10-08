"""Portable configuration shared by the API, collector, and database."""
import json
import os
import secrets
from pathlib import Path

BASE_DIR = Path(os.environ.get('OPS_DATA_DIR', Path(__file__).resolve().parent)).resolve()
CONFIG_PATH = Path(os.environ.get('OPS_CONFIG', BASE_DIR / 'config.json')).resolve()
BASE_DIR.mkdir(parents=True, exist_ok=True)
if not CONFIG_PATH.exists():
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps({'master_api_key': secrets.token_urlsafe(32)}, indent=2), encoding='utf-8')
try:
    USER_CONFIG = json.loads(CONFIG_PATH.read_text(encoding='utf-8'))
except (ValueError, OSError) as exc:
    raise RuntimeError(f'Cannot read configuration at {CONFIG_PATH}: {exc}') from exc
if not isinstance(USER_CONFIG, dict):
    raise ValueError('Configuration must be a JSON object')
if not USER_CONFIG.get('master_api_key') and not os.environ.get('OPS_API_KEY'):
    USER_CONFIG['master_api_key'] = secrets.token_urlsafe(32)
    CONFIG_PATH.write_text(json.dumps(USER_CONFIG, indent=2), encoding='utf-8')
if os.environ.get('OPS_API_KEY'):
    USER_CONFIG['master_api_key'] = os.environ['OPS_API_KEY']

def data_path(value, default):
    path = Path(value or default)
    return path if path.is_absolute() else BASE_DIR / path
