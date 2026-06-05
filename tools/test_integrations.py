import sys, os
# Ensure repo root is on path when running from tools/
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
from monitor import wazuh_client, zabbix_client
import json, sys

def test_wazuh():
    print('Wazuh enabled:', getattr(wazuh_client, 'enabled', False))
    try:
        print('Calling wazuh_client.get_agents() ...', flush=True)
        agents = wazuh_client.get_agents()
        print('Wazuh get_agents returned type:', type(agents))
        print(json.dumps(agents if isinstance(agents, (list, dict)) else str(agents), indent=2))
    except Exception as e:
        print('Wazuh error:', e)


def test_zabbix():
    print('Zabbix enabled:', getattr(zabbix_client, 'enabled', False))
    try:
        print('Calling zabbix_client.get_all_hosts() ...', flush=True)
        hosts = zabbix_client.get_all_hosts()
        print('Zabbix get_all_hosts returned type:', type(hosts))
        print(json.dumps(hosts if isinstance(hosts, (list, dict)) else str(hosts), indent=2))
    except Exception as e:
        print('Zabbix error:', e)

if __name__ == '__main__':
    print('--- Testing Integrations ---')
    test_wazuh()
    print('---')
    test_zabbix()
