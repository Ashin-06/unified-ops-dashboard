import httpx, json, sys, os

# read config.json
root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
conf_path = os.path.join(root, 'config.json')
conf = json.load(open(conf_path,'r'))

wcfg = conf.get('integrations', {}).get('wazuh', {})
zcfg = conf.get('integrations', {}).get('zabbix', {})

print('Wazuh config:', wcfg)
print('Zabbix config:', zcfg)

# Wazuh checks
if wcfg.get('wazuh_url'):
    base = wcfg['wazuh_url'].rstrip('/')
    print('\n--- Wazuh checks ---')
    with httpx.Client(verify=wcfg.get('verify_ssl', True), timeout=5.0) as c:
            try:
                r = c.get(base)
                print('GET base', r.status_code)
                print('headers:', r.headers.get('www-authenticate') or r.headers)
                print('body snippet:', r.text[:400])
            except Exception as e:
                print('GET base error:', e)

            try:
                r = c.get(base + '/agents')
                print('GET /agents', r.status_code)
                try:
                    print('json:', r.json())
                except Exception:
                    print('text snippet:', r.text[:400])
            except Exception as e:
                print('GET /agents error:', e)

            auth_paths = ['/security/user/authenticate', '/security/authenticate', '/login']
            for p in auth_paths:
                try:
                    r = c.post(base + p, json={'username': wcfg.get('wazuh_user'), 'password': wcfg.get('wazuh_password')})
                    print('POST', p, r.status_code)
                    try:
                        print('json:', r.json())
                    except Exception:
                        print('text:', r.text[:400])
                except Exception as e:
                    print('POST', p, 'error', e)

# Zabbix checks
if zcfg.get('zabbix_url'):
    base = zcfg['zabbix_url']
    print('\n--- Zabbix checks ---')
    with httpx.Client(verify=zcfg.get('verify_ssl', True), timeout=7.0) as c:
            payload = {'jsonrpc': '2.0', 'method': 'user.login', 'params': {'user': zcfg.get('zabbix_user'), 'password': zcfg.get('zabbix_password')}, 'id': 1}
            try:
                r = c.post(base, json=payload)
                print('POST login', r.status_code)
                try:
                    print('json:', json.dumps(r.json(), indent=2))
                except Exception:
                    print('text:', r.text[:400])
            except Exception as e:
                print('POST login error', e)

            try:
                payload2 = {'jsonrpc': '2.0', 'method': 'host.get', 'params': {'output': ['hostid','host','name']}, 'id': 1}
                r = c.post(base, json=payload2)
                print('POST host.get', r.status_code)
                try:
                    print('json:', json.dumps(r.json(), indent=2))
                except Exception:
                    print('text:', r.text[:400])
            except Exception as e:
                print('POST host.get error', e)
    # end zabbix client context

print('\nDone')
