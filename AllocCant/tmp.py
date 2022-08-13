import requests
from requests.auth import HTTPBasicAuth
from os import environ as env
alloc_user = env['ALLOC_USER']
alloc_pass = env['ALLOC_PASS']
http_user = env['ALLOC_HTTP_USER']
http_pass = env['ALLOC_HTTP_PASS']
alloc_url = 'https://alloc.cyber.com.au/services/json.php';
alloc_client_version = '1.8.9'
sess = requests.Session()
sess.auth = HTTPBasicAuth(http_user, http_pass)
# headers = {
#     'User-agent': 'alloc-cli %s' % alloc_user,
# }
auth_args = {
    'authenticate': True,
    'username': alloc_user,
    'password': alloc_pass,
    'client_version': alloc_client_version,
}
r = sess.post(url=alloc_url, # headers=headers, 
              data=auth_args)
r.raise_for_status()
sess_id = r.json()['sessID']
