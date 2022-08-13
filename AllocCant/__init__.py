import argparse
import datetime


import pypass
import requests
import requests.adapters
import requests.packages.urllib3.exceptions
import ssl
import urllib3.poolmanager



def main():
    parser = argparse.ArgumentParser()
    parser.set_defaults(
        url='https://alloc-noauth.cyber.com.au/services/json.php',
        sess=requests.Session(),
        store=pypass.PasswordStore(),
    )
    args = parser.parse_args()

    # FIXME: the old server uses an in-house CA (not Let's Encrypt), and
    #        the old server only supports TLS 1.1.
    #        Tell requests it's OK to allow these things, until an automatic sunset of 1 Jan 2023.
    if datetime.date.today() < datetime.date(year=2023, month=1, day=1):
        # Ignore that the server cert is not signed by a trusted CA.
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        # Ignore that the server doesn't speak TLS 1.2+.
        # FIXME: this is not working.
        #        Is TLS 1.0 actually *compiled out* of Debian 11's OpenSSL?
        class ShitAdapter(requests.adapters.HTTPAdapter):
            def init_poolmanager(self, *args, **kwargs):
                self.poolmanager = urllib3.poolmanager.PoolManager(
                    *args,
                    ssl_version=ssl.PROTOCOL_TLSv1_1,
                    **kwargs)
        args.sess.mount("https://", ShitAdapter(ssl.OP_ALL))

    resp = requests.get(
        args.url,
        data={'authenticate': True,
              'username': args.store.get_decrypted_password('alloc.cyber.com.au', entry=pypass.EntryType.username),
              'password': args.store.get_decrypted_password('alloc.cyber.com.au', entry=pypass.EntryType.password)})
    resp.raise_for_status()
    print(resp.json())
