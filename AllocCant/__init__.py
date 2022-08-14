import argparse
from getpass import getuser as whoami

import pypass
import requests
import requests.auth


def main():
    parser = argparse.ArgumentParser()
    parser.set_defaults(
        url='https://alloc.cyber.com.au/services/json.php',
        sess=requests.Session(),
        store=pypass.PasswordStore(),
    )
    args = parser.parse_args()
    args.sess.auth = requests.auth.HTTPBasicAuth(
        username=whoami(),
        password=args.store.get_decrypted_password(
            f'{whoami()}@cyber.com.au',
            entry=pypass.EntryType.password))


    resp = args.sess.get(
        args.url,
        data={'authenticate': True,
              'username': whoami(),
              'password': args.store.get_decrypted_password(
                  f'{whoami()}@alloc.cyber.com.au',
                  entry=pypass.EntryType.password),
              })
    resp.raise_for_status()
    print(resp.text)
