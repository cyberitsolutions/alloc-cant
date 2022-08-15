import argparse
import getpass

import pypass
import requests
import requests.auth


def main():
    args = parse_args()
    login(args)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.set_defaults(
        sess=requests.Session(),
        store=pypass.PasswordStore(),
    )
    args = parser.parse_args()
    args.sess.auth = requests.auth.HTTPBasicAuth(
        username=getpass.getuser(),
        password=args.store.get_decrypted_password(
            f'{getpass.getuser()}@cyber.com.au',
            entry=pypass.EntryType.password))
    return args


def login(args):
    # Get "alloc_test_cookie=alloc_test_cookie".
    # The POST will send it, and get back "alloc_cookie=deadbeefdeadbeefdeadbeefdeadbeef"
    # This avoids needing to get and pass ?sessID=X around forever.
    login_url = 'https://alloc.cyber.com.au/login/login.php'
    resp = args.sess.get(login_url)
    resp.raise_for_status()
    resp = args.sess.post(
        login_url,
        data={
            'login': 'login',   # login.php requires this!
            'username': getpass.getuser(),
            'password': args.store.get_decrypted_password(
                f'{getpass.getuser()}@alloc.cyber.com.au',
                entry=pypass.EntryType.password)})
    resp.raise_for_status()
    # If login worked, we get redirected to /home/home.php.
    if resp.url == login_url:
        raise RuntimeError('bad username/password?')
    return resp                 # DEBUGGING
