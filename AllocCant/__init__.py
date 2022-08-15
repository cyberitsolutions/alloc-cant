import argparse
import getpass

import pypass
import requests
import requests.auth


def main():
    args = parse_args()
    shit_login(args)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.set_defaults(
        sess=requests.Session(),
        store=pypass.PasswordStore(),
        # Later this will get {'sessID': 'deadbeefdeadbeefdeadbeefdeadbeef'}
        session_data={'client_version': '1.8.9'}
    )
    args = parser.parse_args()
    args.sess.auth = requests.auth.HTTPBasicAuth(
        username=getpass.getuser(),
        password=args.store.get_decrypted_password(
            f'{getpass.getuser()}@cyber.com.au',
            entry=pypass.EntryType.password))
    return args


# <twb> So I can log into alloc and get a session cookie.
#       But https://github.com/cyberitsolutions/alloc/blob/master/services/json.php#L27 does not support this.
#       It ONLY supports a sessID passed as a parameter to every single request.
# <mike> As much as I hate that so much,
#        it's kinda standard with a lot of REST-like APIs I've worked with.
# <mattcen> No, I think what would be STANDARD would be
#           to send a parameter like that in the HEADER.
#           Sending it in the content/data seems silly.
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


# Add {'sessID': 'deadbeefdeadbeefdeadbeefdeadbeef'} to args.session_data.
def shit_login(args):
    args.url = 'https://alloc.cyber.com.au/services/json.php'
    resp = args.sess.post(
        args.url,
        data={
            'authenticate': True,
            'client_version': '1.8.9',
            'username': getpass.getuser(),
            'password': args.store.get_decrypted_password(
                f'{getpass.getuser()}@alloc.cyber.com.au',
                entry=pypass.EntryType.password)})
    resp.raise_for_status()
    # https://github.com/cyberitsolutions/alloc/blob/master/services/json.php#L23-L24
    if resp.text == 'Your alloc client needs to be upgraded.':
        raise RuntimeError(resp.text)
    args.session_data |= resp.json()
