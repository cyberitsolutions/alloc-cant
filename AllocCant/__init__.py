import argparse
import getpass
import pathlib
import subprocess
import sys
import tempfile

import pypass
import requests
import requests.auth
import requests.compat

__version__ = '0.0.0'
__doc__ = """ modern green-field replacement for https://github.com/cyberitsolutions/alloc-cli """


def main():
    args = parse_args()
    shit_login(args)
    # print(shit_request(args, method='get_tfid'))
    # print(shit_request(args, method='get_timeSheetItem_comments', taskID=12345))
    # print(shit_request(args, method='get_task_emails', entity='task', taskID=12345))
    # print(shit_request(args, method='get_list', entity='task', taskID=12345))
    mbox(args, 12345)


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


# Add {'sessID': 'deadbeefdeadbeefdeadbeefdeadbeef'} to args.session_data.
def shit_login(args):
    data = shit_request(args,
        authenticate=True,
        username=getpass.getuser(),
        password=args.store.get_decrypted_password(
            f'{getpass.getuser()}@alloc.cyber.com.au',
            entry=pypass.EntryType.password))
    if 'sessID' not in data:
        raise RuntimeError('Did not get session ID pseudo-cookie?', data)
    args.session_data |= data


def shit_request(args, **kwargs) -> dict:
    resp = args.sess.post(
        'https://alloc.cyber.com.au/services/json.php',
        data=args.session_data | kwargs)
    resp.raise_for_status()
    try:
        return resp.json()
    except requests.compat.json.JSONDecodeError:  # json OR simplejson!
        # https://github.com/cyberitsolutions/alloc/blob/master/services/json.php#L23-L24
        # https://github.com/cyberitsolutions/alloc/blob/master/services/lib/services.inc.php
        # Examples:
        #  * Your alloc client needs to be upgraded.
        #    Happens when 'client_version' is not set.
        #  * <empty string>
        #    Happens when neither 'method' nor 'authenticate' is set.
        #  * Warning: array_diff(): Argument #1 is not an array in /var/www/alloc/services/lib/services.inc.php on line 102
        #    Happens when 'method' is set and 'parameters' is not set.
        #  * Fatal error: Call to private method services::get_current_user() from context '' in /var/www/alloc/services/json.php on line 73
        #    Happens when 'method' is 'get_current_user' (which is 'private function' not 'public function').
        raise RuntimeError('PHP said', resp.text.strip())


# Equivalent of "bts show -m 12345".
def mbox(args, taskID: int):
    mbox_text = shit_request(args, method='get_task_emails', entity='task', taskID=taskID)
    if not sys.stdout.isatty():
        # "alloc mbox >tmp.mbox" or "alloc mbox | grep"
        sys.stdout.write(mbox_text)
    else:
        with tempfile.TemporaryDirectory() as td:
            mbox_path = pathlib.Path(td) / 'tmp.mbox'
            mbox_path.write_text(mbox_text)
            subprocess.check_call(['mutt', '-Rf', mbox_path])
