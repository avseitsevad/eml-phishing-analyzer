# populate_ti_database.py
import sqlite3
from datetime import datetime
from pathlib import Path

# IOC данные
ioc_data = {
    'domains': [
        # Email 1
        'primakovreadings.info', '2025primakovreadings.info', 'primakovreadings2025.info',
        'ads-stream-api-v2.global.ssl.fastly.net', 'fast-telemetry-api.global.ssl.fastly.net',
        # Email 2
        'rz-261.ru',
        # Email 3
        'min-prom.ru', 'mail.min-prom.ru', 'superjoke.ru', 'forum-drom.ru', 
        'cloud-telegram.ru', 'about-sport.ru', 'minobnauki.ru',
        # Email 4
        'vniir.nl', 'almaz-antey-info.online', 'antey-almaz-info.site', 
        'almaz-anley.site', 'autotificate.com',
        # Email 5
        'albertn.ru', 'praestol.su', 'armstroy42.ru', 'lieri.ru', 
        'abc92.ru', 'toolhaus.ru', 'mysterykamchatka.ru', 'clack.su',
        # Email 6
        'servepics.com', 'misecure.com', 'theworkpc.com',
        # Email 7
        'alliance-s.ru', '4ad74aab.biz.ua', '4ad74aab.cfd', '4ad74aab.xyz',
        '4ad74aab.fun', '4ad74aab.store', '4ad74aab.online',
        # Email 8
        'mail-rambler.ru', 'qqqoffice.ru', 'qqoffice.ru', 'user-mail.ru',
        'email-office.ru', 'bazalt-vpk.site', 'qinformer.ru', 'zakypky-ru-info.website',
        'center-mail.ru',
        # Email 9
        'impact-dns.ru', 'rt-inforu.ru', 'minpromtorg.msk.ru', 'minprontorg-gov.ru',
        'auntastic.com', 'indoorvisions.org', 'trailtastic.org', 'winetwist.org',
        'sumbetray.org', 'studiomisery.org', 'forbidfashion.org', 'circlewinds.org',
        'crystalarticles.org', 'eliteheirs.org', 'astrarepository.com', 'bft-holding.com',
        'axenixservices.com', 'archive-linux.com', 'pestctlsvc.host', 'it-enterprise.cloud',
        'sajjooapnindazoa.com', 'sopranosolutions.com', 'kranzlerbar.com',
        # Email 10
        'aterogytatus.com', 'extensiens.com', 'vpk-trans.icu'
    ],
    'ips': [
        # Email 1
        '185.81.114.15',
        # Email 2
        '188.114.97.3', '188.114.96.3',
        # Email 3
        '193.124.33.207', '5.8.11.119',
        # Email 4
        '92.63.173.61', '92.63.173.57', '31.172.74.174',
        # Email 5
        '31.207.76.246', '45.141.233.44', '83.220.168.36',
        # Email 6
        '196.251.66.118', '185.185.70.85',
        # Email 7
        '178.236.253.132', '185.159.131.10',
        # Email 8
        '109.107.176.232', '176.123.0.55', '212.224.112.42',
        # Email 9
        '81.30.105.154', '89.110.88.155', '109.107.189.187', '193.124.44.63',
        '195.19.93.162', '213.171.4.200', '94.242.51.73', '89.110.98.26',
        # Email 10
        '185.249.198.173', '192.71.218.100'
    ]
}

def populate_ti_database(db_path=None):
    """Добавление IOC в базу threat intelligence"""
    if db_path is None:
        # Определяем путь относительно расположения скрипта
        script_dir = Path(__file__).parent
        db_path = script_dir / 'ti_database.db'
    
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    timestamp = datetime.now().isoformat()
    
    # Добавление доменов
    for domain in ioc_data['domains']:
        cursor.execute('''
            INSERT OR IGNORE INTO malicious_domains (domain, threat_type, date_added, source)
            VALUES (?, ?, ?, ?)
        ''', (domain, 'phishing', timestamp, 'manual'))
    
    # Добавление IP-адресов
    for ip in ioc_data['ips']:
        cursor.execute('''
            INSERT OR IGNORE INTO malicious_ips (ip, threat_type, date_added, source)
            VALUES (?, ?, ?, ?)
        ''', (ip, 'phishing', timestamp, 'manual'))
    
    conn.commit()
    
    print(f"Added domains: {len(ioc_data['domains'])}")
    print(f"Added IP addresses: {len(ioc_data['ips'])}")
    
    conn.close()

if __name__ == '__main__':
    populate_ti_database()