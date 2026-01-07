"""
Threat Intelligence Module
Управление локальной базой индикаторов компрометации
"""

import sqlite3
from collections import OrderedDict
from pathlib import Path
from typing import Dict, Optional, List, Any

from .utils import normalize_domain_for_ti


class ThreatIntelligence:
    """
    Класс для работы с локальной базой индикаторов компрометации (URLhaus, OpenPhish)
    Управляет подключением к SQLite и проверкой репутации
    """
    
    def __init__(self, db_path: str, max_cache_size: int = 10000):
        """
        Инициализация подключения к базе данных
        
        Args:
            db_path: путь к файлу SQLite базы данных
            max_cache_size: максимальный размер кэша (по умолчанию 10000 записей)
        """
        self.db_path = db_path
        self.conn = None
        self.cache = OrderedDict()  # LRU кэш для результатов проверок
        self.max_cache_size = max_cache_size
        self._connect()
        self.create_database_schema()
    
    def _connect(self):
        """Создание подключения к базе данных"""
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
        
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
    
    def create_database_schema(self):
        """Создание схемы базы данных"""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS malicious_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                threat_type TEXT,
                date_added TEXT,
                source TEXT DEFAULT 'URLhaus'
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_malicious_domain ON malicious_domains(domain)
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS malicious_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                threat_type TEXT,
                date_added TEXT,
                source TEXT DEFAULT 'URLhaus'
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_ip ON malicious_ips(ip)
        """)
        
        self.conn.commit()
    
    def check_domain_reputation(self, domain: str) -> dict:
        """Проверка домена в локальной базе индикаторов"""
        if not domain:
            return {'found': False, 'threat_type': 'clean', 'source': None}
        
        normalized_domain = normalize_domain_for_ti(domain)
        if not normalized_domain:
            normalized_domain = domain.lower()
        
        cache_key = f"domain:{normalized_domain}"
        if cache_key in self.cache:
            self.cache.move_to_end(cache_key)
            return self.cache[cache_key]
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT threat_type, source 
                FROM malicious_domains 
                WHERE domain = ?
            """, (normalized_domain,))
            
            result = cursor.fetchone()
            if result:
                reputation = {
                    'found': True,
                    'threat_type': result['threat_type'] or 'malicious',
                    'source': result['source'] or 'URLhaus'
                }
            else:
                reputation = {'found': False, 'threat_type': 'clean', 'source': None}
            
            # LRU кэш: удаляем самую старую запись при превышении лимита
            if len(self.cache) >= self.max_cache_size:
                self.cache.popitem(last=False)  # Удаляем самую старую запись 
            
            self.cache[cache_key] = reputation
            return reputation
        except sqlite3.Error:
            return {'found': False, 'threat_type': 'clean', 'source': None}
    
    def check_ip_reputation(self, ip_address: str) -> dict:
        """Проверка IP-адреса в локальной базе индикаторов"""
        if not ip_address:
            return {'found': False, 'threat_type': 'clean', 'source': None}
        
        cache_key = f"ip:{ip_address}"
        if cache_key in self.cache:
            self.cache.move_to_end(cache_key)
            return self.cache[cache_key]
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT threat_type, source 
                FROM malicious_ips 
                WHERE ip = ?
            """, (ip_address,))
            
            result = cursor.fetchone()
            if result:
                reputation = {
                    'found': True,
                    'threat_type': result['threat_type'] or 'malicious',
                    'source': result['source'] or 'URLhaus'
                }
            else:
                reputation = {'found': False, 'threat_type': 'clean', 'source': None}
            
            if len(self.cache) >= self.max_cache_size:
                self.cache.popitem(last=False)
            
            self.cache[cache_key] = reputation
            return reputation
        except sqlite3.Error:
            return {'found': False, 'threat_type': 'clean', 'source': None}
    
    def check_domains_batch(self, domains: List[str]) -> Dict[str, Any]:
        """
        Пакетная проверка доменов для оптимизации производительности
        
        Args:
            domains: список доменов для проверки
            
        Returns:
            dict: {
                'malicious_domains': list[str],
                'domain_in_urlhaus': bool,
                'domain_in_openphish': bool
            }
        """
        if not domains:
            return {
                'malicious_domains': [],
                'domain_in_urlhaus': False,
                'domain_in_openphish': False
            }
        
        malicious_domains = []
        domain_in_urlhaus = False
        domain_in_openphish = False
        
        normalized = []
        for domain in domains:
            if not domain:
                continue
            normalized_domain = normalize_domain_for_ti(domain)
            if normalized_domain:
                normalized.append((domain, normalized_domain))
        
        if not normalized:
            return {
                'malicious_domains': [],
                'domain_in_urlhaus': False,
                'domain_in_openphish': False
            }
        
        try:
            cursor = self.conn.cursor()
            normalized_list = [nd for _, nd in normalized]
            placeholders = ','.join(['?'] * len(normalized_list))
            cursor.execute(f"""
                SELECT domain, threat_type, source 
                FROM malicious_domains 
                WHERE domain IN ({placeholders})
            """, normalized_list)
            
            found_domains_info = {}
            for row in cursor.fetchall():
                found_domains_info[row['domain']] = {
                    'threat_type': row['threat_type'],
                    'source': row['source']
                }
        except sqlite3.Error:
            return {
                'malicious_domains': [],
                'domain_in_urlhaus': False,
                'domain_in_openphish': False
            }
        
        for orig_domain, norm_domain in normalized:
            if norm_domain in found_domains_info:
                if orig_domain not in malicious_domains:
                    malicious_domains.append(orig_domain)
                
                source = found_domains_info[norm_domain]['source'] or 'URLhaus'
                source_lower = source.lower()
                
                if 'urlhaus' in source_lower:
                    domain_in_urlhaus = True
                if 'openphish' in source_lower:
                    domain_in_openphish = True
                
                cache_key = f"domain:{norm_domain}"
                if cache_key not in self.cache:
                    reputation = {
                        'found': True,
                        'threat_type': found_domains_info[norm_domain]['threat_type'] or 'malicious',
                        'source': source
                    }
                    if len(self.cache) >= self.max_cache_size:
                        self.cache.popitem(last=False)
                    self.cache[cache_key] = reputation
                else:
                    self.cache.move_to_end(cache_key)
        
        return {
            'malicious_domains': malicious_domains,
            'domain_in_urlhaus': domain_in_urlhaus,
            'domain_in_openphish': domain_in_openphish
        }
    
    def check_reputation(self, domains: List[str], ips: List[str]) -> Dict[str, Any]:
        """
        Главная функция для RuleEngine
        
        Args:
            domains: список доменов из parsed_email['domains']
            ips: список IP из parsed_email['ips']
            
        Returns:
            dict для RuleEngine с полями:
            - malicious_domains: list[str]
            - malicious_ips: list[str]
            - domain_in_urlhaus: bool
            - domain_in_openphish: bool
            - ip_in_blacklist: bool
        """
        domains = domains or []
        ips = ips or []
        
        if not isinstance(domains, list):
            domains = []
        if not isinstance(ips, list):
            ips = []
        
        domains_result = self.check_domains_batch(domains)
        
        malicious_ips = []
        ip_in_blacklist = False
        
        for ip in ips:
            if not ip:
                continue
            result = self.check_ip_reputation(ip)
            if result.get('found'):
                if ip not in malicious_ips:
                    malicious_ips.append(ip)
                ip_in_blacklist = True
        
        return {
            'malicious_domains': domains_result['malicious_domains'],
            'malicious_ips': malicious_ips,
            'domain_in_urlhaus': domains_result['domain_in_urlhaus'],
            'domain_in_openphish': domains_result['domain_in_openphish'],
            'ip_in_blacklist': ip_in_blacklist
        }
    
    def cache_results(self, key: str, result: dict):
        """
        Кэширование результатов проверок
        
        Args:
            key: ключ кэша
            result: результат проверки
        """
        self.cache[key] = result
    
    def clear_cache(self):
        """Очистка кэша результатов"""
        self.cache.clear()
    
    def close(self):
        """Закрытие подключения к базе данных"""
        if self.conn:
            self.conn.close()
            self.conn = None