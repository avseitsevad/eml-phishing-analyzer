"""
Threat Intelligence Module
Управление локальной базой индикаторов компрометации
"""

import sqlite3
import logging
from pathlib import Path
from typing import Dict, Optional, List, Any
import tldextract

# Настройка логирования
logger = logging.getLogger(__name__)


class ThreatIntelligence:
    """
    Класс для работы с локальной базой индикаторов компрометации (URLhaus, OpenPhish)
    Управляет подключением к SQLite и проверкой репутации
    """
    
    def __init__(self, db_path: str):
        """
        Инициализация подключения к базе данных
        
        Args:
            db_path: путь к файлу SQLite базы данных
        """
        self.db_path = db_path
        self.conn = None
        self.cache = {}  # Кэш для результатов проверок
        self._connect()
        self.create_database_schema()
    
    def _connect(self):
        """Создание подключения к базе данных"""
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
        
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        logger.info(f"Подключение к базе данных установлено: {self.db_path}")
    
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
        logger.info("Схема базы данных создана/проверена")
    
    def check_domain_reputation(self, domain: str) -> dict:
        """Проверка домена в локальной базе индикаторов"""
        if not domain:
            return {'found': False, 'threat_type': 'clean', 'source': None}
        
        try:
            extracted = tldextract.extract(domain)
            normalized_domain = f"{extracted.domain}.{extracted.suffix}".lower()
        except Exception:
            normalized_domain = domain.lower()
        
        cache_key = f"domain:{normalized_domain}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
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
        
        self.cache[cache_key] = reputation
        return reputation
    
    def check_ip_reputation(self, ip_address: str) -> dict:
        """Проверка IP-адреса в локальной базе индикаторов"""
        if not ip_address:
            return {'found': False, 'threat_type': 'clean', 'source': None}
        
        cache_key = f"ip:{ip_address}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
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
        
        self.cache[cache_key] = reputation
        return reputation
    
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
            try:
                extracted = tldextract.extract(domain)
                normalized_domain = f"{extracted.domain}.{extracted.suffix}".lower()
                if normalized_domain and normalized_domain != '.':
                    normalized.append((domain, normalized_domain))
            except Exception:
                continue
        
        if not normalized:
            return {
                'malicious_domains': [],
                'domain_in_urlhaus': False,
                'domain_in_openphish': False
            }
        
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
                    self.cache[cache_key] = reputation
        
        return {
            'malicious_domains': malicious_domains,
            'domain_in_urlhaus': domain_in_urlhaus,
            'domain_in_openphish': domain_in_openphish
        }
    
    def check_reputation(self, domains: List[str], ips: List[str]) -> Dict[str, Any]:
        """
        Главная функция для RuleEngine
        
        Args:
            domains: parsed_email['domains']['domains']
            ips: parsed_email['domains']['ips'] + header_analysis['received_ips']
            
        Returns:
            dict для RuleEngine
        """
        # Валидация
        domains = domains or []
        ips = ips or []
        
        if not isinstance(domains, list):
            domains = []
        if not isinstance(ips, list):
            ips = []
        
        # Проверка доменов (пакетная)
        domains_result = self.check_domains_batch(domains)
        
        # Проверка IP
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
        logger.debug("Кэш результатов очищен")
    
    def close(self):
        """Закрытие подключения к базе данных"""
        if self.conn:
            self.conn.close()
            self.conn = None
            logger.info("Подключение к базе данных закрыто")