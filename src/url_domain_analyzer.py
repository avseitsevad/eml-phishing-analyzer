"""
URL&Domain Analyzer Module
Анализирует URL-адреса и домены, извлеченные из email_parser.py:
- Эвристический анализ доменов: длина, TLD
- Детектирование IP-адреса вместо домена в URL
- Обнаружение URL-shorteners
"""

import re
from typing import Dict, List, Optional, Tuple, Any
import tldextract
from urllib.parse import urlparse

from .utils import (
    timing_decorator,
    URL_SHORTENERS,
    IP_PATTERN
)

# Константы для анализа доменов
SUSPICIOUS_TLDS = {
    '.xin', '.win', '.help', '.bond', '.cfd', '.finance',
    '.top', '.xyz', '.icu', '.support', '.vip', '.pro', '.sbs',
    '.site', '.online', '.click', '.tk', '.ml', '.ga', '.cf',
    '.gq', '.club', '.work'
}

LONG_DOMAIN_THRESHOLD = 20

SHORTENER_DOMAINS = set(URL_SHORTENERS)

def is_private_ip(ip: str) -> bool:
    """
    Проверяет, является ли IP-адрес приватным (RFC 1918).
    
    Args:
        ip: IP-адрес в формате 'x.x.x.x'
        
    Returns:
        bool: True если IP приватный
    """
    if not ip or not isinstance(ip, str):
        return False
    
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    
    try:
        first = int(parts[0])
        # 10.0.0.0/8
        if first == 10:
            return True
        
        # 192.168.0.0/16
        if first == 192 and int(parts[1]) == 168:
            return True
        
        # 172.16.0.0/12
        if first == 172:
            second = int(parts[1])
            if 16 <= second <= 31:
                return True
        
        return False
    except (ValueError, IndexError):
        return False


def detect_ip_in_url(url: str) -> Tuple[bool, Optional[str], Dict[str, Any]]:
    """
    Детектирование IP-адреса вместо домена в URL
    
    Args:
        url: URL-адрес
        
    Returns:
        tuple: (найден_IP, IP_адрес, детали)
    """
    matches = IP_PATTERN.findall(url)
    
    if not matches:
        return False, None, {
            'rule': 'ip_in_url',
            'found': False
        }
    
    ip = matches[0]
    
    parts = ip.split('.')
    if len(parts) != 4 or not all(0 <= int(part) <= 255 for part in parts if part.isdigit()):
        return False, None, {
            'rule': 'ip_in_url',
            'found': False,
            'invalid': True
        }
    
    is_private = is_private_ip(ip)
    
    details = {
        'rule': 'ip_in_url',
        'found': True,
        'ip': ip,
        'is_private': is_private
    }
    
    if is_private:
        return False, ip, details
    
    return True, ip, details


def detect_url_shorteners(url: str) -> Tuple[bool, Optional[str], Dict[str, Any]]:
    """
    Обнаружение URL-shorteners
    
    Args:
        url: URL-адрес
        
    Returns:
        tuple: (найден_shortener, домен_shortener, детали)
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        if ':' in domain:
            domain = domain.split(':')[0]
        
        for shortener in SHORTENER_DOMAINS:
            if domain == shortener or domain.endswith(f'.{shortener}'):
                return True, shortener, {
                    'rule': 'url_shortener',
                    'found': True,
                    'shortener': shortener,
                    'domain': domain
                }
        
        return False, None, {
            'rule': 'url_shortener',
            'found': False
        }
    except Exception:
        return False, None, {
            'rule': 'url_shortener',
            'found': False
        }


def is_long_domain(domain: str) -> bool:
    """
    Проверяет, превышает ли домен порог длины.
    """
    return len(domain) > LONG_DOMAIN_THRESHOLD


def is_suspicious_tld(domain: str) -> bool:
    """Проверяет TLD на вхождение в список подозрительных зон"""
    try:
        extracted = tldextract.extract(domain)
        tld = f".{extracted.suffix}" if extracted.suffix else ""
    except Exception:
        parts = domain.split('.')
        tld = f".{parts[-1]}" if len(parts) > 1 else ""
    return tld.lower() in SUSPICIOUS_TLDS


def has_ip_based_url(urls: List[str]) -> bool:
    """
    Проверяет, содержит ли список URL адреса с IP вместо доменного имени.
    """
    for url in urls:
        has_ip, _, _ = detect_ip_in_url(url)
        if has_ip:
            return True
    return False


def has_shortened_url(urls: List[str]) -> bool:
    """
    Проверяет, содержит ли список URL-адреса из известных shortener-сервисов.
    """
    for url in urls:
        has_shortener, _, _ = detect_url_shorteners(url)
        if has_shortener:
            return True
    return False


def _extract_entities(parsed_email_data: Dict[str, Any]) -> Tuple[List[str], List[str], List[str]]:
    """
    Извлекает списки URL, доменов и IP из результата email_parser.parse_email()
    
    Returns:
        tuple: (domains, urls, ips)
    """
    urls = parsed_email_data.get('urls', []) or []
    domains = parsed_email_data.get('domains', []) or []
    ips = parsed_email_data.get('ips', []) or []
    
    if not isinstance(domains, list):
        domains = []
    if not isinstance(urls, list):
        urls = []
    if not isinstance(ips, list):
        ips = []
    
    return domains, urls, ips


@timing_decorator
def analyze_urls_and_domains(parsed_email_data: Dict[str, Any]) -> Dict[str, bool]:
    """
    Анализ URL и доменов
    
    Args:
        parsed_email_data: Результат вызова email_parser.parse_email()
        
    Returns:
        dict: Четыре булевых признака для FeatureExtractor
    """
    domains, urls, ips = _extract_entities(parsed_email_data)

    flags = {
        'has_url_shortener': has_shortened_url(urls),
        'has_long_domain': any(is_long_domain(domain) for domain in domains),
        'has_suspicious_tld': any(is_suspicious_tld(domain) for domain in domains),
        'has_ip_in_url': has_ip_based_url(urls)
    }
    
    return flags
