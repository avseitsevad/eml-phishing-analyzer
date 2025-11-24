"""
URL&Domain Analyzer Module
Анализирует URL-адреса и домены, извлеч енные из email_parser.py:
- Эвристический анализ доменов: длина, TLD
- Детектирование IP-адреса вместо домена в URL
- Обнаружение URL-shorteners
- Выход: эвристические признаки и веса для каждого домена и URL

Примечание: Модуль не извлекает URL/домены/IP, а только анализирует уже извлеченные данные.
Используйте email_parser.py для извлечения данных из email.
"""

import re
import logging
from typing import Dict, List, Optional, Tuple, Any
import tldextract
from urllib.parse import urlparse

from .utils import timing_decorator

# Настройка логирования
logger = logging.getLogger(__name__)

# Списки TLD по категориям
TLD_BLACKLIST = {
    '.xin', '.win', '.help', '.bond', '.cfd', '.finance'
}

TLD_GRAYLIST = {
    '.top', '.xyz', '.icu', '.support', '.vip', '.pro', '.sbs', 
    '.site', '.online', '.click'
}

TLD_WHITELIST = {
    '.com', '.org', '.net', '.edu', '.gov', '.ru', '.рф'
}

# Список URL shorteners
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 
    'cutt.ly', 'rb.gy', 'j.mp', 'tiny.cc', 'short.link',
    'is.gd', 'buff.ly', 'rebrand.ly', 'bitly.com'
}

def is_private_ip(ip: str) -> bool:
    """
    Проверяет, является ли IP-адрес приватным (RFC 1918).
    
    Args:
        ip: IP-адрес в формате 'x.x.x.x'
        
    Returns:
        bool: True если IP приватный
    """
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        # Проверка диапазонов
        if parts[0] == '10':
            return True
        if parts[0] == '192' and parts[1] == '168':
            return True
        if parts[0] == '172' and 16 <= int(parts[1]) <= 31:
            return True
        
        return False
    except (ValueError, IndexError):
        return False


def analyze_domain_length(domain: str) -> Tuple[float, Dict[str, Any]]:
    """
    Эвристический анализ домена: проверка длины.
    
    Правило: Домен длиннее 30 символов — подозрительный
    
    Args:
        domain: Доменное имя
        
    Returns:
        tuple: (вес, детали)
    """
    domain_length = len(domain)
    details = {
        'length': domain_length,
        'rule': 'domain_length'
    }
    
    if domain_length < 25:
        weight = 0.0
        details['level'] = 'normal'
    elif domain_length < 30:
        weight = 0.3
        details['level'] = 'moderate'
    elif domain_length < 40:
        weight = 0.7
        details['level'] = 'suspicious'
    else:
        weight = 1.0
        details['level'] = 'very_suspicious'
    
    return weight, details


def analyze_domain_tld(domain: str) -> Tuple[float, Dict[str, Any]]:
    """
    Эвристический анализ домена: проверка TLD.
    
    Правило: Проверка подозрительных доменных зон
    
    Args:
        domain: Доменное имя
        
    Returns:
        tuple: (вес, детали)
    """
    try:
        extracted = tldextract.extract(domain)
        tld = f".{extracted.suffix}" if extracted.suffix else ""
    except Exception:
        # Fallback: извлечение TLD вручную
        parts = domain.split('.')
        tld = f".{parts[-1]}" if len(parts) > 1 else ""
    
    details = {
        'tld': tld,
        'rule': 'domain_tld'
    }
    
    if tld.lower() in TLD_BLACKLIST:
        weight = 1.0
        details['level'] = 'blacklisted'
        details['category'] = 'blacklist'
    elif tld.lower() in TLD_GRAYLIST:
        weight = 0.5
        details['level'] = 'graylisted'
        details['category'] = 'graylist'
    elif tld.lower() in TLD_WHITELIST:
        weight = 0.0
        details['level'] = 'whitelisted'
        details['category'] = 'whitelist'
    else:
        # Неизвестный TLD - умеренно подозрительно
        weight = 0.3
        details['level'] = 'unknown'
        details['category'] = 'unknown'
    
    return weight, details


def detect_ip_in_url(url: str) -> Tuple[bool, Optional[str], Dict[str, Any]]:
    """
    Детектирование IP-адреса вместо домена в URL.
    
    Правило: Если в URL используется IP-адрес — критически подозрительно
    
    Args:
        url: URL-адрес
        
    Returns:
        tuple: (найден_IP, IP_адрес, детали)
    """
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    matches = ip_pattern.findall(url)
    
    if not matches:
        return False, None, {
            'rule': 'ip_in_url',
            'found': False
        }
    
    # Берем первый найденный IP
    ip = matches[0]
    
    # Валидация IP
    parts = ip.split('.')
    if len(parts) != 4 or not all(0 <= int(part) <= 255 for part in parts if part.isdigit()):
        return False, None, {
            'rule': 'ip_in_url',
            'found': False,
            'invalid': True
        }
    
    # Проверка на приватный IP (исключение)
    is_private = is_private_ip(ip)
    
    details = {
        'rule': 'ip_in_url',
        'found': True,
        'ip': ip,
        'is_private': is_private
    }
    
    if is_private:
        # Приватные IP не считаются подозрительными
        return False, ip, details
    
    return True, ip, details


def detect_url_shorteners(url: str) -> Tuple[bool, Optional[str], Dict[str, Any]]:
    """
    Обнаружение URL-shorteners.
    
    Правило: Проверка домена на вхождение в список URL shorteners
    
    Args:
        url: URL-адрес
        
    Returns:
        tuple: (найден_shortener, домен_shortener, детали)
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Удаление порта, если есть
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Проверка на точное совпадение или поддомен
        for shortener in URL_SHORTENERS:
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
    except Exception as e:
        logger.debug(f"Ошибка при проверке URL shortener для {url}: {e}")
        return False, None, {
            'rule': 'url_shortener',
            'found': False,
            'error': str(e)
        }


def analyze_domain_features(domain: str) -> Dict[str, Any]:
    """
    Комплексный эвристический анализ домена.
    
    Объединяет правила анализа домена:
    - Длина домена
    - Подозрительные TLD
    
    Args:
        domain: Доменное имя
        
    Returns:
        dict: Словарь с результатами анализа и максимальным весом
    """
    results = {
        'domain': domain,
        'rules': {},
        'max_weight': 0.0,
        'total_weight': 0.0
    }
    
    # Анализ длины
    length_weight, length_details = analyze_domain_length(domain)
    results['rules']['length'] = {
        'weight': length_weight,
        **length_details
    }
    results['max_weight'] = max(results['max_weight'], length_weight)
    results['total_weight'] += length_weight
    
    # Анализ TLD
    tld_weight, tld_details = analyze_domain_tld(domain)
    results['rules']['tld'] = {
        'weight': tld_weight,
        **tld_details
    }
    results['max_weight'] = max(results['max_weight'], tld_weight)
    results['total_weight'] += tld_weight
    
    return results


def analyze_urls(urls: List[str]) -> Dict[str, Any]:
    """
    Анализ списка URL по эвристическим правилам.
    
    Args:
        urls: Список URL-адресов
        
    Returns:
        dict: Результаты анализа URL
    """
    results = {
        'urls': urls,
        'url_analyses': [],
        'ip_detections': [],
        'shortener_detections': [],
        'max_weight': 0.0
    }
    
    for url in urls:
        url_analysis = {
            'url': url,
            'rules': {},
            'max_weight': 0.0
        }
        
        # Проверка IP в URL
        has_ip, ip, ip_details = detect_ip_in_url(url)
        if has_ip:
            url_analysis['rules']['ip_in_url'] = {
                'weight': 1.0,  # Критический вес
                **ip_details
            }
            url_analysis['max_weight'] = 1.0
            results['ip_detections'].append({
                'url': url,
                'ip': ip,
                **ip_details
            })
        
        # Проверка URL shortener
        has_shortener, shortener, shortener_details = detect_url_shorteners(url)
        if has_shortener:
            url_analysis['rules']['url_shortener'] = {
                'weight': 0.8,
                **shortener_details
            }
            url_analysis['max_weight'] = max(url_analysis['max_weight'], 0.8)
            results['shortener_detections'].append({
                'url': url,
                'shortener': shortener,
                **shortener_details
            })
        
        results['url_analyses'].append(url_analysis)
        results['max_weight'] = max(results['max_weight'], url_analysis['max_weight'])
    
    return results


@timing_decorator
def analyze_urls_and_domains(
    urls: List[str],
    domains: List[str],
    ips: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Главная функция для анализа URL и доменов.
    
    Объединяет эвристические проверки:
    - Анализ доменов (длина, TLD)
    - Анализ URL (IP, shorteners)
    
    Примечание: URL, домены и IP должны быть уже извлечены из email_parser.py
    
    Args:
        urls: Список URL-адресов (извлеченных из email_parser)
        domains: Список доменов (извлеченных из email_parser)
        ips: Список IP-адресов (опционально, извлеченных из email_parser)
        
    Returns:
        dict: Полный результат анализа со всеми признаками и весами
    """
    result = {
        'urls': urls,
        'domains': domains,
        'ips': ips or [],
        'domain_analyses': {},
        'url_analyses': {},
        'summary': {
            'max_domain_weight': 0.0,
            'max_url_weight': 0.0,
            'total_suspicious_domains': 0,
            'total_suspicious_urls': 0
        }
    }
    
    # Анализ каждого домена
    for domain in result['domains']:
        domain_analysis = analyze_domain_features(domain)
        result['domain_analyses'][domain] = domain_analysis
        result['summary']['max_domain_weight'] = max(
            result['summary']['max_domain_weight'],
            domain_analysis['max_weight']
        )
        if domain_analysis['max_weight'] > 0.5:
            result['summary']['total_suspicious_domains'] += 1
    
    # Анализ URL
    url_analysis = analyze_urls(urls)
    result['url_analyses'] = url_analysis
    result['summary']['max_url_weight'] = url_analysis['max_weight']
    
    # Подсчет подозрительных URL
    for url_analysis_item in url_analysis['url_analyses']:
        if url_analysis_item['max_weight'] > 0.5:
            result['summary']['total_suspicious_urls'] += 1
    
    logger.info(
        f"Проанализировано {len(result['domains'])} доменов и {len(urls)} URL. "
        f"Подозрительных доменов: {result['summary']['total_suspicious_domains']}, "
        f"подозрительных URL: {result['summary']['total_suspicious_urls']}"
    )
    
    return result


def analyze_from_parsed_email(parsed_email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Удобная функция для анализа URL и доменов из результата email_parser.parse_email().
    
    Автоматически извлекает URL, домены и IP из структурированных данных email.
    
    Args:
        parsed_email_data: Результат вызова email_parser.parse_email()
        
    Returns:
        dict: Полный результат анализа со всеми признаками и весами
    """
    # Извлечение данных из структуры parsed_email
    urls = parsed_email_data.get('urls', [])
    domains_data = parsed_email_data.get('domains', {})
    
    # Извлечение доменов и IP из структуры domains
    domains = domains_data.get('domains', []) if isinstance(domains_data, dict) else []
    ips = domains_data.get('ips', []) if isinstance(domains_data, dict) else []
    
    # Если domains_data - это список, используем его как есть
    if isinstance(domains_data, list):
        domains = domains_data
    
    # Вызов главной функции анализа
    return analyze_urls_and_domains(urls=urls, domains=domains, ips=ips)
