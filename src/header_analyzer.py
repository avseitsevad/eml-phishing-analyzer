"""
Header Analyzer Module
Анализ заголовков и извлечение фактов для эвристических правил
"""

import re
from typing import Dict, List, Any


# Компилированные регулярные выражения для оптимизации
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_PATTERN = re.compile(r'@([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})')
SPF_PATTERN = re.compile(r'spf=(\w+)', re.IGNORECASE)
DKIM_PATTERN = re.compile(r'dkim=(\w+)', re.IGNORECASE)
DMARC_PATTERN = re.compile(r'dmarc=(\w+)', re.IGNORECASE)
RE_PREFIX_PATTERN = re.compile(r'^\s*re\s*:', re.IGNORECASE)


def extract_domain(address: str) -> str:
    """
    Извлечение домена из email адреса
    
    Args:
        address: email адрес (например, "user@example.com" или "Name <user@example.com>")
        
    Returns:
        str: домен или пустая строка
    """
    if not address:
        return ''
    
    match = DOMAIN_PATTERN.search(address)
    return match.group(1).lower() if match else ''


def parse_authentication_results(auth_results: str) -> Dict[str, str]:
    """
    Парсинг результатов SPF, DKIM, DMARC из заголовка Authentication-Results
    
    Args:
        auth_results: строка заголовка Authentication-Results
        
    Returns:
        dict: {
            'spf': str ('pass'/'fail'/'none'),
            'dkim': str ('pass'/'fail'/'none'),
            'dmarc': str ('pass'/'fail'/'none')
        }
    """
    result = {'spf': 'none', 'dkim': 'none', 'dmarc': 'none'}
    
    if not auth_results:
        return result
    
    auth_lower = auth_results.lower()
    
    # Парсинг SPF
    spf_match = SPF_PATTERN.search(auth_lower)
    if spf_match:
        result['spf'] = spf_match.group(1).lower()
    
    # Парсинг DKIM
    dkim_match = DKIM_PATTERN.search(auth_lower)
    if dkim_match:
        result['dkim'] = dkim_match.group(1).lower()
    
    # Парсинг DMARC
    dmarc_match = DMARC_PATTERN.search(auth_lower)
    if dmarc_match:
        result['dmarc'] = dmarc_match.group(1).lower()
    
    return result


def extract_received_ips(received_headers: Any) -> List[str]:
    """
    Извлечение IP-адресов из заголовков Received
    
    Args:
        received_headers: список заголовков Received или одиночное значение
    
    Returns:
        list[str]: список уникальных IP-адресов
    """
    if not received_headers:
        return []
    
    # Нормализация: если не список, преобразуем в список
    if not isinstance(received_headers, list):
        received_headers = [received_headers]
    
    ips = []
    for received in received_headers:
        if received:  # Проверка на None и пустые значения
            received_str = str(received)
            found_ips = IP_PATTERN.findall(received_str)
            ips.extend(found_ips)
    
    # Валидация IP-адресов и удаление дубликатов
    valid_ips = []
    seen = set()
    for ip in ips:
        parts = ip.split('.')
        if len(parts) == 4 and ip not in seen:
            try:
                if all(0 <= int(part) <= 255 for part in parts):
                    valid_ips.append(ip)
                    seen.add(ip)
            except ValueError:
                continue
    
    return valid_ips


def check_reply_without_references(subject: str, references: str) -> bool:
    """
    Проверка структурной аномалии: наличие "Re:" в Subject при отсутствии References
    
    Args:
        subject: тема письма
        references: заголовок References
        
    Returns:
        bool: True если аномалия обнаружена
    """
    if not subject:
        return False
    
    subject_lower = subject.lower().strip()
    has_re_prefix = bool(RE_PREFIX_PATTERN.match(subject_lower))
    has_references = bool(references and references.strip())
    
    return has_re_prefix and not has_references


def analyze_headers(headers: Dict[str, Any]) -> Dict[str, Any]:
    """
    Главная функция анализа заголовков
    
    Извлекает факты из заголовков email для использования в эвристических правилах.
    НЕ принимает решений, НЕ считает баллы, НЕ формирует вердикты. Только извлекает факты.
    
    Args:
        headers: словарь с полями заголовков 
        
    Returns:
        dict: плоский словарь с извлеченными фактами:
        {
            'spf_result': str,              # 'pass'/'fail'/'none'
            'dkim_result': str,             # 'pass'/'fail'/'none'
            'dmarc_result': str,            # 'pass'/'fail'/'none'
            'from_domain': str,
            'reply_to_domain': str,
            'return_path_domain': str,
            'received_ips': list[str],
            'received_count': int,
            'has_re_without_references': bool
        }
    """
    result = {
        'spf_result': 'none',
        'dkim_result': 'none',
        'dmarc_result': 'none',
        'from_domain': '',
        'reply_to_domain': '',
        'return_path_domain': '',
        'received_ips': [],
        'received_count': 0,
        'has_re_without_references': False
    }
    
    # Парсинг Authentication-Results
    auth_results = headers.get('authentication-results', '')
    if not auth_results:
        auth_results = headers.get('auth_results', '')  # Альтернативное имя
    
    auth_data = parse_authentication_results(auth_results)
    result['spf_result'] = auth_data.get('spf', 'none')
    result['dkim_result'] = auth_data.get('dkim', 'none')
    result['dmarc_result'] = auth_data.get('dmarc', 'none')
    
    # Извлечение доменов из From/Reply-To/Return-Path
    from_addr = headers.get('from', '')
    reply_to = headers.get('reply-to', '')
    if not reply_to:
        reply_to = headers.get('reply_to', '')  # Альтернативное имя
    
    return_path = headers.get('return-path', '')
    if not return_path:
        return_path = headers.get('return_path', '')  # Альтернативное имя
    
    result['from_domain'] = extract_domain(from_addr)
    result['reply_to_domain'] = extract_domain(reply_to) if reply_to else ''
    result['return_path_domain'] = extract_domain(return_path) if return_path else ''
    
    # Извлечение IP-адресов и подсчет количества Received headers
    received_headers = headers.get('received', [])
    if not received_headers:
        received_headers = headers.get('received_headers', [])  # Альтернативное имя
    
    # Нормализация received_headers: если не список, преобразуем в список
    if not isinstance(received_headers, list):
        received_headers = [received_headers] if received_headers else []
    
    result['received_ips'] = extract_received_ips(received_headers)
    result['received_count'] = len(received_headers)
    
    # Проверка структурной аномалии: "Re:" в Subject при отсутствии References
    subject = headers.get('subject', '')
    references = headers.get('references', '')
    result['has_re_without_references'] = check_reply_without_references(subject, references)
    
    return result
