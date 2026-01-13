"""
Header Analyzer Module
Анализ заголовков и извлечение фактов для эвристических правил
"""

import re
from typing import Dict, Any
import tldextract

from .utils import EMAIL_DOMAIN_PATTERN

# Регулярные выражения для парсинга Authentication-Results
SPF_PATTERN = re.compile(r'spf=(\w+)', re.IGNORECASE)
DKIM_PATTERN = re.compile(r'dkim=(\w+)', re.IGNORECASE)
DMARC_PATTERN = re.compile(r'dmarc=(\w+)', re.IGNORECASE)
RE_PREFIX_PATTERN = re.compile(r'^\s*re\s*:', re.IGNORECASE)


def extract_domain(address: str) -> str:
    """
    Извлечение домена из email адреса
    
    Args:
        address: email адрес
        
    Returns:
        str: домен или пустая строка
    """
    if not address:
        return ''
    
    match = EMAIL_DOMAIN_PATTERN.search(address)
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


def _extract_tld_sld(domain: str) -> str:
    """
    Извлечение TLD+SLD из домена для сравнения
    
    Args:
        domain: полный домен
        
    Returns:
        str: TLD+SLD или пустая строка
    """
    if not domain:
        return ''
    
    extracted = tldextract.extract(domain.lower())
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return ''


def check_domain_mismatch(from_domain: str, reply_to_domain: str, 
                         return_path_domain: str) -> Dict[str, Any]:
    """
    Проверка сопоставления доменов From/Reply-To/Return-Path
    Сравнивает только TLD+SLD
    
    Args:
        from_domain: домен из заголовка From
        reply_to_domain: домен из заголовка Reply-To
        return_path_domain: домен из заголовка Return-Path
        
    Returns:
        dict: {
            'has_domain_mismatch': bool,
            'details': str
        }
    """
    # Извлекаем TLD+SLD для сравнения
    from_tld_sld = _extract_tld_sld(from_domain)
    reply_to_tld_sld = _extract_tld_sld(reply_to_domain)
    return_path_tld_sld = _extract_tld_sld(return_path_domain)
    
    mismatches = []
    
    # Сравниваем TLD+SLD, а не полные домены
    if from_tld_sld and reply_to_tld_sld and from_tld_sld != reply_to_tld_sld:
        mismatches.append(f"Reply-To: {reply_to_domain} ({reply_to_tld_sld})")
    
    if from_tld_sld and return_path_tld_sld and from_tld_sld != return_path_tld_sld:
        mismatches.append(f"Return-Path: {return_path_domain} ({return_path_tld_sld})")
    
    if mismatches:
        return {
            'has_domain_mismatch': True,
            'details': f'From: {from_domain} ({from_tld_sld}) != {", ".join(mismatches)}'
        }
    
    return {
        'has_domain_mismatch': False,
        'details': 'All domains match'
    }


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
    
    Args:
        headers: словарь с полями заголовков из email_parser.parse_email()
        
    Returns:
        dict: {
            'spf_result': str,
            'dkim_result': str,
            'dmarc_result': str,
            'from_domain': str,
            'reply_to_domain': str,
            'return_path_domain': str,
            'has_re_without_references': bool,
            'has_domain_mismatch': bool,
            'domain_mismatch_details': str
        }
    """
    result = {
        'spf_result': 'none',
        'dkim_result': 'none',
        'dmarc_result': 'none',
        'from_domain': '',
        'reply_to_domain': '',
        'return_path_domain': '',
        'has_re_without_references': False,
        'has_domain_mismatch': False,
        'domain_mismatch_details': ''
    }
    
    # Парсинг Authentication-Results
    auth_results = headers.get('auth_results', '')
    auth_data = parse_authentication_results(auth_results)
    result['spf_result'] = auth_data.get('spf', 'none')
    result['dkim_result'] = auth_data.get('dkim', 'none')
    result['dmarc_result'] = auth_data.get('dmarc', 'none')
    
    # Извлечение доменов из From/Reply-To/Return-Path
    from_addr = headers.get('from', '')
    reply_to = headers.get('reply_to', '')
    return_path = headers.get('return_path', '')
    
    result['from_domain'] = extract_domain(from_addr)
    result['reply_to_domain'] = extract_domain(reply_to) if reply_to else ''
    result['return_path_domain'] = extract_domain(return_path) if return_path else ''
    
    # Проверка несоответствия доменов
    domain_mismatch_result = check_domain_mismatch(
        result['from_domain'],
        result['reply_to_domain'],
        result['return_path_domain']
    )
    result['has_domain_mismatch'] = domain_mismatch_result['has_domain_mismatch']
    result['domain_mismatch_details'] = domain_mismatch_result['details']
    
    # Проверка структурной аномалии: "Re:" в Subject при отсутствии References
    subject = headers.get('subject', '')
    references = headers.get('references', '')
    result['has_re_without_references'] = check_reply_without_references(subject, references)
    
    return result
