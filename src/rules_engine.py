"""
Rules Engine Module
Эвристические правила и формирование risk score
"""

import re
from typing import List, Dict, Any

from .utils import DANGEROUS_EXTENSIONS

# Веса правил (настраиваются)
RULE_WEIGHTS = {
    'spf_fail': 15,
    'dkim_fail': 15,
    'dmarc_fail': 10,
    'domain_mismatch': 20,
    'url_in_ti_db': 25,
    'domain_in_ti_db': 25,
    'reply_anomaly': 10,
    'dangerous_attachment': 20,
    'url_shortener': 10,
    'ip_in_url': 15
}


def check_authentication(header_analysis: dict) -> dict:
    """
    Проверка результатов SPF/DKIM/DMARC из результатов header_analyzer
    
    Args:
        header_analysis: результат analyze_headers() из header_analyzer
        
    Returns:
        dict: {
            'triggered': bool,
            'score': int,
            'details': str
        }
    """
    spf = header_analysis.get('spf_result', 'none')
    dkim = header_analysis.get('dkim_result', 'none')
    dmarc = header_analysis.get('dmarc_result', 'none')
    
    triggered = False
    score = 0
    details_parts = []
    
    if spf and spf.lower() == 'fail':
        triggered = True
        score += RULE_WEIGHTS['spf_fail']
        details_parts.append('SPF fail')
    
    if dkim and dkim.lower() == 'fail':
        triggered = True
        score += RULE_WEIGHTS['dkim_fail']
        details_parts.append('DKIM fail')
    
    if dmarc and dmarc.lower() == 'fail':
        triggered = True
        score += RULE_WEIGHTS['dmarc_fail']
        details_parts.append('DMARC fail')
    
    details = '; '.join(details_parts) if details_parts else 'All authentication passed'
    
    return {
        'triggered': triggered,
        'score': score,
        'details': details
    }


def check_domain_mismatch(header_analysis: dict) -> dict:
    """
    Проверка сопоставления доменов From/Reply-To/Return-Path
    
    Args:
        header_analysis: результат analyze_headers() из header_analyzer
        
    Returns:
        dict: результат проверки
    """
    from_domain = header_analysis.get('from_domain', '')
    reply_to_domain = header_analysis.get('reply_to_domain', '')
    return_path_domain = header_analysis.get('return_path_domain', '')
    
    mismatches = []
    
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        mismatches.append(f"Reply-To: {reply_to_domain}")
    
    if from_domain and return_path_domain and from_domain != return_path_domain:
        mismatches.append(f"Return-Path: {return_path_domain}")
    
    if mismatches:
        return {
            'triggered': True,
            'score': RULE_WEIGHTS['domain_mismatch'],
            'details': f'From: {from_domain} != {", ".join(mismatches)}'
        }
    
    return {
        'triggered': False,
        'score': 0,
        'details': 'All domains match'
    }


def check_threat_intelligence(urls: list, domains: list, ips: list,
                               ti_module) -> dict:
    """
    Проверка репутации извлеченных RLU, доменов и IP по локальной TI-базе
    
    Args:
        urls: список URL
        domains: список доменов
        ips: список IP-адресов
        ti_module: экземпляр ThreatIntelligence
        
    Returns:
        dict: результаты проверки репутации
    """
    if not ti_module:
        return {
            'triggered': False,
            'score': 0,
            'details': 'TI module not available'
        }
    
    triggered = False
    score = 0
    found_items = []
    
    # Проверка URL
    for url in urls or []:
        if not url:
            continue
        result = ti_module.check_url_reputation(url)
        if result.get('found'):
            triggered = True
            score += RULE_WEIGHTS['url_in_ti_db']
            found_items.append(f"URL: {url} ({result.get('threat_type', 'malicious')})")
    
    # Проверка доменов
    for domain in domains or []:
        if not domain:
            continue
        result = ti_module.check_domain_reputation(domain)
        if result.get('found'):
            triggered = True
            score += RULE_WEIGHTS['domain_in_ti_db']
            found_items.append(f"Domain: {domain} ({result.get('threat_type', 'phishing')})")
    
    # Проверка IP (используем тот же вес что и для URL)
    for ip in ips or []:
        if not ip:
            continue
        result = ti_module.check_ip_reputation(ip)
        if result.get('found'):
            triggered = True
            score += RULE_WEIGHTS['url_in_ti_db']
            found_items.append(f"IP: {ip} ({result.get('threat_type', 'malicious')})")
    
    details = '; '.join(found_items) if found_items else 'No threats found in TI database'
    
    return {
        'triggered': triggered,
        'score': score,
        'details': details
    }


def check_reply_anomaly(header_analysis: dict) -> dict:
    """
    Проверка структурной аномалии: "Re:" в Subject при отсутствии References
    
    Args:
        header_analysis: результат analyze_headers() из header_analyzer
        
    Returns:
        dict: результат проверки
    """
    if header_analysis.get('has_re_without_references'):
        return {
            'triggered': True,
            'score': RULE_WEIGHTS['reply_anomaly'],
            'details': 'Subject contains "Re:" but References header is missing'
        }
    
    return {
        'triggered': False,
        'score': 0,
        'details': 'No reply anomaly detected'
    }


def check_dangerous_attachments(attachments: list) -> dict:
    """
    Проверка характеристик вложений (опасные расширения: .exe, .scr, .bat и т.д.)
    
    Args:
        attachments: список вложений (словари с ключом 'filename')
        
    Returns:
        dict: результат проверки
    """
    if not attachments:
        return {
            'triggered': False,
            'score': 0,
            'details': 'No attachments found'
        }
    
    dangerous_files = []
    
    for attachment in attachments:
        filename = attachment.get('filename', '') if isinstance(attachment, dict) else str(attachment)
        if not filename:
            continue
        
        filename_lower = filename.lower()
        for ext in DANGEROUS_EXTENSIONS:
            if filename_lower.endswith(ext):
                dangerous_files.append(filename)
                break
    
    if dangerous_files:
        return {
            'triggered': True,
            'score': RULE_WEIGHTS['dangerous_attachment'],
            'details': f'Dangerous attachments: {", ".join(dangerous_files)}'
        }
    
    return {
        'triggered': False,
        'score': 0,
        'details': 'No dangerous attachments found'
    }


def check_url_characteristics(url_analysis: dict) -> dict:
    """
    Проверка характеристик URL (shorteners, IP в URL)
    
    Args:
        url_analysis: результат analyze_urls_and_domains() из url_domain_analyzer
        
    Returns:
        dict: результат проверки
    """
    triggered = False
    score = 0
    details_parts = []
    
    url_analyses = url_analysis.get('url_analyses', {})
    shortener_detections = url_analyses.get('shortener_detections', [])
    ip_detections = url_analyses.get('ip_detections', [])
    
    # Проверка URL shorteners
    if shortener_detections:
        triggered = True
        score += RULE_WEIGHTS['url_shortener'] * len(shortener_detections)
        details_parts.append(f'URL shorteners found: {len(shortener_detections)}')
    
    # Проверка IP в URL
    if ip_detections:
        triggered = True
        score += RULE_WEIGHTS['ip_in_url'] * len(ip_detections)
        details_parts.append(f'IP addresses in URLs: {len(ip_detections)}')
    
    details = '; '.join(details_parts) if details_parts else 'No suspicious URL characteristics'
    
    return {
        'triggered': triggered,
        'score': score,
        'details': details
    }


def calculate_risk_score(triggered_rules: list) -> int:
    """
    Формирование risk score (0-100) на основе сработавших правил с весовыми коэффициентами
    
    Args:
        triggered_rules: список сработавших правил с их весами (список словарей с ключами 'rule' и 'weight')
        
    Returns:
        int: risk score (0-100)
    """
    if not triggered_rules:
        return 0
    
    total_score = 0
    for rule in triggered_rules:
        if isinstance(rule, dict):
            weight = rule.get('weight', 0)
        elif isinstance(rule, str) and rule in RULE_WEIGHTS:
            weight = RULE_WEIGHTS[rule]
        else:
            weight = 0
        total_score += weight
    
    return min(100, total_score)


def classify_risk_level(risk_score: int) -> str:
    """
    Классификация уровня риска
    
    Args:
        risk_score: риск-скор (0-100)
        
    Returns:
        str: 'LOW' (<30), 'MEDIUM' (30-70), 'HIGH' (>70)
    """
    if risk_score < 30:
        return 'LOW'
    elif risk_score <= 70:
        return 'MEDIUM'
    else:
        return 'HIGH'


def evaluate_all_rules(header_analysis: dict, url_analysis: dict, 
                       parsed_email: dict, ti_module) -> dict:
    """
    Главная функция для оценки всех правил
    
    Args:
        header_analysis: результат analyze_headers() из header_analyzer
        url_analysis: результат analyze_urls_and_domains() из url_domain_analyzer
        parsed_email: результат parse_email() из email_parser
        ti_module: экземпляр ThreatIntelligence
        
    Returns:
        dict: {
            'risk_score': int,
            'risk_level': str,
            'triggered_rules': list,
            'rule_details': dict
        }
    """
    triggered_rules = []
    rule_details = {}
    
    # Authentication
    auth_result = check_authentication(header_analysis)
    if auth_result['triggered']:
        triggered_rules.append({'rule': 'authentication', 'weight': auth_result['score']})
    rule_details['authentication'] = auth_result
    
    # Domain mismatch
    domain_result = check_domain_mismatch(header_analysis)
    if domain_result['triggered']:
        triggered_rules.append({'rule': 'domain_mismatch', 'weight': domain_result['score']})
    rule_details['domain_mismatch'] = domain_result
    
    # Reply anomaly
    reply_result = check_reply_anomaly(header_analysis)
    if reply_result['triggered']:
        triggered_rules.append({'rule': 'reply_anomaly', 'weight': reply_result['score']})
    rule_details['reply_anomaly'] = reply_result
    
    # Threat Intelligence
    urls = parsed_email.get('urls', [])
    domains = parsed_email.get('domains', [])
    ips = parsed_email.get('ips', [])
    
    ti_result = check_threat_intelligence(urls, domains, ips, ti_module)
    if ti_result['triggered']:
        triggered_rules.append({'rule': 'threat_intelligence', 'weight': ti_result['score']})
    rule_details['threat_intelligence'] = ti_result
    
    # Dangerous attachments
    attachments = parsed_email.get('attachments_metadata', [])
    attach_result = check_dangerous_attachments(attachments)
    if attach_result['triggered']:
        triggered_rules.append({'rule': 'dangerous_attachment', 'weight': attach_result['score']})
    rule_details['dangerous_attachments'] = attach_result
    
    # URL characteristics
    url_char_result = check_url_characteristics(url_analysis)
    if url_char_result['triggered']:
        triggered_rules.append({'rule': 'url_characteristics', 'weight': url_char_result['score']})
    rule_details['url_characteristics'] = url_char_result
    
    # Calculate risk score
    risk_score = calculate_risk_score(triggered_rules)
    risk_level = classify_risk_level(risk_score)
    
    return {
        'risk_score': risk_score,
        'risk_level': risk_level,
        'triggered_rules': triggered_rules,
        'rule_details': rule_details
    }