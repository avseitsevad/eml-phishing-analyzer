"""
Rules Engine Module
Эвристические правила и формирование risk score
"""

# Константы для правил
RECEIVED_HOPS_THRESHOLD = 10

# Веса правил
RULE_WEIGHTS = {
    'spf_fail': 15,
    'dkim_fail': 15,
    'dmarc_fail': 10,
    'domain_mismatch': 20,
    'domain_in_ti_db': 25,
    'ip_in_ti_db': 25,
    'reply_anomaly': 10,
    'received_hops_anomaly': 15,
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


def check_threat_intelligence(ti_results: dict) -> dict:
    """
    Проверка репутации на основе готовых результатов TI
    
    Args:
        ti_results: результат ti_module.check_reputation() с полями:
            - malicious_domains: list[str]
            - malicious_ips: list[str]
            - domain_in_urlhaus: bool
            - domain_in_openphish: bool
            - ip_in_blacklist: bool
        
    Returns:
        dict: результаты проверки репутации
    """
    if not ti_results:
        return {
            'triggered': False,
            'score': 0,
            'details': 'TI results not available'
        }
    
    malicious_domains = ti_results.get('malicious_domains', [])
    malicious_ips = ti_results.get('malicious_ips', [])
    
    triggered = bool(malicious_domains or malicious_ips)
    score = 0
    found_items = []
    
    # Проверка доменов
    for domain in malicious_domains:
        if domain:
            score += RULE_WEIGHTS['domain_in_ti_db']
            found_items.append(f"Domain: {domain}")
    
    # Проверка IP-адресов
    for ip in malicious_ips:
        if ip:
            score += RULE_WEIGHTS['ip_in_ti_db']
            found_items.append(f"IP: {ip}")
    
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


def check_received_hops_anomaly(header_analysis: dict) -> dict:
    """
    Проверка аномально большого количества хопов в заголовках Received
    
    Args:
        header_analysis: результат analyze_headers() из header_analyzer
        
    Returns:
        dict: результат проверки
    """
    received_count = header_analysis.get('received_count', 0)
    
    if received_count > RECEIVED_HOPS_THRESHOLD:
        return {
            'triggered': True,
            'score': RULE_WEIGHTS['received_hops_anomaly'],
            'details': f'Anomalous number of Received hops: {received_count} (threshold: {RECEIVED_HOPS_THRESHOLD})'
        }
    
    return {
        'triggered': False,
        'score': 0,
        'details': f'Received hops count: {received_count} (normal)'
    }


def calculate_risk_score(triggered_rules: list) -> int:
    """
    Формирование risk score (0-100) на основе сработавших правил с весовыми коэффициентами
    
    Args:
        triggered_rules: список сработавших правил с их весами (список словарей с ключами 'rule_name' и 'weight')
        
    Returns:
        int: risk score (0-100)
    """
    if not triggered_rules:
        return 0
    
    total_score = 0
    for rule in triggered_rules:
        if isinstance(rule, dict):
            weight = rule.get('weight', 0)
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


def evaluate_all_rules(header_analysis: dict, parsed_email: dict, 
                       ti_results: dict) -> dict:
    """
    Главная функция для оценки всех правил
    
    Args:
        header_analysis: результат analyze_headers() из header_analyzer
        parsed_email: результат parse_email() из email_parser
        ti_results: результат ti_module.check_reputation() из threat_intelligence
        
    Returns:
        dict: {
            'risk_score': int,              # 0-100
            'risk_level': str,              # 'LOW'/'MEDIUM'/'HIGH'
            'triggered_rules': [
                {
                    'rule_name': str,
                    'weight': int,
                    'description': str
                }
            ],
            'rule_details': dict
        }
    """
    triggered_rules = []
    rule_details = {}
    
    # 1. Authentication (SPF/DKIM/DMARC)
    auth_result = check_authentication(header_analysis)
    if auth_result['triggered']:
        triggered_rules.append({
            'rule_name': 'authentication',
            'weight': auth_result['score'],
            'description': auth_result['details']
        })
    rule_details['authentication'] = auth_result
    
    # 2. Domain mismatch (From/Reply-To/Return-Path)
    domain_result = check_domain_mismatch(header_analysis)
    if domain_result['triggered']:
        triggered_rules.append({
            'rule_name': 'domain_mismatch',
            'weight': domain_result['score'],
            'description': domain_result['details']
        })
    rule_details['domain_mismatch'] = domain_result
    
    # 3. Reply anomaly ("Re:" без References)
    reply_result = check_reply_anomaly(header_analysis)
    if reply_result['triggered']:
        triggered_rules.append({
            'rule_name': 'reply_anomaly',
            'weight': reply_result['score'],
            'description': reply_result['details']
        })
    rule_details['reply_anomaly'] = reply_result
    
    # 4. Received: аномально большое кол-во хопов
    hops_result = check_received_hops_anomaly(header_analysis)
    if hops_result['triggered']:
        triggered_rules.append({
            'rule_name': 'received_hops_anomaly',
            'weight': hops_result['score'],
            'description': hops_result['details']
        })
    rule_details['received_hops_anomaly'] = hops_result
    
    # 5. TI reputation (domains/IPs)
    ti_result = check_threat_intelligence(ti_results)
    if ti_result['triggered']:
        triggered_rules.append({
            'rule_name': 'threat_intelligence',
            'weight': ti_result['score'],
            'description': ti_result['details']
        })
    rule_details['threat_intelligence'] = ti_result
    
    # Calculate risk score
    risk_score = calculate_risk_score(triggered_rules)
    risk_level = classify_risk_level(risk_score)
    
    return {
        'risk_score': risk_score,
        'risk_level': risk_level,
        'triggered_rules': triggered_rules,
        'rule_details': rule_details
    }