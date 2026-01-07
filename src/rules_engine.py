"""
Rules Engine Module
Эвристические правила и формирование risk score
"""

# Опасные расширения файлов
DANGEROUS_EXTENSIONS = {
    '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js',
    '.jar', '.app', '.deb', '.pkg', '.dmg', '.msi', '.dll', '.lnk',
    '.hta', '.wsf', '.ps1', '.sh', '.run', '.bin', '.rar', '.7z', '.zip'
}

# Веса правил
RULE_WEIGHTS = {
    'spf_fail': 20,
    'dkim_fail': 20,
    'dmarc_fail': 20,
    'domain_mismatch': 30,
    'domain_in_ti_db': 60,
    'ip_in_ti_db': 60,
    'reply_anomaly': 30,
    'dangerous_attachments': 40,
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
    
    # Проверка доменов (только уникальные)
    unique_domains = set(domain for domain in malicious_domains if domain)
    for domain in unique_domains:
        score += RULE_WEIGHTS['domain_in_ti_db']
        found_items.append(f"Domain: {domain}")
    
    # Проверка IP-адресов (только уникальные)
    unique_ips = set(ip for ip in malicious_ips if ip)
    for ip in unique_ips:
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


def check_dangerous_attachments(parsed_email: dict) -> dict:
    """
    Проверка наличия вложений с опасными расширениями
    
    Args:
        parsed_email: результат parse_email() из email_parser
        
    Returns:
        dict: результат проверки
    """
    attachments = parsed_email.get('attachments', [])
    
    if not attachments:
        return {
            'triggered': False,
            'score': 0,
            'details': 'No attachments found'
        }
    
    dangerous_files = []
    for attachment in attachments:
        filename = attachment.get('name', '') if isinstance(attachment, dict) else str(attachment)
        if any(filename.lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS):
            dangerous_files.append(filename)
    
    if dangerous_files:
        return {
            'triggered': True,
            'score': RULE_WEIGHTS['dangerous_attachments'],
            'details': f'Dangerous file extensions found: {", ".join(dangerous_files)}'
        }
    
    return {
        'triggered': False,
        'score': 0,
        'details': 'No dangerous file extensions detected'
    }


def calculate_risk_score(triggered_rules: list) -> int:
    """
    Формирование risk score (0-100) на основе сработавших правил с весовыми коэффициентами
    
    Args:
        triggered_rules: список сработавших правил с их весами
        
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
        str: 'LOW' (<30), 'MEDIUM' (30-69), 'HIGH' (>=70)
    """
    if risk_score < 30:
        return 'LOW'
    elif risk_score <= 69:
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
            'risk_score': int,
            'risk_level': str,
            'triggered_rules': list,
            'rule_details': dict
        }
    """
    if not isinstance(header_analysis, dict):
        header_analysis = {}
    if not isinstance(parsed_email, dict):
        parsed_email = {}
    if not isinstance(ti_results, dict):
        ti_results = {}
    
    triggered_rules = []
    rule_details = {}
    
    # Аутентификация
    auth_result = check_authentication(header_analysis)
    if auth_result['triggered']:
        triggered_rules.append({
            'rule_name': 'authentication',
            'weight': auth_result['score'],
            'description': auth_result['details']
        })
    rule_details['authentication'] = auth_result
    
    # Несоответствие доменов
    domain_result = check_domain_mismatch(header_analysis)
    if domain_result['triggered']:
        triggered_rules.append({
            'rule_name': 'domain_mismatch',
            'weight': domain_result['score'],
            'description': domain_result['details']
        })
    rule_details['domain_mismatch'] = domain_result
    
    # Аномалия ответа
    reply_result = check_reply_anomaly(header_analysis)
    if reply_result['triggered']:
        triggered_rules.append({
            'rule_name': 'reply_anomaly',
            'weight': reply_result['score'],
            'description': reply_result['details']
        })
    rule_details['reply_anomaly'] = reply_result
    
    # Репутация TI
    ti_result = check_threat_intelligence(ti_results)
    if ti_result['triggered']:
        triggered_rules.append({
            'rule_name': 'threat_intelligence',
            'weight': ti_result['score'],
            'description': ti_result['details']
        })
    rule_details['threat_intelligence'] = ti_result
    
    # Опасные вложения
    attachments_result = check_dangerous_attachments(parsed_email)
    if attachments_result['triggered']:
        triggered_rules.append({
            'rule_name': 'dangerous_attachments',
            'weight': attachments_result['score'],
            'description': attachments_result['details']
        })
    rule_details['dangerous_attachments'] = attachments_result
    
    # Расчет risk score
    risk_score = calculate_risk_score(triggered_rules)
    risk_level = classify_risk_level(risk_score)
    
    return {
        'risk_score': risk_score,
        'risk_level': risk_level,
        'triggered_rules': triggered_rules,
        'rule_details': rule_details
    }