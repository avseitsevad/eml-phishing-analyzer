"""
Rules Engine Module
Эвристические правила и формирование risk score
"""

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


def check_authentication(spf: str, dkim: str, dmarc: str) -> dict:
    """
    Проверка результатов SPF/DKIM/DMARC из заголовков
    
    Args:
        spf: результат SPF ('pass'/'fail'/'none')
        dkim: результат DKIM
        dmarc: результат DMARC
        
    Returns:
        dict: {
            'triggered': bool,
            'score': int,
            'details': str
        }
    """
    pass


def check_domain_mismatch(from_domain: str, reply_to_domain: str, 
                          return_path_domain: str) -> dict:
    """
    Проверка сопоставления доменов From/Reply-To/Return-Path
    
    Args:
        from_domain: домен отправителя
        reply_to_domain: домен для ответа
        return_path_domain: домен возврата
        
    Returns:
        dict: результат проверки
    """
    pass


def check_threat_intelligence(urls: list, domains: list, ips: list,
                               ti_module) -> dict:
    """
    Проверка репутации извлеченных URL, доменов и IP по локальной TI-базе
    
    Args:
        urls: список URL
        domains: список доменов
        ips: список IP-адресов
        ti_module: экземпляр ThreatIntelligence
        
    Returns:
        dict: результаты проверки репутации
    """
    pass


def check_reply_anomaly(subject: str, references: str) -> dict:
    """
    Проверка структурной аномалии: "Re:" в Subject при отсутствии References
    
    Args:
        subject: тема письма
        references: заголовок References
        
    Returns:
        dict: результат проверки
    """
    pass


def check_dangerous_attachments(attachments: list) -> dict:
    """
    Проверка характеристик вложений (опасные расширения: .exe, .scr, .bat и т.д.)
    
    Args:
        attachments: список вложений
        
    Returns:
        dict: результат проверки
    """
    pass


def check_url_characteristics(urls: list, url_shorteners: list) -> dict:
    """
    Проверка характеристик URL (shorteners, избыточное количество)
    
    Args:
        urls: список URL
        url_shorteners: список обнаруженных shorteners
        
    Returns:
        dict: результат проверки
    """
    pass


def calculate_risk_score(triggered_rules: list) -> int:
    """
    Формирование risk score (0-100) на основе сработавших правил с весовыми коэффициентами
    
    Args:
        triggered_rules: список сработавших правил с их весами
        
    Returns:
        int: risk score (0-100)
    """
    pass


def classify_risk_level(risk_score: int) -> str:
    """
    Классификация уровня риска
    
    Args:
        risk_score: риск-скор (0-100)
        
    Returns:
        str: 'LOW' (<30), 'MEDIUM' (30-70), 'HIGH' (>70)
    """
    pass