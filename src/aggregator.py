"""
Aggregator & Decision Module
Агрегация результатов и формирование вердикта
"""


def normalize_risk_score(risk_score: int) -> float:
    """
    Нормализация risk score (0-100) к диапазону (0-1)
    
    Args:
        risk_score: риск-скор от Rules Engine (0-100)
        
    Returns:
        float: нормализованный скор (0-1)
    """
    pass


def aggregate_scores(ml_confidence: float, normalized_risk: float,
                     ml_weight: float = 0.7, rule_weight: float = 0.3) -> float:
    """
    Weighted average агрегация результатов ML и правил
    final_score = ml_confidence * ml_weight + normalized_risk * rule_weight
    
    Args:
        ml_confidence: confidence score от ML модели (0-1)
        normalized_risk: нормализованный risk score (0-1)
        ml_weight: вес ML компонента (по умолчанию 0.7)
        rule_weight: вес Rules компонента (по умолчанию 0.3)
        
    Returns:
        float: агрегированный финальный скор (0-1)
    """
    pass


def determine_verdict(final_score: float, threshold: float = 0.5) -> str:
    """
    Определение финального вердикта на основе агрегированной оценки
    
    Args:
        final_score: агрегированный скор (0-1)
        threshold: порог классификации (по умолчанию 0.5)
        
    Returns:
        str: 'legitimate' или 'phishing'
    """
    pass


def generate_detailed_report(email_data: dict, ml_result: dict, 
                             rules_result: dict, final_verdict: str,
                             final_score: float) -> dict:
    """
    Формирование детализированного отчета с объяснением решения
    
    Args:
        email_data: данные письма
        ml_result: результаты ML классификатора
        rules_result: результаты правиловой системы
        final_verdict: финальный вердикт
        final_score: финальный скор
        
    Returns:
        dict: {
            'verdict': str,
            'final_score': float,
            'ml_confidence': float,
            'risk_score': int,
            'triggered_rules': list,
            'significant_features': list,
            'ti_checks': dict,
            'email_metadata': dict
        }
    """
    pass