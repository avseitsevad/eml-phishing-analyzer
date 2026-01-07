"""
Aggregator & Decision Module (src/aggregator.py)

Назначение:
- Принимает результаты Rules Engine и ML Classifier
- Нормализует risk_score (0..100) -> (0..1)
- Выполняет взвешенную агрегацию:
    final_score = w_ml * ml_confidence + w_rules * risk_norm
- Применяет порог threshold для финального вердикта
- Формирует детальный отчёт

"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Union


@dataclass
class AggregationConfig:
    w_rules: float = 0.3
    w_ml: float = 0.7
    threshold: float = 0.5


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def _normalize_risk_score(risk_score: Any) -> float:
    try:
        rs = float(risk_score)
    except Exception:
        return 0.0
    return _clamp01(rs / 100.0)


def _load_config(weights_path: Optional[Union[str, Path]] = None,
                 default: Optional[AggregationConfig] = None) -> AggregationConfig:
    cfg = default if default is not None else AggregationConfig()

    if not weights_path:
        return cfg

    p = Path(weights_path)
    if not p.exists():
        return cfg

    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        cfg.w_rules = float(data.get("w_rules", cfg.w_rules))
        cfg.w_ml = float(data.get("w_ml", cfg.w_ml))
        cfg.threshold = float(data.get("threshold", cfg.threshold))
    except Exception:
        return cfg

    s = (cfg.w_rules or 0.0) + (cfg.w_ml or 0.0)
    if s > 0:
        cfg.w_rules = cfg.w_rules / s
        cfg.w_ml = cfg.w_ml / s

    return cfg


def _extract_ml_confidence(ml_result: Dict[str, Any]) -> float:
    """
    Предпочтение: phishing_probability, иначе confidence.
    """
    ml_conf = ml_result.get("phishing_probability", None)
    if ml_conf is None:
        ml_conf = ml_result.get("confidence", 0.0)

    try:
        ml_conf = float(ml_conf)
    except Exception:
        ml_conf = 0.0

    return _clamp01(ml_conf)


def aggregate_scores(ml_result: Dict[str, Any],
                     rules_result: Dict[str, Any],
                     config: AggregationConfig) -> Dict[str, Any]:
    """
    Возвращает агрегированные значения без формирования отчёта.
    """
    ml_conf = _extract_ml_confidence(ml_result)

    risk_score = rules_result.get("risk_score", 0)
    risk_norm = _normalize_risk_score(risk_score)

    final_score = config.w_ml * ml_conf + config.w_rules * risk_norm
    final_score = _clamp01(final_score)

    return {
        "ml_confidence": ml_conf,
        "risk_score": float(risk_score) if isinstance(risk_score, (int, float, str)) else 0.0,
        "risk_norm": risk_norm,
        "w_ml": config.w_ml,
        "w_rules": config.w_rules,
        "threshold": config.threshold,
        "final_score": final_score,
    }


def decide(final_score: float, threshold: float) -> int:
    """
    1 = phishing, 0 = legitimate
    """
    return int(float(final_score) >= float(threshold))


def _format_triggered_rules(rule_details: Dict[str, Any]) -> list:
    """
    Форматирует rule_details в список сработавших правил в формате:
    {rule: 'XXX', 'triggered': True, 'details': '...'}
    """
    formatted_rules = []
    
    if not isinstance(rule_details, dict):
        return formatted_rules
    
    for rule_name, rule_data in rule_details.items():
        if not isinstance(rule_data, dict):
            continue
        
        triggered = rule_data.get("triggered", False)
        if triggered:
            details = rule_data.get("details", "")
            formatted_rules.append({
                "rule": rule_name,
                "triggered": True,
                "details": str(details) if details else ""
            })
    
    return formatted_rules


def generate_detailed_report(ml_result: Dict[str, Any],
                             rules_result: Dict[str, Any],
                             aggregation: Dict[str, Any],
                             final_verdict: int) -> Dict[str, Any]:
    """
    Детальный отчёт без рекомендаций.
    Включает информацию о сработавших правилах в формате:
    {rule: 'XXX', 'triggered': True, 'details': '...'}
    """
    triggered_rules = rules_result.get("triggered_rules", [])
    rule_details = rules_result.get("rule_details", {})
    risk_level = rules_result.get("risk_level", None)

    if triggered_rules is None:
        triggered_rules = []
    if not isinstance(triggered_rules, list):
        triggered_rules = [triggered_rules]

    if rule_details is None:
        rule_details = {}
    if not isinstance(rule_details, dict):
        rule_details = {}

    # Форматируем сработавшие правила в нужном формате
    formatted_triggered_rules = _format_triggered_rules(rule_details)

    report = {
        "verdict": {
            "final_verdict": int(final_verdict),
            "final_score": float(aggregation["final_score"]),
            "threshold": float(aggregation["threshold"]),
        },
        "scores": {
            "ml_confidence": float(aggregation["ml_confidence"]),
            "risk_score": float(aggregation["risk_score"]),
            "risk_norm": float(aggregation["risk_norm"]),
            "w_ml": float(aggregation["w_ml"]),
            "w_rules": float(aggregation["w_rules"]),
        },
        "ml": {
            "prediction": ml_result.get("prediction"),
            "confidence": ml_result.get("confidence"),
            "phishing_probability": ml_result.get("phishing_probability"),
            "class_label": ml_result.get("class_label"),
            "model_type": ml_result.get("model_type"),
        },
        "rules": {
            "risk_score": rules_result.get("risk_score"),
            "risk_level": risk_level,
            "triggered_rules": triggered_rules,
            "rule_details": rule_details,
            "triggered_rules_formatted": formatted_triggered_rules,
        },
    }

    return report


def aggregate_and_decide(ml_result: Dict[str, Any],
                         rules_result: Dict[str, Any],
                         weights_path: Optional[Union[str, Path]] = None,
                         config: Optional[AggregationConfig] = None) -> Dict[str, Any]:
    """
    Главная функция модуля:
    - агрегирует оценки (ML + rules)
    - выдаёт вердикт
    - формирует детальный отчёт

    Возвращает:
    {
      "final_verdict": 0/1,
      "final_score": float,
      "aggregation": {...},
      "report": {...}
    }
    """
    cfg = _load_config(weights_path=weights_path, default=config)
    aggregation = aggregate_scores(ml_result=ml_result, rules_result=rules_result, config=cfg)
    final_verdict = decide(aggregation["final_score"], aggregation["threshold"])
    report = generate_detailed_report(
        ml_result=ml_result,
        rules_result=rules_result,
        aggregation=aggregation,
        final_verdict=final_verdict
    )

    return {
        "final_verdict": final_verdict,
        "final_score": aggregation["final_score"],
        "aggregation": aggregation,
        "report": report,
    }
