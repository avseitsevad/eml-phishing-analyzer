"""
Web Interface Module
Streamlit веб-интерфейс для загрузки писем и визуализации результатов
"""

import sys
import json
import time
import os
from pathlib import Path
from typing import Dict, Any, Optional, Union
from datetime import datetime
from urllib.parse import urlparse
from io import BytesIO
import torch
torch.classes.__path__ = []
import streamlit as st
import pandas as pd

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# Добавляем корневую директорию проекта в путь
BASE_DIR = Path(__file__).parent.parent.resolve()
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.pipeline import EmailAnalysisPipeline
from src.feature_extractor import FeatureExtractor


def pluralize_ru(count: int, singular: str, plural_2_4: str, plural_5_plus: str) -> str:
    """
    Возвращает правильную форму слова в зависимости от числительного
    
    Args:
        count: число
        singular: форма для 1 (домен, IP)
        plural_2_4: форма для 2-4 (домена, IP)
        plural_5_plus: форма для 5+ (доменов, IP)
    
    Returns:
        Правильная форма слова
    """
    if count % 10 == 1 and count % 100 != 11:
        return singular
    elif 2 <= count % 10 <= 4 and (count % 100 < 10 or count % 100 >= 20):
        return plural_2_4
    else:
        return plural_5_plus


def format_verdict_color(final_score: float, threshold: float) -> tuple:
    """
    Определяет цвет вердикта на основе final_score
            
        Returns:
        tuple: (уровень риска, цвет)
    """
    if final_score < 0.30:
        return ("LOW", "#28a745")  # зеленый
    elif final_score < 0.69:
        return ("MEDIUM", "#ff9800")  # оранжевый
    else:
        return ("HIGH", "#dc3545")  # красный


def format_rule_name(rule_name: str) -> str:
    """Преобразует название правила"""
    rule_names = {
        'authentication': 'Ошибка аутентификации',
        'domain_mismatch': 'Несоответствие доменов в From/Reply-To/Return-Path',
        'reply_anomaly': 'Аномалия в Reply-To',
        'threat_intelligence': 'Индикаторы в TI-базе',
        'dangerous_attachments': 'Подозрительный формат вложения'
    }
    return rule_names.get(rule_name, rule_name)


def format_risk_level_color(risk_level: str) -> str:
    """Возвращает цвет для уровня риска"""
    colors = {
        'LOW': '#28a745',
        'MEDIUM': '#ffc107',
        'HIGH': '#dc3545'
    }
    return colors.get(risk_level, '#6c757d')


def format_duration_seconds(seconds: Any) -> str:
    """Форматирует длительность для UI/отчетов"""
    return f"{float(seconds or 0):.2f} с"


def display_authentication_results(header_analysis: Dict[str, Any], parsed_email: Dict[str, Any]):
    """Отображение результатов SPF/DKIM/DMARC с детализацией"""
    spf = header_analysis.get('spf_result', 'none')
    dkim = header_analysis.get('dkim_result', 'none')
    dmarc = header_analysis.get('dmarc_result', 'none')
    auth_results_raw = parsed_email.get('auth_results', '')
    
    # Таблица результатов
    auth_df = pd.DataFrame({
        'Метод': ['SPF', 'DKIM', 'DMARC'],
        'Результат': [
            spf.upper() if spf != 'none' else 'NONE',
            dkim.upper() if dkim != 'none' else 'NONE',
            dmarc.upper() if dmarc != 'none' else 'NONE'
        ]
    })
    
    st.subheader("Результаты аутентификации")
    
    # Цветовое кодирование
    def color_result(val):
        if val == 'PASS':
            return 'background-color: #d4edda; color: #155724'
        elif val == 'FAIL':
            return 'background-color: #f8d7da; color: #721c24'
        else:
            return 'background-color: #e2e3e5; color: #383d41'
    
    styled_df = auth_df.style.map(color_result, subset=['Результат'])
    st.dataframe(styled_df, use_container_width=True, hide_index=True)
    
    # Детализация заголовка Authentication-Results
    if auth_results_raw:
        with st.expander("Детали заголовка Authentication-Results"):
            st.text_area(
                label="Authentication-Results",
                value=auth_results_raw,
                height=240,
                label_visibility="collapsed"
            )
    else:
        st.info("Заголовок Authentication-Results не найден в письме")


def display_urls_with_reputation(urls: list, ti_results: Dict[str, Any], parsed_email: Dict[str, Any]):
    """Отображение списка URL с репутацией"""
    if not urls:
        st.info("URL не найдены в теле письма")
        return
    
    st.subheader("Извлеченные URL")
    
    malicious_domains = set(ti_results.get('malicious_domains', []))
    
    url_data = []
    for url in urls:
        domain = urlparse(url).netloc.lower().split(':')[0]
        url_data.append({
            'URL': url,
            'Домен': domain,
            'Репутация': 'Найдено в базе TI' if domain in malicious_domains else 'Не найдено в базе TI'
        })
    
    url_df = pd.DataFrame(url_data)
    st.dataframe(url_df, use_container_width=True, hide_index=True)


def display_attachments(attachments: list):
    """Отображение списка вложений с SHA-256 и ссылками на VirusTotal"""
    if not attachments:
        st.info("Вложения не найдены в письме")
        return
    
    st.subheader("Вложения")
    
    attachment_data = []
    for att in attachments:
        sha256 = att.get('sha256', '')
        filename = att.get('name', 'unknown')
        size = att.get('size', 0)
        file_type = att.get('type', 'unknown')
        
        # Форматирование размера
        if size > 1024 * 1024:
            size_str = f"{size / (1024 * 1024):.2f} MB"
        elif size > 1024:
            size_str = f"{size / 1024:.2f} KB"
        else:
            size_str = f"{size} B"
        
        # Ссылка на VirusTotal
        vt_link = f"https://www.virustotal.com/gui/file/{sha256}/details" if sha256 and sha256 != 'skipped_too_large' else None
        
        attachment_data.append({
            'Имя файла': filename,
            'Тип': file_type,
            'Размер': size_str,
            'SHA-256': sha256[:16] + '...' if len(sha256) > 16 else sha256,
            'SHA-256 (полный)': sha256,
            'VirusTotal': vt_link
        })
    
    att_df = pd.DataFrame(attachment_data)
    
    # Отображаем таблицу без ссылки на VirusTotal
    display_df = att_df[['Имя файла', 'Тип', 'Размер', 'SHA-256']].copy()
    st.dataframe(display_df, use_container_width=True, hide_index=True)
    
    # Детальная информация с полным SHA-256
    with st.expander("Детальная информация о вложениях"):
        for i, att in enumerate(attachments):
            sha256 = att.get('sha256', '')
            if sha256 and sha256 != 'skipped_too_large':
                st.write(f"**{att.get('name', 'unknown')}**")
                st.code(sha256, language=None)
                st.markdown(f"[Открыть в VirusTotal](https://www.virustotal.com/gui/file/{sha256}/details)")
                if i < len(attachments) - 1:
                    st.divider()


def display_triggered_rules(rules_result: Dict[str, Any]):
    """Отображение сработавших правил"""
    triggered_rules = rules_result.get('triggered_rules', [])
    rule_details = rules_result.get('rule_details', {})
    
    if not triggered_rules:
        st.info("Ни одно правило не сработало")
        return
    
    st.subheader("Сработавшие правила")
    
    rules_data = []
    for rule in triggered_rules:
        rule_name = rule.get('rule_name', 'unknown')
        description = rule.get('description', '')
        
        rules_data.append({
            'Правило': format_rule_name(rule_name),
            'Описание': description
        })
    
    rules_df = pd.DataFrame(rules_data)
    st.dataframe(rules_df, use_container_width=True, hide_index=True)
    
    # Детализация правил
    with st.expander("Детали правил"):
        # 1–2 предложения: объяснение логики правила “человеческим” языком
        rule_descriptions_ru = {
            "authentication": (
                "Правило проверяет результаты SPF/DKIM/DMARC из заголовка Authentication-Results"
            ),
            "domain_mismatch": (
                "Правило сравнивает домены в From, Reply-To и Return-Path. "
                "Если домены различаются, это может указывать на подмену адреса отправителя или попытку перенаправления ответа"
            ),
            "reply_anomaly": (
                "Правило проверяет, является ли письмо «ответом» по теме (Re:), но при этом отсутствует заголовок References. "
                "Такая техника часто используется злоумышленниками для создания иллюзии переписки."
            ),
            "threat_intelligence": (
                "Правило проверяет домены и IP из письма по локальной базе Threat Intelligence. "
            ),
            "dangerous_attachments": (
                "Правило анализирует расширения вложений и ищет потенциально опасные типы файлов (например, .exe, .js, .ps1). "
                "Наличие подобных вложений может указывать на вредоносность письма"
            ),
        }

        shown = False
        for rule_key, details in (rule_details or {}).items():
            if isinstance(details, dict) and details.get("triggered", False):
                shown = True
                title = format_rule_name(rule_key)
                desc = rule_descriptions_ru.get(rule_key, "Сработало правило эвристического анализа.")
                st.write(f"- {title}: {desc}")

        if not shown:
            st.write("Нет сработавших правил.")




def display_parsed_email_details(parsed_email: Dict[str, Any], detected_language: str):
    """Отображение детальной информации о письме"""
    st.header("Детальная информация о письме")
    
    # Заголовки письма
    st.subheader("Заголовки письма")
    
    # Основная информация
    col1, col2 = st.columns(2)
    
    with col1:
        for field in ['from', 'to', 'subject', 'date']:
            st.write(f"**{field.capitalize() if field != 'from' else 'From'}{':' if field != 'from' else ':'}**")
            value = parsed_email.get(field, '') or '—'
            st.text(value)
    
    with col2:
        for field, label in [('reply_to', 'Reply-To'), ('return_path', 'Return-Path'), 
                            ('message_id', 'Message-ID'), ('references', 'References')]:
            st.write(f"**{label}:**")
            value = parsed_email.get(field, '') or '—'
            st.text(value)
    
    # Authentication-Results
    auth_results = parsed_email.get('auth_results', '')
    if auth_results:
        st.write("**Authentication-Results:**")
        st.code(auth_results, language=None)
    
    # Received заголовки
    received_headers = parsed_email.get('received_headers', [])
    if received_headers:
        with st.expander(f"Received заголовки ({len(received_headers)})"):
            for i, received in enumerate(received_headers):
                st.write(f"**Received {i+1}:**")
                st.code(received, language=None)
                if i < len(received_headers) - 1:
                    st.divider()
    
    st.divider()
    
    # Тело письма
    st.subheader("Тело письма")
    
    body_plain = parsed_email.get('body_plain', '')
    body_html = parsed_email.get('body_html', '')
    
    if body_plain:
        with st.expander("Текстовая версия", expanded=False):
            st.text_area(
                label="Текстовая версия письма",
                value=body_plain,
                height=400,
                disabled=False,
                key="body_plain_display",
                label_visibility="collapsed",
            )
    
    if body_html:
        st.write("**HTML версия:**")
        with st.expander("Показать HTML код"):
            st.code(body_html, language='html')
        with st.expander("Показать отрендеренный HTML"):
            # Используем st.components.v1.html для корректного рендеринга полноценного HTML
            st.components.v1.html(body_html, height=600, scrolling=True)
    
    # Домены и IP из URL в теле письма
    st.subheader("Домены и IP-адреса из тела письма")
    
    urls = parsed_email.get('urls', [])
    domains_from_urls = FeatureExtractor._extract_domains_from_urls(urls)
    ips_from_urls = FeatureExtractor._extract_ips_from_urls(urls)
    
    col1, col2 = st.columns(2)
    
    with col1:
        count_domains = len(domains_from_urls)
        form_domains = pluralize_ru(count_domains, "домен", "домена", "доменов")
        st.write(f"**{count_domains} {form_domains}:**")
        if domains_from_urls:
            with st.expander("Показать список доменов", expanded=False):
                df_domains = pd.DataFrame({"Домен": domains_from_urls})
                st.dataframe(df_domains, use_container_width=True, hide_index=True)
        else:
            st.write("Не найдено")
    
    with col2:
        count_ips = len(ips_from_urls)
        form_ips = pluralize_ru(count_ips, "IP-адрес", "IP-адреса", "IP-адресов")
        st.write(f"**{count_ips} {form_ips}:**")
        if ips_from_urls:
            with st.expander("Показать список IP-адресов", expanded=False):
                df_ips = pd.DataFrame({"IP-адрес": ips_from_urls})
                st.dataframe(df_ips, use_container_width=True, hide_index=True)
        else:
            st.write("Не найдено")
    
    # URL
    if urls:
        st.write(f"**URL ({len(urls)}):**")
        with st.expander("Показать список URL", expanded=False):
            url_rows = []
            for u in urls:
                parsed = urlparse(u)
                domain = (parsed.netloc or "").lower().split(":", 1)[0]
                url_rows.append({"Домен": domain, "URL": u})
            df_urls = pd.DataFrame(url_rows)
            st.dataframe(df_urls, use_container_width=True, hide_index=True)


def export_report_json(results: Dict[str, Any]) -> str:
    """Экспорт отчета в JSON формате"""
    parsed_email = results.get('parsed_email', {})
    aggregation = results.get('aggregation_result', {})
    ml_result = results.get('ml_result', {})
    rules_result = results.get('rules_result', {})
    header_analysis = results.get('header_analysis', {})
    ti_results = results.get('ti_results', {})
    
    final_verdict = aggregation.get('final_verdict', 0)
    final_score = aggregation.get('final_score', 0)
    verdict_text = "Подозрительное письмо" if final_verdict == 1 else "Легитимное письмо"
    
    # Формируем структурированный отчет
    report = {
        "meta": {
            "analysis_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "analysis_time_seconds": results.get('analysis_time', 0),
            "detected_language": results.get('detected_language', 'unknown')
        },
        "verdict": {
            "result": verdict_text,
            "final_verdict": final_verdict,
            "final_score": round(final_score, 4),
            "rule_risk_score": rules_result.get('risk_score', 0),
            "ml_phishing_probability": round(ml_result.get('phishing_probability', 0), 4)
        },
        "email_info": {
            "from": parsed_email.get('from', '') or '—',
            "to": parsed_email.get('to', '') or '—',
            "subject": parsed_email.get('subject', '') or '—',
            "date": parsed_email.get('date', '') or '—',
            "reply_to": parsed_email.get('reply_to', '') or '—',
            "return_path": parsed_email.get('return_path', '') or '—',
            "message_id": parsed_email.get('message_id', '') or '—',
            "references": parsed_email.get('references', '') or '—'
        },
        "authentication": {
            "spf": header_analysis.get('spf_result', 'none'),
            "dkim": header_analysis.get('dkim_result', 'none'),
            "dmarc": header_analysis.get('dmarc_result', 'none')
        },
        "triggered_rules": [
            {
                "rule_name": rule.get('rule_name', ''),
                "readable_name": format_rule_name(rule.get('rule_name', '')),
                "description": rule.get('description', ''),
                "weight": rule.get('weight', 0)
            }
            for rule in rules_result.get('triggered_rules', [])
        ],
        "urls": [
            {
                "url": url,
                "domain": urlparse(url).netloc.lower().split(':')[0],
                "found_in_ti": urlparse(url).netloc.lower().split(':')[0] in set(ti_results.get('malicious_domains', []))
            }
            for url in parsed_email.get('urls', [])
        ],
        "attachments": [
            {
                "filename": att.get('name', ''),
                "size_bytes": att.get('size', 0),
                "sha256": att.get('sha256', '')
            }
            for att in parsed_email.get('attachments', [])
        ],
        "ml_classification": {
            "prediction": ml_result.get('class_label', 'unknown'),
            "confidence": round(ml_result.get('confidence', 0), 4),
            "phishing_probability": round(ml_result.get('phishing_probability', 0), 4)
        }
    }
    
    return json.dumps(report, ensure_ascii=False, indent=2)


def export_report_pdf(results: Dict[str, Any]) -> bytes:
    """Экспорт отчета в PDF формат"""
    def _ensure_cyrillic_font_registered() -> str:
        font_name = "Arial"
        bold_name = "Arial-Bold"

        if font_name in pdfmetrics.getRegisteredFontNames():
            return font_name

        win_dir = os.environ.get("WINDIR", r"C:\Windows")
        fonts_dir = Path(win_dir) / "Fonts"
        candidates = [
            (font_name, fonts_dir / "arial.ttf"),
            (bold_name, fonts_dir / "arialbd.ttf"),
            ("DejaVuSans", fonts_dir / "DejaVuSans.ttf"),
            ("DejaVuSans-Bold", fonts_dir / "DejaVuSans-Bold.ttf"),
        ]

        try:
            arial_path = fonts_dir / "arial.ttf"
            arial_bold_path = fonts_dir / "arialbd.ttf"
            if arial_path.exists() and arial_bold_path.exists():
                pdfmetrics.registerFont(TTFont(font_name, str(arial_path)))
                pdfmetrics.registerFont(TTFont(bold_name, str(arial_bold_path)))
                pdfmetrics.registerFontFamily("Arial", normal=font_name, bold=bold_name)
                return font_name
        except Exception:
            pass

        try:
            dejavu_path = fonts_dir / "DejaVuSans.ttf"
            dejavu_bold_path = fonts_dir / "DejaVuSans-Bold.ttf"
            if dejavu_path.exists() and dejavu_bold_path.exists():
                pdfmetrics.registerFont(TTFont("DejaVuSans", str(dejavu_path)))
                pdfmetrics.registerFont(TTFont("DejaVuSans-Bold", str(dejavu_bold_path)))
                pdfmetrics.registerFontFamily("DejaVuSans", normal="DejaVuSans", bold="DejaVuSans-Bold")
                return "DejaVuSans"
        except Exception:
            pass

        return "Helvetica"

    base_font = _ensure_cyrillic_font_registered()

    def _escape_xml(text: str) -> str:
        """Экранирует XML-символы для ReportLab Paragraph"""
        return str(text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    
    def _soft_wrap_long_token(text: str, every: int = 60) -> str:
        """
        Вставляет zero-width space для переноса очень длинных токенов (URL и т.п.)
        ReportLab иначе плохо переносит строки без пробелов.
        """
        s = str(text or "")
        if len(s) <= every:
            return s
        return "\u200b".join(s[i:i + every] for i in range(0, len(s), every))

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    story = []
    
    # Стили
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=16,
        fontName=base_font,
        textColor=colors.HexColor('#1f4788'),
        spaceAfter=30,
    )
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=12,
        fontName=base_font,
        textColor=colors.HexColor('#333333'),
        spaceAfter=12,
    )
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontName=base_font,
        fontSize=10,
        leading=12,
    )
    url_style = ParagraphStyle(
        'CustomURL',
        parent=normal_style,
        wordWrap='CJK',  # позволяет переносить длинные строки
    )
    
    parsed_email = results.get('parsed_email', {})
    aggregation = results.get('aggregation_result', {})
    ml_result = results.get('ml_result', {})
    rules_result = results.get('rules_result', {})
    header_analysis = results.get('header_analysis', {})
    ti_results = results.get('ti_results', {})
    
    final_verdict = aggregation.get('final_verdict', 0)
    final_score = aggregation.get('final_score', 0)
    verdict_text = "Подозрительное письмо" if final_verdict == 1 else "Легитимное письмо"
    
    # Заголовок
    story.append(Paragraph("ОТЧЕТ ОБ АНАЛИЗЕ ПИСЬМА", title_style))
    
    # Дата и время
    story.append(Paragraph(f"<b>Дата анализа:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    story.append(Paragraph(f"<b>Время анализа:</b> {format_duration_seconds(results.get('analysis_time', 0))}", normal_style))
    story.append(Spacer(1, 0.12*inch))
    
    # Финальный вердикт
    story.append(Paragraph("ФИНАЛЬНЫЙ ВЕРДИКТ", heading_style))
    verdict_color = colors.HexColor('#dc3545') if final_verdict == 1 else colors.HexColor('#28a745')
    story.append(Paragraph(f"<b>Результат проверки:</b> <font color='{verdict_color.hexval()}'>{verdict_text}</font>", normal_style))
    story.append(Paragraph(f"<b>Итоговая оценка:</b> {final_score:.2%}", normal_style))
    story.append(Paragraph(f"<b>Оценка по эвристическим правилам:</b> {rules_result.get('risk_score', 0)}/100", normal_style))
    story.append(Paragraph(f"<b>Оценка машинного обучения:</b> {ml_result.get('phishing_probability', 0):.2%}", normal_style))
    story.append(Spacer(1, 0.12*inch))
    
    # Информация о письме
    story.append(Paragraph("ИНФОРМАЦИЯ О ПИСЬМЕ", heading_style))
    
    def _format_field(value):
        field_value = parsed_email.get(value, '') or '—'
        return _soft_wrap_long_token(_escape_xml(field_value), 50 if value != 'subject' else 60)
    
    story.append(Paragraph(f"<b>От:</b> {_format_field('from')}", normal_style))
    story.append(Paragraph(f"<b>Кому:</b> {_format_field('to')}", normal_style))
    story.append(Paragraph(f"<b>Тема:</b> {_format_field('subject')}", normal_style))
    story.append(Paragraph(f"<b>Дата:</b> {_format_field('date')}", normal_style))
    
    for field, label in [('reply_to', 'Reply-To'), ('return_path', 'Return-Path'), 
                         ('message_id', 'Message-ID'), ('references', 'References')]:
        val = parsed_email.get(field, '') or '—'
        story.append(Paragraph(f"<b>{label}:</b> {_soft_wrap_long_token(_escape_xml(val), 50)}", normal_style))
    
    story.append(Spacer(1, 0.12*inch))
    
    # Аутентификация
    story.append(Paragraph("РЕЗУЛЬТАТЫ АУТЕНТИФИКАЦИИ", heading_style))
    auth_data = [
        ['Метод', 'Результат'],
        ['SPF', header_analysis.get('spf_result', 'none').upper()],
        ['DKIM', header_analysis.get('dkim_result', 'none').upper()],
        ['DMARC', header_analysis.get('dmarc_result', 'none').upper()],
    ]
    auth_table = Table(auth_data, colWidths=[2*inch, 2*inch])
    auth_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), base_font),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('FONTNAME', (0, 1), (-1, -1), base_font),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    story.append(auth_table)
    story.append(Spacer(1, 0.12*inch))
    
    # Сработавшие правила
    triggered_rules = rules_result.get('triggered_rules', [])
    story.append(Paragraph("СРАБОТАВШИЕ ПРАВИЛА", heading_style))
    if triggered_rules:
        for rule in triggered_rules:
            rule_name = format_rule_name(rule.get('rule_name', 'unknown'))
            description = rule.get('description', '')
            story.append(Paragraph(f"• <b>{rule_name}:</b> {description}", normal_style))
    else:
        story.append(Paragraph("Ни одно правило не сработало", normal_style))
    story.append(Spacer(1, 0.12*inch))
    
    # URL
    urls = parsed_email.get('urls', [])
    if urls:
        story.append(Paragraph("URL В ТЕЛЕ ПИСЬМА", heading_style))
        malicious_domains = set(ti_results.get('malicious_domains', []))
        url_rows = [["Домен", "Статус", "URL"]]

        for url in urls:
            parsed_url = urlparse(url)
            domain = (parsed_url.netloc or "").lower()
            if ':' in domain:
                domain = domain.split(':')[0]
            found_in_ti = domain in malicious_domains
            status = "TI: найдено" if found_in_ti else "TI: не найдено"

            url_rows.append([
                Paragraph(_soft_wrap_long_token(_escape_xml(domain), 30), normal_style),
                Paragraph(status, normal_style),
                Paragraph(_soft_wrap_long_token(_escape_xml(url), 60), url_style),
            ])

        url_table = Table(url_rows, colWidths=[1.6*inch, 1.2*inch, 3.6*inch])
        url_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), base_font),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
            ('FONTNAME', (0, 1), (-1, -1), base_font),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ]))
        story.append(url_table)
        story.append(Spacer(1, 0.12*inch))
    
    # Вложения
    attachments = parsed_email.get('attachments', [])
    if attachments:
        story.append(Paragraph("ВЛОЖЕНИЯ", heading_style))
        for att in attachments:
            filename = _escape_xml(att.get('name', 'unknown'))
            size = att.get('size', 0)
            sha256 = att.get('sha256', '')
            if size > 1024 * 1024:
                size_str = f"{size / (1024 * 1024):.2f} MB"
            elif size > 1024:
                size_str = f"{size / 1024:.2f} KB"
            else:
                size_str = f"{size} B"
            story.append(Paragraph(f"• {filename} ({size_str}, SHA-256: {sha256[:16]}...)", normal_style))
        story.append(Spacer(1, 0.12*inch))
    
    # Threat Intelligence результаты
    malicious_domains_list = ti_results.get('malicious_domains', [])
    malicious_ips_list = ti_results.get('malicious_ips', [])
    
    if malicious_domains_list or malicious_ips_list:
        story.append(Paragraph("ИНДИКАТОРЫ КОМПРОМЕТАЦИИ (TI)", heading_style))
        
        if malicious_domains_list:
            story.append(Paragraph("<b>Обнаруженные вредоносные домены:</b>", normal_style))
            for domain in malicious_domains_list:
                story.append(Paragraph(f"  • {domain}", normal_style))
        
        if malicious_ips_list:
            story.append(Paragraph("<b>Обнаруженные вредоносные IP:</b>", normal_style))
            for ip in malicious_ips_list:
                story.append(Paragraph(f"  • {ip}", normal_style))
        
        story.append(Spacer(1, 0.12*inch))
    
    # ML результаты
    story.append(Paragraph("ML КЛАССИФИКАЦИЯ", heading_style))
    story.append(Paragraph(f"<b>Предсказание:</b> {ml_result.get('class_label', 'unknown').upper()}", normal_style))
    story.append(Paragraph(f"<b>Уверенность:</b> {ml_result.get('confidence', 0):.2%}", normal_style))
    story.append(Paragraph(f"<b>Вероятность фишинга:</b> {ml_result.get('phishing_probability', 0):.2%}", normal_style))
    
    # Сборка PDF
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()


def main():
    """
    Основная функция Streamlit приложения
    
    Структура интерфейса:
    1. Заголовок и описание
    2. Загрузка .eml файла
    3. Кнопка анализа
    4. Визуализация результатов:
       - Общий вердикт (цветовая индикация)
       - Итоговая оценка и оценки по правилам/ML (progress bars)
       - Таблица SPF/DKIM/DMARC
       - Список URL с репутацией
       - Список вложений с SHA-256 и ссылками на VirusTotal
       - Сработавшие правила
       - ML классификация
       - Детальный отчет
    5. Экспорт результатов
    """
    st.set_page_config(
        page_title="EML Analyzer",
        layout="wide"
    )
    
    st.markdown("""
    <style>
        :root { --primary-color: #5C778A; }
        .stButton>button[kind="primary"] {
            background-color: #5C778A;
            border-color: #5C778A;
        }
        .stButton>button[kind="primary"]:hover {
            background-color: #4a6170;
            border-color: #4a6170;
        }
    </style>
    """, unsafe_allow_html=True)
    
    st.title("Система анализа писем")
    
    # Инициализация pipeline (кэшируется)
    @st.cache_resource
    def get_pipeline():
        return EmailAnalysisPipeline()
    
    pipeline = get_pipeline()
    
    # Информация о последнем обновлении баз
    last_update_date = pipeline.threat_intelligence.get_last_update_date()
    if last_update_date:
        dt = datetime.strptime(last_update_date[:19], '%Y-%m-%d %H:%M:%S')
        st.markdown(f"""
        <div style="background-color: #e3f2fd; border-left: 4px solid #2196F3; padding: 12px; margin: 20px 0; border-radius: 4px;">
            <strong>Последнее обновление баз:</strong> {dt.strftime('%d-%m-%Y %H:%M')}
        </div>
        """, unsafe_allow_html=True)
    
    st.divider()
    
    st.markdown("Загрузите .eml файл для анализа письма с помощью ML и эвристических правил")
    
    # Загрузка файла
    uploaded_file = st.file_uploader(
        "Выберите .eml файл",
        type=['eml'],
        help="Загрузите письмо в формате .eml"
    )
    
    # Очистка результатов при удалении файла или загрузке нового
    if uploaded_file is None:
        # Файл удален - очистить session_state
        if 'analysis_results' in st.session_state:
            del st.session_state['analysis_results']
        if 'file_name' in st.session_state:
            del st.session_state['file_name']
    elif 'file_name' in st.session_state and st.session_state['file_name'] != uploaded_file.name:
        # Загружен новый файл - очистить старые результаты
        if 'analysis_results' in st.session_state:
            del st.session_state['analysis_results']
        st.session_state['file_name'] = uploaded_file.name
    
    if uploaded_file is not None:
        # Кнопка анализа
        if st.button("Начать анализ", type="primary", use_container_width=True):
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            def update_progress(message: str, percent: int):
                status_text.markdown(f"**{message}**")
                progress_bar.progress(percent / 100)
            
            try:
                # Чтение файла
                file_content = uploaded_file.read()
                
                # Выполнение анализа
                results = pipeline.analyze_email(file_content, progress_callback=update_progress)
                
                # Очистка прогресс-бара
                progress_bar.empty()
                status_text.empty()
                
                # Сохранение результатов в session state
                st.session_state['analysis_results'] = results
                st.session_state['file_name'] = uploaded_file.name
                
                st.success("Анализ завершен успешно")
                
            except Exception as e:
                progress_bar.empty()
                status_text.empty()
                st.error(f"Ошибка при анализе: {str(e)}")
                st.exception(e)
        
        # Отображение результатов
        if 'analysis_results' in st.session_state:
            results = st.session_state['analysis_results']
            
            # Вкладки
            tab1, tab2 = st.tabs(["Результаты анализа", "Детальная информация о письме"])
            
            with tab1:
                # Общий вердикт
                aggregation = results.get('aggregation_result', {})
                final_verdict = aggregation.get('final_verdict', 0)
                final_score = aggregation.get('final_score', 0)
                threshold = aggregation.get('aggregation', {}).get('threshold', 0.5)
                
                risk_level, color = format_verdict_color(final_score, threshold)
                verdict_text = "Подозрительное письмо" if final_verdict == 1 else "Легитимное письмо"
                
                # Применяем цвет к заголовку
                st.markdown(
                    f'<h2 style="color: {color};">{verdict_text}</h2>',
                    unsafe_allow_html=True
                )
                
                # Оценки под вердиктом
                rules_result = results.get('rules_result', {})
                ml_result = results.get('ml_result', {})
                risk_score = rules_result.get('risk_score', 0)
                ml_confidence = ml_result.get('phishing_probability', 0)
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.subheader("Результат")
                    st.progress(final_score)
                    st.metric("Результат", f"{final_score:.0%}", f"Порог: {threshold:.0%}", label_visibility="visible")
                
                with col2:
                    st.subheader("Эвристические правила")
                    st.progress(risk_score / 100.0)
                    st.metric("Эвристические правила", f"{risk_score}/100", label_visibility="visible")
                
                with col3:
                    st.subheader("Машинное обучение")
                    st.progress(ml_confidence)
                    st.metric("Машинное обучение", f"{ml_confidence:.0%}", label_visibility="visible")
                
                # Время анализа
                analysis_time = results.get('analysis_time', 0)
                st.caption(f"Время анализа: {format_duration_seconds(analysis_time)}")
                
                st.divider()
                
                # SPF/DKIM/DMARC
                header_analysis = results.get('header_analysis', {})
                parsed_email = results.get('parsed_email', {})
                display_authentication_results(header_analysis, parsed_email)
                
                st.divider()
                
                # URL с репутацией
                urls = parsed_email.get('urls', [])
                ti_results = results.get('ti_results', {})
                display_urls_with_reputation(urls, ti_results, parsed_email)
                
                st.divider()
                
                # Вложения
                attachments = parsed_email.get('attachments', [])
                display_attachments(attachments)
                
                st.divider()
                
                # Сработавшие правила
                display_triggered_rules(rules_result)
                
                st.divider()
                
                # ML результаты
                ml_result = results.get('ml_result', {})
                st.subheader("ML Классификация")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.metric(
                        "Предсказание",
                        ml_result.get('class_label', 'unknown').upper()
                    )
                
                with col2:
                    st.metric(
                        "Phishing Probability",
                        f"{ml_result.get('phishing_probability', 0):.2%}"
                    )
                
                st.divider()
                
                # Экспорт отчета
                st.subheader("Экспорт отчета")
                report_json = export_report_json(results)
                report_pdf = export_report_pdf(results)
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.download_button(
                        label="Скачать отчет (JSON)",
                        data=report_json,
                        file_name=f"phishing_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json",
                        use_container_width=True
                    )
                
                with col2:
                    st.download_button(
                        label="Скачать отчет (PDF)",
                        data=report_pdf,
                        file_name=f"phishing_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )
            
            with tab2:
                # Детальная информация о письме
                detected_language = results.get('detected_language', 'en')
                display_parsed_email_details(parsed_email, detected_language)
    
    else:
        st.info("Загрузите .eml файл для начала анализа")


if __name__ == "__main__":
    main()