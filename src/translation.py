"""
Translation Module
Определение языка и машинный перевод
"""

import logging
from langdetect import detect, LangDetectException
import argostranslate.package
import argostranslate.translate

# Настройка логирования
logger = logging.getLogger(__name__)


class Translator:
    """
    Класс для автоматического определения языка и перевода русских текстов на английский
    Использует langdetect для определения языка и Argos Translate для перевода
    """
    
    def __init__(self):
        """
        Инициализация компонентов перевода
        Загрузка языковых пакетов Argos Translate (ru→en)
        """
        try:
            installed_packages = argostranslate.package.get_installed_packages()
            self.translator = next(
                (pkg for pkg in installed_packages 
                 if pkg.from_code == "ru" and pkg.to_code == "en"),
                None
            )
        except Exception as e:
            logger.error(f"Failed to initialize translation packages: {e}")
            self.translator = None
    
    def detect_language(self, text: str) -> str:
        """
        Автоматическое определение языка текста с использованием langdetect
        
        Args:
            text: текст для анализа
            
        Returns:
            str: код языка ('ru', 'en' или другой код языка)
        """
        if not text or not isinstance(text, str) or len(text.strip()) < 3:
            return 'en'
        
        try:
            return detect(text)
        except (LangDetectException, Exception):
            return 'en'
    
    def translate_to_english(self, text: str, source_lang: str = 'ru') -> str:
        """
        Перевод русскоязычного текста на английский через Argos Translate
        
        Args:
            text: текст для перевода
            source_lang: исходный язык (по умолчанию 'ru')
            
        Returns:
            str: переведенный текст на английском (или исходный текст при ошибке)
        """
        if not text or not isinstance(text, str):
            return text or ""
        
        if source_lang == 'en':
            return text
        
        if self.translator is None:
            return text
        
        try:
            return argostranslate.translate.translate(text, "ru", "en")
        except Exception as e:
            logger.error(f"Translation failed: {e}")
            return text
    
    def get_translated_text(self, subject: str, body: str) -> str:
        """
        Получение объединенного переведенного текста для использования в feature_extractor
        Объединяет subject и body в одну строку после перевода
        
        Args:
            subject: тема письма
            body: тело письма
            
        Returns:
            str: объединенный переведенный текст (subject + body)
        """
        subject = subject or ""
        body = body or ""
        
        # Определяем язык по объединенному тексту
        combined_text = f"{subject} {body}".strip()
        detected_language = self.detect_language(combined_text)
        
        # Переводим только если язык русский
        if detected_language == 'ru':
            translated_subject = self.translate_to_english(subject, 'ru')
            translated_body = self.translate_to_english(body, 'ru')
        else:
            translated_subject = subject
            translated_body = body
        
        # Объединяем переведенные части
        translated_parts = []
        if translated_subject:
            translated_parts.append(translated_subject)
        if translated_body:
            translated_parts.append(translated_body)
        
        return ' '.join(translated_parts).strip()
    
    def translate_parsed_email(self, parsed_email: dict) -> str:
        """
        Удобный метод для перевода письма из результата email_parser.parse_email()
        Автоматически объединяет body_plain и body_html
        
        Args:
            parsed_email: результат email_parser.parse_email() со следующими полями:
                - subject: str
                - body_plain: str
                - body_html: str
                
        Returns:
            str: объединенный переведенный текст (subject + body) для feature_extractor
        """
        subject = parsed_email.get('subject', '') or ''
        body_plain = parsed_email.get('body_plain', '') or ''
        body_html = parsed_email.get('body_html', '') or ''
        
        # Объединяем body_plain и body_html (приоритет body_plain)
        body = body_plain or body_html
        
        return self.get_translated_text(subject, body)