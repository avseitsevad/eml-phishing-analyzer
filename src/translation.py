"""
Translation Module
Определение языка и машинный перевод
"""

import logging
from langdetect import detect
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
        installed_packages = argostranslate.package.get_installed_packages()
        self.translator = next(
            (pkg for pkg in installed_packages 
             if pkg.from_code == "ru" and pkg.to_code == "en"),
            None
        )
    
    def detect_language(self, text: str) -> str:
        """
        Автоматическое определение языка текста с использованием langdetect
        
        Args:
            text: текст для анализа
            
        Returns:
            str: код языка ('ru' или 'en')
        """
        if not text or len(text.strip()) < 3:
            return 'en'  # По умолчанию английский для коротких/пустых текстов
        
        try:
            return detect(text)
        except Exception as e:
            logger.warning(f"Language detection failed: {e}, defaulting to 'en'")
            return 'en'
    
    def translate_to_english(self, text: str, source_lang: str = 'ru') -> str:
        """
        Перевод русскоязычного текста на английский через Argos Translate
        
        Args:
            text: текст для перевода
            source_lang: исходный язык (по умолчанию 'ru')
            
        Returns:
            str: переведенный текст на английском
        """
        if source_lang == 'en':
            return text
        
        return argostranslate.translate.translate(text, "ru", "en")
    
    def process_email_text(self, subject: str, body: str) -> dict:
        """
        Pipeline обработки: определение языка → перевод при необходимости
        Обработка Subject и body письма
        
        Args:
            subject: тема письма
            body: тело письма
            
        Returns:
            dict: {
                'original_subject': str,
                'original_body': str,
                'translated_subject': str,
                'translated_body': str,
                'detected_language': str,
                'was_translated': bool
            }
        """
        original_subject = subject if subject else ""
        original_body = body if body else ""
        
        # Определяем язык по объединенному тексту
        combined_text = f"{original_subject} {original_body}".strip()
        detected_language = self.detect_language(combined_text)
        
        # Переводим только если язык русский
        was_translated = False
        translated_subject = original_subject
        translated_body = original_body
        
        if detected_language == 'ru':
            if original_subject:
                translated_subject = self.translate_to_english(original_subject, 'ru')
                was_translated = True
            if original_body:
                translated_body = self.translate_to_english(original_body, 'ru')
                was_translated = True
        
        return {
            'original_subject': original_subject,
            'original_body': original_body,
            'translated_subject': translated_subject,
            'translated_body': translated_body,
            'detected_language': detected_language,
            'was_translated': was_translated
        }