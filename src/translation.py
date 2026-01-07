"""
Translation Module
Определение языка и машинный перевод
"""

import logging
import re
import warnings
from langdetect import detect, LangDetectException

for logger_name in ['argostranslate', 'argostranslate.utils', 'argostranslate.translate', 
                     'argostranslate.package', 'ctranslate2', 'sentencepiece']:
    logger_obj = logging.getLogger(logger_name)
    logger_obj.setLevel(logging.CRITICAL)
    logger_obj.addHandler(logging.NullHandler())
    logger_obj.propagate = False

warnings.filterwarnings('ignore', category=DeprecationWarning, module='pkg_resources')
warnings.filterwarnings('ignore', message='.*pkg_resources.*')

import argostranslate.package
import argostranslate.translate


class Translator:
    """Автоматическое определение языка и перевод русских текстов на английский"""
    
    def __init__(self):
        """Инициализация компонентов перевода"""
        self.from_code = "ru"
        self.to_code = "en"
        self.translator_available = False
        
        try:
            argostranslate.package.update_package_index()
            
            installed_languages = argostranslate.translate.get_installed_languages()
            has_ru = any(lang.code == "ru" for lang in installed_languages)
            has_en = any(lang.code == "en" for lang in installed_languages)
            
            if not (has_ru and has_en):
                available_packages = argostranslate.package.get_available_packages()
                ru_to_en = next(
                    (pkg for pkg in available_packages 
                     if pkg.from_code == "ru" and pkg.to_code == "en"),
                    None
                )
                if ru_to_en:
                    try:
                        argostranslate.package.install_from_path(ru_to_en.download())
                        argostranslate.translate.load_installed_languages()
                        installed_languages = argostranslate.translate.get_installed_languages()
                        has_ru = any(lang.code == "ru" for lang in installed_languages)
                        has_en = any(lang.code == "en" for lang in installed_languages)
                    except Exception:
                        pass
            
            if has_ru and has_en:
                try:
                    translation = argostranslate.translate.get_translation_from_codes(self.from_code, self.to_code)
                    if translation:
                        self.translator_available = True
                except Exception:
                    pass
                
        except Exception:
            self.translator_available = False
    
    def detect_language(self, text: str) -> str:
        """
        Автоматическое определение языка текста с использованием langdetect
        
        Args:
            text: текст для анализа
            
        Returns:
            str: код языка ('ru', 'en' или другой код языка)
        """
        if not text or not isinstance(text, str):
            return 'en'
        
        # Проверяем минимальную длину текста
        if len(text.strip()) < 10:
            return 'en'
        
        try:
            return detect(text)
        except (LangDetectException, Exception):
            return 'en'
    
    def translate_to_english(self, text: str, source_lang: str = 'ru') -> str:
        """
        Перевод текста на английский через Argos Translate
        
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
        
        if not self.translator_available:
            return text
        
        try:
            translation = argostranslate.translate.get_translation_from_codes(self.from_code, self.to_code)
            if translation:
                translated = translation.translate(text)
                if translated and translated != text:
                    return translated
                else:
                    return text
            else:
                return text
                
        except Exception:
            return text
    
    def translate_text(self, text: str) -> str:
        """
        Перевод текста на английский язык (если требуется)
        
        Args:
            text: текст для перевода
            
        Returns:
            str: переведенный текст на английском (или исходный, если уже английский)
        """
        if not text or not isinstance(text, str):
            return ""
        
        detected_language = self.detect_language(text)
        
        if detected_language == 'ru':
            translated = self.translate_to_english(text, 'ru')
            return translated
        else:
            return text