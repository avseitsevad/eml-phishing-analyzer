"""
Translation Module
Определение языка и машинный перевод
"""

import logging
import re
import warnings
from bs4 import BeautifulSoup
from langdetect import detect, LangDetectException

# КРИТИЧНО: подавление логирования ПЕРЕД импортом argostranslate
logging.getLogger('argostranslate').setLevel(logging.ERROR)
logging.getLogger('argostranslate.utils').setLevel(logging.ERROR)
logging.getLogger('argostranslate.translate').setLevel(logging.ERROR)
logging.getLogger('ctranslate2').setLevel(logging.ERROR)
logging.getLogger('sentencepiece').setLevel(logging.ERROR)

# Подавление warnings от pkg_resources
warnings.filterwarnings('ignore', category=DeprecationWarning, module='pkg_resources')
warnings.filterwarnings('ignore', message='.*pkg_resources.*')

import argostranslate.package
import argostranslate.translate

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
        self.from_code = "ru"
        self.to_code = "en"
        self.translator_available = False
        
        try:
            # Обновляем список доступных пакетов (тихо)
            argostranslate.package.update_package_index()
            
            # Проверяем установленные языки
            installed_languages = argostranslate.translate.get_installed_languages()
            has_ru = any(lang.code == "ru" for lang in installed_languages)
            has_en = any(lang.code == "en" for lang in installed_languages)
            
            # Если языки не установлены, пытаемся установить пакет
            if not (has_ru and has_en):
                logger.info("Russian→English translation package not found, attempting installation...")
                available_packages = argostranslate.package.get_available_packages()
                ru_to_en = next(
                    (pkg for pkg in available_packages 
                     if pkg.from_code == "ru" and pkg.to_code == "en"),
                    None
                )
                if ru_to_en:
                    try:
                        logger.info("Downloading and installing Russian→English translation package...")
                        argostranslate.package.install_from_path(ru_to_en.download())
                        logger.info("Package installed successfully")
                        # Перезагружаем языки
                        argostranslate.translate.load_installed_languages()
                        installed_languages = argostranslate.translate.get_installed_languages()
                        has_ru = any(lang.code == "ru" for lang in installed_languages)
                        has_en = any(lang.code == "en" for lang in installed_languages)
                    except Exception as install_error:
                        logger.error(f"Failed to install translation package: {install_error}")
            
            # Проверяем доступность перевода
            if has_ru and has_en:
                try:
                    # Пробуем получить объект перевода
                    translation = argostranslate.translate.get_translation_from_codes(self.from_code, self.to_code)
                    if translation:
                        self.translator_available = True
                        logger.info("Argos Translate ru→en translation available")
                    else:
                        logger.warning("Translation object not available despite languages being installed")
                except Exception as e:
                    logger.warning(f"Could not get translation object: {e}")
            else:
                logger.error("Russian→English translation package not available")
                
        except Exception as e:
            logger.error(f"Failed to initialize translation packages: {e}")
            self.translator_available = False
    
    @staticmethod
    def strip_html_tags(html_text: str) -> str:
        """
        Удаление HTML-тегов и извлечение чистого текста
        
        Args:
            html_text: HTML-разметка
            
        Returns:
            str: очищенный текст без тегов
        """
        if not html_text or not isinstance(html_text, str):
            return ""
        
        try:
            soup = BeautifulSoup(html_text, 'html.parser')
            # Удаляем script и style блоки
            for script in soup(["script", "style"]):
                script.decompose()
            # Извлекаем текст
            text = soup.get_text(separator=' ', strip=True)
            # Убираем множественные пробелы
            text = re.sub(r'\s+', ' ', text)
            return text.strip()
        except Exception as e:
            logger.error(f"HTML stripping failed: {e}")
            # Fallback: простое удаление тегов regex
            return re.sub(r'<[^>]+>', ' ', html_text).strip()
    
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
        
        # Очищаем от HTML если есть теги
        if '<' in text and '>' in text:
            text = self.strip_html_tags(text)
        
        # Проверяем минимальную длину текста
        if len(text.strip()) < 10:
            return 'en'
        
        try:
            return detect(text)
        except (LangDetectException, Exception) as e:
            logger.debug(f"Language detection failed: {e}")
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
        
        # Если уже английский - не переводим
        if source_lang == 'en':
            return text
        
        # Если переводчик недоступен - возвращаем оригинал
        if not self.translator_available:
            logger.warning("Translator not available, returning original text")
            return text
        
        try:
            # Используем правильный API Argos Translate
            translation = argostranslate.translate.get_translation_from_codes(self.from_code, self.to_code)
            if translation:
                translated = translation.translate(text)
                
                # Проверяем что перевод реально произошел
                if translated and translated != text:
                    logger.debug(f"Translation successful: {len(text)} → {len(translated)} chars")
                    return translated
                else:
                    logger.warning("Translation returned original text, may indicate failure")
                    return text
            else:
                logger.warning("Could not get translation object")
                return text
                
        except Exception as e:
            logger.error(f"Translation failed: {e}")
            return text
    
    def prepare_text_for_translation(self, parsed_email: dict) -> tuple:
        """
        Подготовка текста письма: очистка HTML и объединение компонентов
        
        Args:
            parsed_email: результат email_parser.parse_email()
            
        Returns:
            tuple: (subject, body_clean) где body_clean - очищенное тело письма
        """
        subject = parsed_email.get('subject', '') or ''
        body_plain = parsed_email.get('body_plain', '') or ''
        body_html = parsed_email.get('body_html', '') or ''
        
        # Приоритет body_plain, но если его нет - чистим HTML
        if body_plain:
            body_clean = body_plain
        elif body_html:
            body_clean = self.strip_html_tags(body_html)
        else:
            body_clean = ''
        
        return subject, body_clean
    
    def get_translated_text(self, subject: str, body: str) -> str:
        """
        Получение объединенного переведенного текста для использования в feature_extractor
        Объединяет subject и body в одну строку после перевода
        
        Args:
            subject: тема письма (уже очищенная)
            body: тело письма (уже очищенное от HTML)
            
        Returns:
            str: объединенный переведенный текст (subject + body)
        """
        subject = subject or ""
        body = body or ""
        
        # Определяем язык по объединенному тексту
        combined_text = f"{subject} {body}".strip()
        
        if not combined_text:
            return ""
        
        detected_language = self.detect_language(combined_text)
        logger.info(f"Detected language: {detected_language}")
        
        # Переводим только если язык русский
        if detected_language == 'ru':
            translated_subject = self.translate_to_english(subject, 'ru')
            translated_body = self.translate_to_english(body, 'ru')
        else:
            translated_subject = subject
            translated_body = body
        
        # Объединяем переведенные части
        result_parts = []
        if translated_subject:
            result_parts.append(translated_subject)
        if translated_body:
            result_parts.append(translated_body)
        
        return ' '.join(result_parts).strip()
    
    def translate_parsed_email(self, parsed_email: dict) -> str:
        """
        Удобный метод для перевода письма из результата email_parser.parse_email()
        Автоматически очищает HTML и объединяет body_plain и body_html
        
        Args:
            parsed_email: результат email_parser.parse_email() со следующими полями:
                - subject: str
                - body_plain: str
                - body_html: str
                
        Returns:
            str: объединенный переведенный текст (subject + body) для feature_extractor
        """
        # Подготовка: очистка HTML и выбор body
        subject, body_clean = self.prepare_text_for_translation(parsed_email)
        
        # Перевод очищенного текста
        return self.get_translated_text(subject, body_clean)