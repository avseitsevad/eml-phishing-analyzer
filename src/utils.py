"""
Utils Module

Вспомогательные функции для проекта:
- Загрузка конфигурации
- Настройка логирования
- Валидация .eml формата
- Обработка различных кодировок
- Декоратор измерения времени выполнения
"""


import os
import json
import logging
import functools
import time
from pathlib import Path
from typing import Any, Dict, Callable, Optional, Union


def load_config(config_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Загружает конфигурационный файл (JSON).
    
    Args:
        config_path: Путь к конфигурационному файлу
        
    Returns:
        dict: Словарь с конфигурацией
        
    Raises:
        FileNotFoundError: Если файл не найден
        json.JSONDecodeError: Если файл содержит невалидный JSON
    """
    config_path = Path(config_path)
    
    if not config_path.exists():
        raise FileNotFoundError(f"Конфигурационный файл не найден: {config_path}")
    
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
    
    return config


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[Union[str, Path]] = None,
    log_format: Optional[str] = None
) -> None:
    """
    Настройка логирования для проекта.
    
    Args:
        log_level: Уровень логирования (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Путь к файлу для записи логов (опционально)
        log_format: Формат логов (опционально)
    """
    if log_format is None:
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Настройка формата даты
    date_format = '%Y-%m-%d %H:%M:%S'
    
    # Настройка уровня логирования
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Базовая конфигурация
    handlers = [logging.StreamHandler()]
    
    if log_file:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding='utf-8'))
    
    logging.basicConfig(
        level=numeric_level,
        format=log_format,
        datefmt=date_format,
        handlers=handlers,
        force=True
    )
    
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)

# Добавить в src/utils.py

import re
from urllib.parse import urlparse
from typing import Optional, Tuple
import tldextract

def extract_hostname_from_url(url: str) -> Tuple[Optional[str], bool]:
    """
    Извлекает hostname из URL и определяет, является ли он IP-адресом
    
    Args:
        url: URL для парсинга
    
    Returns:
        tuple: (hostname, is_ip) где is_ip=True если hostname это IP-адрес
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc or (parsed.path.split('/')[0] if parsed.path else None)
        
        if not hostname:
            return None, False
        
        # Удаляем порт
        hostname = hostname.rsplit(':', 1)[0] if ':' in hostname else hostname
        
        # Проверяем, является ли IP-адресом
        is_ip = bool(IP_PATTERN.match(hostname))
        return hostname, is_ip
    except Exception:
        return None, False

def normalize_domain(hostname: str) -> Optional[str]:
    """
    Нормализует домен используя tldextract
    
    Args:
        hostname: hostname для нормализации
    
    Returns:
        str: нормализованный домен (domain.suffix) или None
    """
    try:
        extracted = tldextract.extract(hostname)
        normalized = f"{extracted.domain}.{extracted.suffix}".lower()
        return normalized if normalized and normalized != '.' else None
    except Exception:
        return None


def normalize_domain_for_ti(domain: str) -> Optional[str]:
    """
    Нормализует домен для Threat Intelligence проверки.
    Возвращает domain.suffix в нижнем регистре.
    
    Args:
        domain: домен для нормализации
    
    Returns:
        str: нормализованный домен (domain.suffix) или None
    """
    if not domain:
        return None
    
    try:
        extracted = tldextract.extract(domain)
        normalized = f"{extracted.domain}.{extracted.suffix}".lower()
        return normalized if normalized and normalized != '.' else None
    except Exception:
        return None

def validate_eml_format(email_content: Union[str, bytes]) -> bool:
    """
    Валидация формата .eml файла согласно RFC 5322 и MIME.
    
    Args:
        email_content: Содержимое email (строка или байты)
        
    Returns:
        bool: True если формат валиден, False иначе
    """
    try:
        if isinstance(email_content, bytes):
            email_content = decode_text(email_content)
        
        if not email_content or not email_content.strip():
            return False
        
        if len(email_content) <= 50:
            return False
        
        lines = email_content.split('\n')
        
        # Должны быть заголовки
        has_headers = False
        header_end = False
        
        for i, line in enumerate(lines):
            # Проверка на пустую строку (разделитель заголовков и тела)
            if not line.strip():
                header_end = True
                if i > 0:
                    has_headers = True
                break
            
            if ':' in line:
                has_headers = True
            elif not line.startswith(' ') and not line.startswith('\t'):
                if has_headers:
                    header_end = True
                    break
        
        if not has_headers:
            return False
        
        # Проверка наличия обязательных заголовков (хотя бы одного из основных)
        required_headers = ['From', 'To', 'Subject', 'Date']
        email_lower = email_content.lower()
        has_required = any(f'{header.lower()}:' in email_lower for header in required_headers)
        
        return has_required
        
    except Exception as e:
        logging.warning(f"Ошибка при валидации .eml формата: {e}")
        return False


def _decode_with_encoding(
    text: Union[str, bytes],
    encodings: list
) -> tuple[str, str]:
    """
    Внутренняя функция для декодирования текста с возвратом текста и кодировки.
    
    Args:
        text: Текст для декодирования (строка или байты)
        encodings: Список кодировок для попытки декодирования
        
    Returns:
        tuple: (декодированный_текст, найденная_кодировка)
    """
    if isinstance(text, str):
        return text, 'utf-8'
    
    if isinstance(text, bytes):
        for encoding in encodings:
            try:
                decoded = text.decode(encoding)
                return decoded, encoding
            except (UnicodeDecodeError, LookupError):
                continue
        
        for encoding in encodings:
            try:
                decoded = text.decode(encoding, errors='replace')
                logging.warning(f"Декодирование с заменой ошибок в {encoding}")
                return decoded, encoding
            except LookupError:
                continue
        
        return text.decode('utf-8', errors='replace'), 'utf-8'
    
    return str(text), 'utf-8'


def decode_text(
    text: Union[str, bytes],
    encodings: list = ['utf-8', 'windows-1251', 'koi8-r']
) -> str:
    """
    Обрабатывает различные кодировки текста.
    Пробует декодировать текст в указанных кодировках.
    
    Args:
        text: Текст для декодирования (строка или байты)
        encodings: Список кодировок для попытки декодирования
        
    Returns:
        str: Декодированный текст в UTF-8
        
    Raises:
        UnicodeDecodeError: Если не удалось декодировать ни в одной кодировке
    """
    decoded, _ = _decode_with_encoding(text, encodings)
    return decoded


def handle_encoding(
    text: Union[str, bytes],
    encodings: list = ['utf-8', 'windows-1251', 'koi8-r']
) -> tuple[str, str]:
    """
    Обрабатывает различные кодировки и возвращает декодированный текст и найденную кодировку.
    
    Args:
        text: Текст для декодирования (строка или байты)
        encodings: Список кодировок для попытки декодирования
        
    Returns:
        tuple: (декодированный_текст, найденная_кодировка)
    """
    return _decode_with_encoding(text, encodings)


def timing_decorator(func: Callable) -> Callable:
    """
    Декоратор для измерения времени выполнения функции.
    
    Args:
        func: Функция для обертки
        
    Returns:
        Обернутая функция с логированием времени выполнения
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            elapsed_time = time.time() - start_time
            logging.info(
                f"Функция {func.__name__} выполнена за {elapsed_time:.4f} секунд"
            )
            return result
        except Exception as e:
            elapsed_time = time.time() - start_time
            logging.error(
                f"Функция {func.__name__} завершилась с ошибкой за {elapsed_time:.4f} секунд: {e}"
            )
            raise
    
    return wrapper


def save_results(results: dict, output_path: Union[str, Path]) -> None:
    """
    Сохраняет результаты анализа в JSON файл.
    
    Args:
        results: Словарь с результатами
        output_path: Путь для сохранения
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)


# Общие константы для проекта (используются в 2+ модулях)
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 
    'cutt.ly', 'rb.gy', 'j.mp', 'tiny.cc', 'short.link',
    'is.gd', 'buff.ly', 'rebrand.ly', 'bitly.com'
}

# Регулярные выражения для парсинга
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
EMAIL_DOMAIN_PATTERN = re.compile(r'@([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', re.IGNORECASE)
