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
    
    # Добавляем файловый handler, если указан
    if log_file:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding='utf-8'))
    
    logging.basicConfig(
        level=numeric_level,
        format=log_format,
        datefmt=date_format,
        handlers=handlers,
        force=True  # Перезаписываем существующую конфигурацию
    )
    
    # Устанавливаем уровень для сторонних библиотек
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)


def validate_eml_format(email_content: Union[str, bytes]) -> bool:
    """
    Валидация формата .eml файла согласно RFC 5322 и MIME.
    
    Args:
        email_content: Содержимое email (строка или байты)
        
    Returns:
        bool: True если формат валиден, False иначе
    """
    try:
        # Преобразуем в строку, если это байты
        if isinstance(email_content, bytes):
            email_content = decode_text(email_content)
        
        if not email_content or not email_content.strip():
            return False
        
        # Базовые проверки RFC 5322
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
            
            # Проверка формата заголовка (ключ: значение)
            if ':' in line:
                has_headers = True
            elif not line.startswith(' ') and not line.startswith('\t'):
                # Если строка не является продолжением заголовка
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
    # Если уже строка, возвращаем как есть
    if isinstance(text, str):
        return text
    
    # Если байты, пробуем декодировать
    if isinstance(text, bytes):
        for encoding in encodings:
            try:
                decoded = text.decode(encoding)
                return decoded
            except (UnicodeDecodeError, LookupError):
                continue
        
        # Если не удалось декодировать, пробуем с обработкой ошибок
        for encoding in encodings:
            try:
                decoded = text.decode(encoding, errors='replace')
                logging.warning(f"Декодирование с заменой ошибок в {encoding}")
                return decoded
            except LookupError:
                continue
        
        # Последняя попытка - UTF-8 с заменой ошибок
        return text.decode('utf-8', errors='replace')
    
    # Если другой тип, преобразуем в строку
    return str(text)


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
    # Если уже строка, возвращаем как есть
    if isinstance(text, str):
        return text, 'utf-8'
    
    # Если байты, пробуем декодировать
    if isinstance(text, bytes):
        for encoding in encodings:
            try:
                decoded = text.decode(encoding)
                return decoded, encoding
            except (UnicodeDecodeError, LookupError):
                continue
        
        # Если не удалось декодировать, пробуем с обработкой ошибок
        for encoding in encodings:
            try:
                decoded = text.decode(encoding, errors='replace')
                logging.warning(f"Декодирование с заменой ошибок в {encoding}")
                return decoded, encoding
            except LookupError:
                continue
        
        # Последняя попытка - UTF-8 с заменой ошибок
        return text.decode('utf-8', errors='replace'), 'utf-8'
    
    # Если другой тип, преобразуем в строку
    return str(text), 'utf-8'


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


# Инициализация логирования при импорте модуля (опционально)
# Можно вызвать setup_logging() явно в главном модуле
# setup_logging()
