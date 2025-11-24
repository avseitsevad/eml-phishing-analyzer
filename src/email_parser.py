"""
Email Parser Module (Исправленная версия)

Модуль парсинга email сообщений с поддержкой различных форматов входных данных:
- .eml файлы
- Текстовые строки из CSV датасетов (Nazario, Enron)
- Байтовые последовательности

Извлекаемые компоненты:
- Заголовки (headers): From, To, Subject, Date, Authentication-Results и др.
- Тело письма (body): text/plain и text/html части
- Вложения (attachments): метаданные и SHA-256 хэши
- URL-адреса из текста и HTML
- Домены и IP-адреса из URL и заголовков
- Multipart структуры
"""


import logging
import hashlib
import re
from pathlib import Path
from typing import Dict, List, Optional, Union, Any
import eml_parser
from bs4 import BeautifulSoup
from urlextract import URLExtract
import tldextract


# Инициализация URLExtract для извлечения URL
url_extractor = URLExtract()

# Настройка логирования
logger = logging.getLogger(__name__)


def timing_decorator(func):
    """Декоратор для измерения времени выполнения функции"""
    import time
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        elapsed_time = time.time() - start_time
        logger.debug(f"{func.__name__} executed in {elapsed_time:.4f} sec")
        return result
    return wrapper


def validate_eml_format(email_str: str) -> bool:
    """
    Базовая валидация формата email.
    
    Проверяет наличие основных компонентов email сообщения:
    - Заголовки (хотя бы один из: From, To, Subject, Message-ID, Date)
    - Разделитель между заголовками и телом (двойной перевод строки)
    
    Args:
        email_str: Строка с содержимым email
        
    Returns:
        bool: True если формат корректен, False иначе
    """
    if not email_str or not isinstance(email_str, str):
        return False
    
    # Проверка наличия базовых заголовков
    basic_headers = ['From:', 'To:', 'Subject:', 'Message-ID:', 'Date:']
    has_header = any(header.lower() in email_str.lower()[:1000] for header in basic_headers)
    
    # Проверка наличия разделителя заголовков и тела
    has_separator = '\n\n' in email_str or '\r\n\r\n' in email_str
    
    return has_header and has_separator


def decode_text(content: Union[str, bytes]) -> str:
    """
    Универсальная функция декодирования текста.
    
    Пробует различные кодировки для корректного декодирования содержимого.
    
    Args:
        content: Текст или байты для декодирования
        
    Returns:
        str: Декодированная строка
    """
    if isinstance(content, str):
        return content
    
    if not isinstance(content, bytes):
        return str(content)
    
    # Список кодировок для попытки декодирования
    encodings = ['utf-8', 'windows-1251', 'iso-8859-1', 'cp1252']
    
    for encoding in encodings:
        try:
            return content.decode(encoding)
        except (UnicodeDecodeError, AttributeError):
            continue
    
    # Если все попытки не удались, используем utf-8 с игнорированием ошибок
    return content.decode('utf-8', errors='ignore')


@timing_decorator
def parse_eml(email_content: Union[str, bytes, Path]) -> Dict[str, Any]:
    """
    Парсинг email с использованием eml_parser.
    Поддерживает RFC 5322 и MIME (RFC 2046).
    
    Улучшенная версия с корректной обработкой различных форматов:
    - Путь к .eml файлу
    - Текстовая строка из CSV датасета
    - Байтовая последовательность
    
    Args:
        email_content: Содержимое email (строка, байты или путь к файлу)
        
    Returns:
        dict: Словарь с распарсенными данными email
        
    Raises:
        ValueError: Если формат email невалиден или парсинг не удался
    """
    email_bytes = None
    
    # 1. Обработка входных данных
    if isinstance(email_content, Path):
        # Если передан объект Path
        if email_content.exists() and email_content.is_file():
            with open(email_content, 'rb') as f:
                email_bytes = f.read()
        else:
            raise ValueError(f"File not found: {email_content}")
            
    elif isinstance(email_content, str):
        # Если передана строка
        # Сначала проверяем длину строки
        if len(email_content) < 256:
            # Только короткие строки проверяем как пути к файлам
            try:
                file_path = Path(email_content)
                if file_path.exists() and file_path.is_file():
                    with open(file_path, 'rb') as f:
                        email_bytes = f.read()
                else:
                    # Короткая строка, но не файл - это содержимое email
                    email_bytes = email_content.encode('utf-8', errors='replace')
            except (OSError, ValueError):
                # Ошибка при работе с путем - это содержимое email
                email_bytes = email_content.encode('utf-8', errors='replace')
        else:
            # Длинная строка - это точно содержимое email из CSV
            email_bytes = email_content.encode('utf-8', errors='replace')
            
    elif isinstance(email_content, bytes):
        # Если уже байты - используем как есть
        email_bytes = email_content
    else:
        raise ValueError(f"Unsupported input data type: {type(email_content)}")
    
    # 2. Валидация формата (опциональная проверка)
    try:
        email_str = decode_text(email_bytes)
        if not validate_eml_format(email_str):
            logger.warning("Email format may be invalid, continuing parsing")
    except Exception as e:
        logger.warning(f"Error during format validation: {e}")
    
    # 3. Парсинг через eml_parser
    try:
        ep = eml_parser.EmlParser(
            include_raw_body=True,
            include_attachment_data=True
        )
        parsed = ep.decode_email_bytes(email_bytes)
        
        if not parsed:
            raise ValueError("Failed to parse email")
        
        logger.debug(f"Email successfully parsed, found {len(parsed.get('header', {}))} headers")
        
        return parsed
        
    except Exception as e:
        logger.error(f"Error parsing email via eml_parser: {e}")
        raise ValueError(f"Email parsing error: {e}")


def extract_headers(parsed_email: Dict[str, Any]) -> Dict[str, Any]:
    """
    Извлечение заголовков email.
    
    Извлекаемые заголовки:
    - Основные: From, To, Subject, Date, Message-ID
    - Маршрутизация: Received, Return-Path, Reply-To
    - Аутентификация: Authentication-Results, DKIM-Signature, SPF, DMARC
    - Дополнительные: Content-Type, MIME-Version, X-* заголовки
    
    Args:
        parsed_email: Результат парсинга от parse_eml()
        
    Returns:
        dict: Словарь с заголовками (ключи в нижнем регистре)
    """
    headers = {}
    
    try:
        email_headers = parsed_email.get('header', {})
        
        if not email_headers:
            logger.warning("Headers not found in parsed email")
            return headers
        
        # Список основных заголовков
        priority_headers = [
            'from', 'to', 'subject', 'date', 'message-id',
            'received', 'return-path', 'reply-to', 'cc', 'bcc',
            'authentication-results', 'dkim-signature',
            'content-type', 'mime-version',
            'x-mailer', 'x-originating-ip'
        ]
        
        # Извлечение приоритетных заголовков
        for key in priority_headers:
            value = email_headers.get(key) or email_headers.get(key.lower()) or email_headers.get(key.upper())
            
            if value:
                # Обработка списков (некоторые заголовки могут быть списками)
                if isinstance(value, list):
                    headers[key] = value[0] if value else None
                else:
                    headers[key] = value
        
        # Извлечение всех остальных заголовков
        for key, value in email_headers.items():
            normalized_key = key.lower()
            if normalized_key not in headers:
                if isinstance(value, list):
                    headers[normalized_key] = value[0] if value else None
                else:
                    headers[normalized_key] = value
        
        logger.debug(f"Extracted {len(headers)} headers")
        
    except Exception as e:
        logger.error(f"Error extracting headers: {e}")
    
    return headers


def extract_body(parsed_email: Dict[str, Any]) -> Dict[str, str]:
    """
    Извлечение тела письма: text/plain и text/html.
    
    Args:
        parsed_email: Результат парсинга от parse_eml()
        
    Returns:
        dict: Словарь с ключами 'text' и 'html'
    """
    body = {
        'text': '',
        'html': ''
    }
    
    try:
        email_body = parsed_email.get('body', [])
        
        if isinstance(email_body, list):
            # Стандартный формат eml_parser - список частей
            for part in email_body:
                content_type = part.get('content_type', '').lower()
                content = part.get('content', '')
                
                if 'text/plain' in content_type:
                    body['text'] = decode_text(content) if content else ''
                elif 'text/html' in content_type:
                    body['html'] = decode_text(content) if content else ''
        
        elif isinstance(email_body, dict):
            # Альтернативный формат - словарь с ключами text/html
            if 'text' in email_body:
                text_parts = email_body['text']
                if isinstance(text_parts, list) and text_parts:
                    body['text'] = decode_text(text_parts[0])
                elif isinstance(text_parts, str):
                    body['text'] = decode_text(text_parts)
            
            if 'html' in email_body:
                html_parts = email_body['html']
                if isinstance(html_parts, list) and html_parts:
                    body['html'] = decode_text(html_parts[0])
                elif isinstance(html_parts, str):
                    body['html'] = decode_text(html_parts)
        
        # Если тело не найдено через body, пробуем raw_body
        if not body['text'] and not body['html']:
            raw_body = parsed_email.get('raw_body', [])
            if raw_body:
                if isinstance(raw_body, list):
                    # Берем первую часть
                    body['text'] = decode_text(raw_body[0]) if raw_body else ''
                elif isinstance(raw_body, (str, bytes)):
                    body['text'] = decode_text(raw_body)
        
        logger.debug(f"Extracted body: text={len(body['text'])} chars, html={len(body['html'])} chars")
        
    except Exception as e:
        logger.error(f"Error extracting body: {e}")
    
    return body


def extract_multipart(parsed_email: Dict[str, Any]) -> Dict[str, Any]:
    """
    Обработка multipart структур (multipart/mixed, multipart/alternative).
    
    Args:
        parsed_email: Результат парсинга от parse_eml()
        
    Returns:
        dict: Информация о multipart структуре
    """
    multipart_info = {
        'is_multipart': False,
        'content_type': '',
        'type': 'single',
        'parts': []
    }
    
    try:
        headers = parsed_email.get('header', {})
        content_type = headers.get('content-type', '') or headers.get('content_type', '')
        
        if isinstance(content_type, list):
            content_type = content_type[0] if content_type else ''
        
        content_type_str = str(content_type).lower()
        
        # Проверка наличия multipart в Content-Type
        if 'multipart' in content_type_str:
            multipart_info['is_multipart'] = True
            multipart_info['content_type'] = content_type
            
            # Определение типа multipart
            if 'multipart/mixed' in content_type_str:
                multipart_info['type'] = 'mixed'
            elif 'multipart/alternative' in content_type_str:
                multipart_info['type'] = 'alternative'
            elif 'multipart/related' in content_type_str:
                multipart_info['type'] = 'related'
            else:
                multipart_info['type'] = 'other'
            
            # Извлечение информации о частях (body parts)
            body = parsed_email.get('body', [])
            if isinstance(body, list):
                for part in body:
                    part_info = {
                        'content_type': part.get('content_type', 'unknown'),
                        'size': len(str(part.get('content', '')))
                    }
                    multipart_info['parts'].append(part_info)
            
            # Добавление информации о вложениях как части multipart
            attachments = parsed_email.get('attachment', [])
            if attachments:
                for att in attachments:
                    part_info = {
                        'content_type': att.get('content_type', 'unknown'),
                        'size': att.get('size', 0),
                        'is_attachment': True,
                        'filename': att.get('filename', 'unknown')
                    }
                    multipart_info['parts'].append(part_info)
            
            logger.debug(f"Found multipart structure: {multipart_info['type']}, parts: {len(multipart_info['parts'])}")
        
    except Exception as e:
        logger.error(f"Error processing multipart: {e}")
    
    return multipart_info


def extract_attachments_metadata(parsed_email: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Извлечение метаданных вложений (имя, тип, размер).
    
    Args:
        parsed_email: Результат парсинга от parse_eml()
        
    Returns:
        list: Список словарей с метаданными вложений
    """
    attachments = []
    
    try:
        email_attachments = parsed_email.get('attachment', [])
        
        if not email_attachments:
            return attachments
        
        for att in email_attachments:
            metadata = {
                'filename': att.get('filename', 'unknown'),
                'content_type': att.get('content_type', 'unknown'),
                'size': 0,
                'content_disposition': att.get('content_disposition', '')
            }
            
            # Определение размера вложения
            raw_data = att.get('raw', b'')
            if raw_data:
                metadata['size'] = len(raw_data)
            else:
                # Альтернативный способ через payload
                content = att.get('payload', '') or att.get('content', '')
                if content:
                    if isinstance(content, bytes):
                        metadata['size'] = len(content)
                    else:
                        metadata['size'] = len(str(content))
            
            attachments.append(metadata)
        
        logger.debug(f"Extracted metadata for {len(attachments)} attachments")
        
    except Exception as e:
        logger.error(f"Error extracting attachment metadata: {e}")
    
    return attachments


def compute_attachment_hashes(parsed_email: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Вычисление SHA-256 хэшей вложений (in-memory).
    
    Args:
        parsed_email: Результат парсинга от parse_eml()
        
    Returns:
        list: Список словарей с filename и sha256 хэшем
    """
    hashes = []
    
    try:
        email_attachments = parsed_email.get('attachment', [])
        
        if not email_attachments:
            return hashes
        
        for att in email_attachments:
            filename = att.get('filename', 'unknown')
            raw_data = att.get('raw', b'')
            
            if raw_data:
                # Вычисление SHA-256 хэша
                sha256_hash = hashlib.sha256(raw_data).hexdigest()
                hashes.append({
                    'filename': filename,
                    'sha256': sha256_hash
                })
            else:
                # Попытка через payload
                payload = att.get('payload', '') or att.get('content', '')
                if payload:
                    if isinstance(payload, str):
                        payload_bytes = payload.encode('utf-8', errors='ignore')
                    else:
                        payload_bytes = payload
                    
                    sha256_hash = hashlib.sha256(payload_bytes).hexdigest()
                    hashes.append({
                        'filename': filename,
                        'sha256': sha256_hash
                    })
                else:
                    logger.warning(f"Failed to compute hash for attachment: {filename}")
        
        logger.debug(f"Computed {len(hashes)} SHA-256 hashes for attachments")
        
    except Exception as e:
        logger.error(f"Error computing attachment hashes: {e}")
    
    return hashes


def extract_urls(parsed_email: Dict[str, Any]) -> List[str]:
    """
    Извлечение URL из текста и HTML тела письма.
    
    Использует URLExtract для обнаружения URL в тексте и BeautifulSoup
    для извлечения URL из HTML-атрибутов (href, src).
    
    Args:
        parsed_email: Результат парсинга от parse_eml()
        
    Returns:
        list: Список уникальных URL
    """
    urls = []
    
    try:
        # Извлечение тела письма
        body = extract_body(parsed_email)
        
        # 1. Извлечение URL из text/plain
        if body['text']:
            try:
                text_urls = url_extractor.find_urls(body['text'])
                urls.extend(text_urls)
            except Exception as e:
                logger.warning(f"Error extracting URLs from text: {e}")
        
        # 2. Извлечение URL из text/html
        if body['html']:
            try:
                soup = BeautifulSoup(body['html'], 'html.parser')
                
                # Извлечение URL из атрибутов href, src, action
                for tag in soup.find_all(['a', 'img', 'link', 'script', 'iframe', 'form']):
                    for attr in ['href', 'src', 'action']:
                        url = tag.get(attr)
                        if url and isinstance(url, str):
                            urls.append(url.strip())
                
                # Также извлекаем URL из текста HTML через urlextract
                html_text = soup.get_text()
                html_urls = url_extractor.find_urls(html_text)
                urls.extend(html_urls)
                
            except Exception as e:
                logger.warning(f"Error parsing HTML: {e}")
                # Fallback: извлечение URL напрямую из HTML строки
                try:
                    html_urls = url_extractor.find_urls(body['html'])
                    urls.extend(html_urls)
                except:
                    pass
        
        # 3. Очистка и фильтрация URL
        cleaned_urls = []
        for url in urls:
            url = url.strip()
            # Фильтрация корректных URL (начинаются с протокола)
            if url and (url.startswith(('http://', 'https://', 'ftp://')) or '://' in url):
                cleaned_urls.append(url)
        
        # Удаление дубликатов
        unique_urls = list(set(cleaned_urls))
        
        logger.debug(f"Extracted {len(unique_urls)} unique URLs")
        
    except Exception as e:
        logger.error(f"Error extracting URLs: {e}")
        unique_urls = []
    
    return unique_urls


def extract_domains(parsed_email: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Извлечение доменов и IP-адресов из email.
    
    Источники доменов:
    - URL в теле письма
    - Email адреса в заголовках (From, To, Reply-To, Return-Path)
    - IP-адреса в URL и заголовках Received
    
    Args:
        parsed_email: Результат парсинга от parse_eml()
        
    Returns:
        dict: Словарь с ключами:
            - 'domains': список уникальных доменов из URL
            - 'ips': список уникальных IP-адресов
            - 'email_domains': домены из email адресов в заголовках
    """
    domains = []
    ips = []
    email_domains = []
    
    try:
        # 1. Извлечение доменов из URL
        urls = extract_urls(parsed_email)
        
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        
        for url in urls:
            try:
                # Проверка на IP-адрес в URL
                ip_match = ip_pattern.search(url)
                if ip_match:
                    ip = ip_match.group()
                    if ip not in ips:
                        ips.append(ip)
                else:
                    # Извлечение домена через tldextract
                    extracted = tldextract.extract(url)
                    if extracted.domain and extracted.suffix:
                        domain = f"{extracted.domain}.{extracted.suffix}"
                        if domain not in domains:
                            domains.append(domain.lower())
            except Exception as e:
                logger.debug(f"Error extracting domain from URL {url}: {e}")
        
        # 2. Извлечение доменов из email адресов в заголовках
        headers = extract_headers(parsed_email)
        email_header_fields = ['from', 'to', 'reply-to', 'return-path', 'cc', 'bcc']
        
        email_pattern = re.compile(r'[\w\.-]+@([\w\.-]+\.\w+)', re.IGNORECASE)
        
        for field in email_header_fields:
            header_value = headers.get(field, '')
            if not header_value:
                continue
            
            # Извлечение email адресов и их доменов
            email_matches = email_pattern.findall(str(header_value))
            for email_domain in email_matches:
                email_domain_lower = email_domain.lower()
                if email_domain_lower not in email_domains:
                    email_domains.append(email_domain_lower)
            
            # Извлечение IP-адресов из заголовков
            ip_matches = ip_pattern.findall(str(header_value))
            for ip in ip_matches:
                if ip not in ips:
                    ips.append(ip)
        
        # 3. Извлечение доменов и IP из заголовка Received
        received_headers = headers.get('received', [])
        if not isinstance(received_headers, list):
            received_headers = [received_headers] if received_headers else []
        
        for received in received_headers:
            received_str = str(received)
            
            # Поиск доменов в Received (паттерн: from domain.com)
            domain_matches = re.findall(
                r'from\s+([\w\.-]+\.\w+)',
                received_str,
                re.IGNORECASE
            )
            for domain in domain_matches:
                domain_lower = domain.lower()
                if domain_lower not in domains:
                    domains.append(domain_lower)
            
            # Поиск IP-адресов в Received
            ip_matches = ip_pattern.findall(received_str)
            for ip in ip_matches:
                if ip not in ips:
                    ips.append(ip)
        
        # 4. Валидация IP-адресов
        valid_ips = []
        for ip in ips:
            parts = ip.split('.')
            if len(parts) == 4:
                try:
                    if all(0 <= int(part) <= 255 for part in parts):
                        valid_ips.append(ip)
                except ValueError:
                    continue
        
        # 5. Объединение всех доменов
        all_domains = list(set(domains + email_domains))
        
        result = {
            'domains': sorted(all_domains),
            'ips': sorted(list(set(valid_ips))),
            'email_domains': sorted(list(set(email_domains)))
        }
        
        logger.debug(f"Extracted domains: {len(result['domains'])}, IPs: {len(result['ips'])}, email domains: {len(result['email_domains'])}")
        
    except Exception as e:
        logger.error(f"Error extracting domains: {e}")
        result = {
            'domains': [],
            'ips': [],
            'email_domains': []
        }
    
    return result


def parse_email(email_content: Union[str, bytes, Path]) -> Dict[str, Any]:
    """
    Главная функция парсинга email с извлечением всех компонентов.
    
    Универсальная функция, объединяющая все этапы парсинга:
    1. Парсинг базовой структуры email
    2. Извлечение заголовков
    3. Извлечение тела письма (text/html)
    4. Анализ multipart структуры
    5. Обработка вложений (метаданные и хэши)
    6. Извлечение URL
    7. Извлечение доменов и IP-адресов
    
    Args:
        email_content: Содержимое email в одном из форматов:
            - Путь к .eml файлу (str или Path)
            - Текстовая строка с содержимым email (из CSV)
            - Байтовая последовательность
        
    Returns:
        dict: Словарь со всеми извлеченными данными:
            - headers: заголовки email
            - body: тело письма (text, html)
            - multipart: информация о multipart структуре
            - attachments_metadata: метаданные вложений
            - attachment_hashes: SHA-256 хэши вложений
            - urls: список извлеченных URL
            - domains: домены и IP-адреса
            - raw_parsed: исходный результат парсинга (для отладки)
    
    Raises:
        ValueError: При критических ошибках парсинга
    """
    try:
        # 1. Парсинг email через eml_parser
        parsed = parse_eml(email_content)
        
        # 2. Извлечение всех компонентов
        result = {
            'headers': extract_headers(parsed),
            'body': extract_body(parsed),
            'multipart': extract_multipart(parsed),
            'attachments_metadata': extract_attachments_metadata(parsed),
            'attachment_hashes': compute_attachment_hashes(parsed),
            'urls': extract_urls(parsed),
            'domains': extract_domains(parsed),
            'raw_parsed': parsed
        }
        
        logger.info(
            f"Email successfully parsed: "
            f"headers={len(result['headers'])}, "
            f"URLs={len(result['urls'])}, "
            f"domains={len(result['domains']['domains'])}"
        )
        
        return result
        
    except Exception as e:
        logger.error(f"Critical error parsing email: {e}")
        raise


# Для тестирования модуля
if __name__ == "__main__":
    # Настройка логирования для тестов
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("Email Parser Module - Fixed version")
    print("Module ready to use")