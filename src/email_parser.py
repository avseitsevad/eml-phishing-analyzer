"""
Email Parser Module

Модуль парсинга email сообщений для системы детектирования фишинга.
Использует стандартную библиотеку email.parser
Поддерживает .eml файлы с декодированием UTF-8, Windows-1251, KOI8-R.

Основные функции:
- load_eml_file(): чтение и декодирование .eml файла
- parse_email(): парсинг структуры RFC 5322 + MIME

Извлекаемые компоненты:
- Заголовки: From, To, Subject, Date, Message-ID, Received, Authentication-Results,
  Reply-To, Return-Path
- Тело письма: text/plain и text/html с учетом multipart структур
- Вложения: метаданные (имя, тип, размер, SHA-256)
- URL-адреса, домены и IP-адреса из текста, HTML и заголовков
"""

import logging
import hashlib
import re
from pathlib import Path
from typing import Dict, List, Optional, Union, Any
from urllib.parse import urlparse
from email.parser import BytesParser
from email.policy import default
from email.message import EmailMessage
from bs4 import BeautifulSoup
from urlextract import URLExtract
from .utils import (
    timing_decorator,
    validate_eml_format,
    extract_hostname_from_url,
    normalize_domain,
    decode_text,
    IP_PATTERN,
    EMAIL_DOMAIN_PATTERN
)
import tldextract

# Регулярные выражения для парсинга доменов
DOMAIN_PATTERN = re.compile(r'^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$', re.IGNORECASE)
RECEIVED_DOMAIN_PATTERN = re.compile(r'from\s+((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,})', re.IGNORECASE)


url_extractor = URLExtract()
logger = logging.getLogger(__name__)


def load_eml_file(file_input: Union[str, Path, Any]) -> str:
    """
    Чтение файлового объекта/пути, декодирование с поддержкой UTF-8, 
    Windows-1251, KOI8-R, базовая валидация структуры.
    
    Args:
        file_input: Путь к файлу или файловый объект
        
    Returns:
        str: Содержимое письма как строка
        
    Raises:
        FileNotFoundError: Если файл не найден
        ValueError: Если файл невалиден или слишком короткий
    """
    # Чтение файла
    if isinstance(file_input, (str, Path)):
        path = Path(file_input)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        with open(path, 'rb') as f:
            content_bytes = f.read()
    elif hasattr(file_input, 'read'):
        content_bytes = file_input.read()
        if isinstance(content_bytes, str):
            content_bytes = content_bytes.encode('utf-8')
    else:
        raise ValueError(f"Unsupported input type: {type(file_input)}")
    
    # Декодирование с поддержкой UTF-8, Windows-1251, KOI8-R
    content_str = decode_text(content_bytes)
    
    # Валидация формата .eml
    if not validate_eml_format(content_str):
        raise ValueError("Provided content is not a valid .eml message")
    
    return content_str


def extract_headers(message: EmailMessage) -> Dict[str, Any]:
    """
    Извлекаемые заголовки:
    - Основные: From, To, Subject, Date, Message-ID
    - Маршрутизация: Received, Reply-To, Return-Path, References
    - Аутентификация: Authentication-Results
    - MIME: Content-Type (для определения структуры письма)
    
    Все заголовки возвращаются как строки (кроме 'received', который возвращается как список строк).
    """
    headers = {}
    required_headers = [
        'from', 'to', 'subject', 'date', 'message-id',
        'received', 'authentication-results', 
        'reply-to', 'return-path', 'references',
        'content-type'
    ]
    
    for header_name in required_headers:
        if header_name == 'received':
            values = message.get_all(header_name)
            if values:
                headers[header_name] = [str(v) if v else '' for v in values]
        else:
            value = message.get(header_name)
            if value:
                headers[header_name] = str(value)
    
    return headers


def extract_body(message: EmailMessage) -> Dict[str, str]:
    """
    Извлечение тела письма: text/plain и text/html.
    Обрабатывает multipart структуры (alternative, mixed, related).
    """
    body = {'text': '', 'html': ''}
    
    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get('Content-Disposition', '')).lower()
            
            if 'attachment' in content_disposition or part.is_multipart():
                continue
            
            if content_type == 'text/plain' and not body['text']:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or 'utf-8'
                    body['text'] = payload.decode(charset, errors='ignore').strip()
            elif content_type == 'text/html' and not body['html']:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or 'utf-8'
                    body['html'] = payload.decode(charset, errors='ignore').strip()
    else:
        content_type = message.get_content_type()
        payload = message.get_payload(decode=True)
        if payload:
            charset = message.get_content_charset() or 'utf-8'
            decoded = payload.decode(charset, errors='ignore').strip()
            if content_type == 'text/plain':
                body['text'] = decoded
            elif content_type == 'text/html':
                body['html'] = decoded
    
    return body


def extract_attachments_metadata(message: EmailMessage) -> List[Dict[str, Any]]:
    """
    Извлечение метаданных вложений.
    Не сохраняет файлы на диск - только метаданные.
    """
    attachments = []
    
    for part in message.walk():
        if part.is_multipart():
            continue
        
        content_disposition = str(part.get('Content-Disposition', '')).lower()
        
        if 'attachment' in content_disposition:
            filename = part.get_filename()
            content_type = part.get_content_type()
            payload = part.get_payload(decode=True)
            size = len(payload) if payload else 0
            sha256_hash = hashlib.sha256(payload).hexdigest() if payload else ''
            
            attachments.append({
                'filename': filename or 'unknown',
                'content_type': content_type,
                'size': size,
                'sha256': sha256_hash
            })
    
    return attachments


def extract_urls(message: EmailMessage, body: Optional[Dict[str, str]] = None) -> List[str]:
    """
    Извлечение URL из текста и HTML.
    Использует urlextract и BeautifulSoup для парсинга HTML.
    """
    urls = []
    
    if body is None:
        body = extract_body(message)
    
    # Из text/plain
    if body['text']:
        urls.extend(url_extractor.find_urls(body['text']))
    
    # Из text/html
    if body['html']:
        soup = BeautifulSoup(body['html'], 'html.parser')
        
        # Извлекаем URL из атрибутов тегов
        for tag in soup.find_all(['a', 'img', 'link', 'script', 'iframe', 'form']):
            for attr in ['href', 'src', 'action']:
                url = tag.get(attr)
                if url and isinstance(url, str):
                    urls.append(url.strip())
        
        # Ищем URL в тексте HTML
        urls.extend(url_extractor.find_urls(soup.get_text()))
    
    # Фильтрация и очистка
    cleaned_urls = [
        url.strip() for url in urls
        if url and (url.startswith(('http://', 'https://', 'ftp://')) or '://' in url)
    ]
    
    return list(set(cleaned_urls))


def extract_domains(
    message: EmailMessage,
    headers: Optional[Dict[str, Any]] = None,
    urls: Optional[List[str]] = None
) -> Dict[str, List[str]]:
    """
    Извлечение доменов и IP-адресов из:
    - URL в теле письма (с поддоменами 2, 3 и более уровней)
    - Email адресов в заголовках (From, To, Reply-To, Return-Path)
    - Заголовков Received
    
    Домены извлекаются целиком с сохранением всех уровней поддоменов.
    Префикс 'www.' автоматически удаляется из доменов.
    """
    domains: List[str] = []
    ips: List[str] = []
    
    remove_www = lambda d: d[4:] if d and d.lower().startswith('www.') else d
    
    # 1. Из URL в теле письма
    if urls is None:
        urls = extract_urls(message, body=None) 

    for url in urls:
        hostname, is_ip = extract_hostname_from_url(url)
        if not hostname:
            continue
        
        hostname = remove_www(hostname.lower())
        
        if is_ip:
            ips.append(hostname)
            continue
        
        if DOMAIN_PATTERN.match(hostname) or re.match(r'^[a-z0-9\.\-]+$', hostname, re.IGNORECASE):
            domains.append(hostname)
            normalized = normalize_domain(hostname)
            if normalized and normalized != hostname:
                domains.append(remove_www(normalized))
    
    # 2. Из email адресов в заголовках
    if headers is None:
        headers = extract_headers(message)
    for field in ['from', 'to', 'reply-to', 'return-path']:
        if header_value := headers.get(field, ''):
            for match in EMAIL_DOMAIN_PATTERN.finditer(header_value):
                email_domain = match.group(1)
                if email_domain and not IP_PATTERN.match(email_domain):
                    domains.append(remove_www(email_domain.lower()))
            ips.extend(IP_PATTERN.findall(header_value))
    
    # 3. Из заголовков Received
    received_headers = headers.get('received', [])
    if not isinstance(received_headers, list):
        received_headers = [received_headers] if received_headers else []
    
    for received in received_headers:
        received_str = str(received)
        for match in RECEIVED_DOMAIN_PATTERN.finditer(received_str):
            domain = match.group(1)
            if domain and not IP_PATTERN.match(domain):
                domains.append(remove_www(domain.lower()))
        ips.extend(IP_PATTERN.findall(received_str))
    
    # 4. Валидация IP-адресов
    valid_ips = []
    for ip in set(ips):
        parts = ip.split('.')
        if len(parts) == 4:
            try:
                if all(0 <= int(part) <= 255 for part in parts):
                    valid_ips.append(ip)
            except ValueError:
                continue
    
    result = {
        'domains': sorted(set(domains)),
        'ips': sorted(set(valid_ips))
    }
    
    return result


@timing_decorator
def parse_email(email_string: str) -> Dict[str, Any]:
    """
    Парсинг структуры RFC 5322 + MIME.
    Принимает строку с содержимым email и возвращает словарь с распарсенными данными.
    
    Args:
        email_string: Строка с содержимым .eml файла
        
    Returns:
        Dict с полями:
        - from, to, reply_to, return_path, subject, date, message_id, references
        - body_plain, body_html
        - auth_results
        - received_headers (list)
        - attachments (list of dicts with 'name', 'type', 'size')
        - urls (list)
        - domains (list)
        - ips (list)
    """
    # Конвертация строки в bytes для парсинга
    email_bytes = email_string.encode('utf-8', errors='replace')
    
    # Парсинг через стандартную библиотеку email.parser
    parser = BytesParser(policy=default)
    message = parser.parsebytes(email_bytes)
    
    if not message:
        raise ValueError("Parser returned empty message")
    
    # Извлечение данных
    headers = extract_headers(message)
    body = extract_body(message)
    urls = extract_urls(message, body=body)
    attachments_metadata = extract_attachments_metadata(message)
    # Передаем уже извлеченные headers и urls 
    domains_info = extract_domains(message, headers=headers, urls=urls)
    
    # Формирование результата в требуемом формате
    result = {
        'from': headers.get('from', ''),
        'to': headers.get('to', ''),
        'reply_to': headers.get('reply-to', ''),
        'return_path': headers.get('return-path', ''),
        'subject': headers.get('subject', ''),
        'date': headers.get('date', ''),
        'message_id': headers.get('message-id', ''),
        'references': headers.get('references', ''),
        'body_plain': body.get('text', ''),
        'body_html': body.get('html', ''),
        'auth_results': headers.get('authentication-results', ''),
        'received_headers': headers.get('received', []),
        'attachments': [
            {
                'name': att.get('filename', 'unknown'),
                'type': att.get('content_type', ''),
                'size': att.get('size', 0)
            }
            for att in attachments_metadata
        ],
        'urls': urls,
        'domains': domains_info.get('domains', []),
        'ips': domains_info.get('ips', [])
    }
    
    return result


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    print("Email Parser Module v2 - email.parser based")
    print("="*60)
    print("Features:")
    print("  - RFC 5322/2045-2049 compliant")
    print("  - Direct access to all headers including Content-Type")
    print("  - Proper multipart handling (mixed/alternative/и )")
    print("  - In-memory attachment processing with SHA-256 hashes")
    print("  - URL and domain extraction")

