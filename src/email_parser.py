"""
Email Parser Module

Модуль парсинга email сообщений 
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

def load_eml_file(file_input: Union[str, Path, Any]) -> bytes:
    """
    Чтение файла и возврат содержимого как bytes для корректного парсинга.
    """
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
    
    # Базовая валидация - проверка на наличие заголовков
    try:
        content_str = content_bytes.decode('utf-8', errors='ignore')
        if not validate_eml_format(content_str):
            raise ValueError("Provided content is not a valid .eml message")
    except Exception:
        raise ValueError("Failed to decode .eml content")
    
    return content_bytes



def extract_headers(message: EmailMessage) -> Dict[str, Any]:
    """Извлечение заголовков с нормализацией имен."""
    headers = {}
    
    # Маппинг для нормализации имен заголовков
    header_mapping = {
        'from': 'From',
        'to': 'To',
        'subject': 'Subject',
        'date': 'Date',
        'message-id': 'Message-ID',
        'received': 'Received',
        'authentication-results': 'Authentication-Results',
        'reply-to': 'Reply-To',
        'return-path': 'Return-Path',
        'references': 'References',
        'content-type': 'Content-Type'
    }
    
    for key, header_name in header_mapping.items():
        if key == 'received':
            values = message.get_all(header_name, [])
            if values:
                headers[key] = [str(v).strip() if v else '' for v in values]
        else:
            value = message.get(header_name, '')
            if value:
                headers[key] = str(value).strip()
    
    return headers



def extract_body(message: EmailMessage) -> Dict[str, str]:
    """Извлечение тела письма: text/plain и text/html"""
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


def extract_attachments_metadata(message: EmailMessage, max_attachment_size: int = 50 * 1024 * 1024) -> List[Dict[str, Any]]:
    """
    Извлечение метаданных вложений
    
    Args:
        message: EmailMessage объект
        max_attachment_size: максимальный размер вложения в байтах
    
    Returns:
        List[Dict]: список метаданных вложений
    """
    attachments = []
    
    for part in message.walk():
        if part.is_multipart():
            continue
        
        content_disposition = str(part.get('Content-Disposition', '')).lower()
        
        if 'attachment' in content_disposition:
            filename = part.get_filename()
            content_type = part.get_content_type()
            
            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    size = 0
                    sha256_hash = ''
                else:
                    size = len(payload)
                    
                    if size > max_attachment_size:
                        attachments.append({
                            'filename': filename or 'unknown',
                            'content_type': content_type,
                            'size': size,
                            'sha256': 'skipped_too_large',
                            'error': f'Attachment size {size} exceeds limit {max_attachment_size}'
                        })
                        continue
                    
                    sha256_hash = hashlib.sha256(payload).hexdigest()
            except Exception:
                size = 0
                sha256_hash = ''
            
            attachments.append({
                'filename': filename or 'unknown',
                'content_type': content_type,
                'size': size,
                'sha256': sha256_hash
            })
    
    return attachments


def extract_urls(message: EmailMessage, body: Optional[Dict[str, str]] = None) -> List[str]:
    """Извлечение URL из текста и HTML"""
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
    """Извлечение доменов и IP-адресов из URL, заголовков и email адресов"""
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
def parse_email(email_input: Union[str, bytes]) -> Dict[str, Any]:
    """
    Парсинг email из строки или bytes.
    """
    # Определяем тип входных данных
    if isinstance(email_input, str):
        email_bytes = email_input.encode('utf-8', errors='replace')
    elif isinstance(email_input, bytes):
        email_bytes = email_input
    else:
        raise TypeError(f"Expected str or bytes, got {type(email_input).__name__}")
    
    if not email_bytes or not email_bytes.strip():
        raise ValueError("Email content cannot be empty")
    
    # Парсинг
    parser = BytesParser(policy=default)
    message = parser.parsebytes(email_bytes)
    
    if not message:
        raise ValueError("Parser returned empty message")
    
    # Извлечение данных
    headers = extract_headers(message)
    body = extract_body(message)
    urls = extract_urls(message, body=body)
    attachments_metadata = extract_attachments_metadata(message)
    domains_info = extract_domains(message, headers=headers, urls=urls)
    
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
                'size': att.get('size', 0),
                'sha256': att.get('sha256', '')
            }
            for att in attachments_metadata
        ],
        'urls': urls,
        'domains': domains_info.get('domains', []),
        'ips': domains_info.get('ips', [])
    }
    
    return result


