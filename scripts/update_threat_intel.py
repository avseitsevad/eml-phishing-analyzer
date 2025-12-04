"""
Скрипт обновления локальной базы индикаторов компрометации
Поддерживает загрузку и импорт данных из URLhaus и OpenPhish
"""

import argparse
import csv
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

import requests

# Добавляем путь к src для импорта модулей
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.threat_intelligence import ThreatIntelligence
from src.utils import extract_hostname_from_url, normalize_domain, normalize_domain_for_ti

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Константы
URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
BATCH_SIZE = 1000
PROGRESS_INTERVAL = 10000
CHUNK_SIZE = 8192
DOWNLOAD_TIMEOUT = 30


def download_feed(url: str, output_filename: str, download_dir: Optional[str] = None) -> Optional[str]:
    """Универсальная функция загрузки фида"""
    if download_dir is None:
        download_dir = Path(__file__).parent.parent / "data" / "threat_intelligence"
    else:
        download_dir = Path(download_dir)
    
    download_dir.mkdir(parents=True, exist_ok=True)
    output_file = download_dir / output_filename
    
    logger.info(f"Загрузка фида из {url}")
    response = requests.get(url, timeout=DOWNLOAD_TIMEOUT, stream=True)
    response.raise_for_status()
    
    total_size = int(response.headers.get('content-length', 0))
    downloaded = 0
    
    with open(output_file, 'wb') as f:
        for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
            if chunk:
                f.write(chunk)
                downloaded += len(chunk)
                if total_size > 0:
                    percent = (downloaded / total_size) * 100
                    print(f"\rПрогресс: {percent:.1f}%", end='', flush=True)
    
    print()
    logger.info(f"Фид загружен: {output_file} ({downloaded:,} байт)")
    return str(output_file)


def download_urlhaus_feed(download_dir: Optional[str] = None) -> Optional[str]:
    """Загрузка CSV фида от URLhaus"""
    return download_feed(URLHAUS_CSV_URL, "urlhaus_recent.csv", download_dir)


def download_openphish_feed(download_dir: Optional[str] = None) -> Optional[str]:
    """Загрузка фида от OpenPhish"""
    return download_feed(OPENPHISH_FEED_URL, "openphish_feed.txt", download_dir)


def _process_url_for_urlhaus(url: str, threat_type: str, date_added: str) -> Optional[Tuple[str, str, str, str, str]]:
    """Обрабатывает URL для URLhaus и возвращает кортеж для вставки в БД"""
    hostname, is_ip = extract_hostname_from_url(url)
    if not hostname:
        return None
    
    if is_ip:
        return (hostname, threat_type, date_added, 'URLhaus', 'ip')
    
    normalized_domain = normalize_domain(hostname)
    if normalized_domain:
        return (normalized_domain, threat_type, date_added, 'URLhaus', 'domain')
    return None


def _process_url_for_openphish(url: str, date_added: str) -> Optional[Tuple[str, str, str, str]]:
    """Обрабатывает URL для OpenPhish и возвращает кортеж для вставки в БД"""
    hostname, is_ip = extract_hostname_from_url(url)
    if not hostname or is_ip:
        return None
    
    normalized_domain = normalize_domain(hostname)
    if normalized_domain:
        return (normalized_domain, 'phishing', date_added, 'OpenPhish')
    return None


def update_from_urlhaus(ti_instance: ThreatIntelligence, csv_path: str):
    """Загрузка и импорт данных из URLhaus. Формат: CSV с заголовком после комментариев."""
    cursor = ti_instance.conn.cursor()
    date_added = datetime.now().isoformat()
    imported_domains = 0
    imported_ips = 0
    skipped_count = 0
    total_rows = 0
    
    domains_batch = []
    ips_batch = []
    
    logger.info(f"Начало импорта из {csv_path}")
    
    # URLhaus CSV структура: комментарии с #, затем заголовок с #, затем данные
    # Заголовок: # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
    with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
        # Пропускаем все строки с комментариями (включая заголовок с #)
        data_lines = []
        for line in f:
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                data_lines.append(line)
        
        if not data_lines:
            logger.warning("Файл не содержит данных")
            return
        
        # Используем фиксированные имена колонок из заголовка URLhaus
        reader = csv.DictReader(
            data_lines,
            fieldnames=['id', 'dateadded', 'url', 'url_status', 'last_online', 'threat', 'tags', 'urlhaus_link', 'reporter']
        )
        
        for row in reader:
            total_rows += 1
            url = row.get('url', '').strip().strip('"')
            if not url:
                skipped_count += 1
                continue
            
            threat_type = row.get('threat', '').strip().strip('"') or 'malicious'
            
            result = _process_url_for_urlhaus(url, threat_type, date_added)
            if result:
                data, _, _, _, data_type = result
                if data_type == 'ip':
                    ips_batch.append((data, threat_type, date_added, 'URLhaus'))
                    if len(ips_batch) >= BATCH_SIZE:
                        cursor.executemany("""
                            INSERT OR IGNORE INTO malicious_ips 
                            (ip, threat_type, date_added, source)
                            VALUES (?, ?, ?, ?)
                        """, ips_batch)
                        imported_ips += cursor.rowcount
                        ips_batch.clear()
                else:
                    domains_batch.append((data, threat_type, date_added, 'URLhaus'))
                    if len(domains_batch) >= BATCH_SIZE:
                        cursor.executemany("""
                            INSERT OR IGNORE INTO malicious_domains 
                            (domain, threat_type, date_added, source)
                            VALUES (?, ?, ?, ?)
                        """, domains_batch)
                        imported_domains += cursor.rowcount
                        domains_batch.clear()
            else:
                skipped_count += 1
            
            if total_rows % PROGRESS_INTERVAL == 0:
                logger.info(f"Обработано строк: {total_rows:,}")
    
    # Финальные вставки
    if domains_batch:
        cursor.executemany("""
            INSERT OR IGNORE INTO malicious_domains 
            (domain, threat_type, date_added, source)
            VALUES (?, ?, ?, ?)
        """, domains_batch)
        imported_domains += cursor.rowcount
    
    if ips_batch:
        cursor.executemany("""
            INSERT OR IGNORE INTO malicious_ips 
            (ip, threat_type, date_added, source)
            VALUES (?, ?, ?, ?)
        """, ips_batch)
        imported_ips += cursor.rowcount
    
    ti_instance.conn.commit()
    logger.info(
        f"Импорт из URLhaus завершен: "
        f"обработано строк {total_rows:,}, "
        f"импортировано доменов {imported_domains:,}, IP {imported_ips:,}, "
        f"пропущено {skipped_count:,}"
    )
    
    ti_instance.cache.clear()


def update_from_openphish(ti_instance: ThreatIntelligence, feed_path: str):
    """Загрузка и импорт данных из OpenPhish. Формат: текстовый файл, один URL на строку."""
    cursor = ti_instance.conn.cursor()
    date_added = datetime.now().isoformat()
    imported_count = 0
    skipped_count = 0
    total_lines = 0
    
    domains_batch = []
    
    logger.info(f"Начало импорта из {feed_path}")
    
    with open(feed_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            total_lines += 1
            url = line.strip()
            if not url:
                continue
            
            result = _process_url_for_openphish(url, date_added)
            if result:
                domains_batch.append(result)
                
                if len(domains_batch) >= BATCH_SIZE:
                    cursor.executemany("""
                        INSERT OR IGNORE INTO malicious_domains 
                        (domain, threat_type, date_added, source)
                        VALUES (?, ?, ?, ?)
                    """, domains_batch)
                    imported_count += cursor.rowcount
                    domains_batch.clear()
            else:
                skipped_count += 1
            
            if total_lines % PROGRESS_INTERVAL == 0:
                logger.info(f"Обработано строк: {total_lines:,}")
    
    # Вставляем оставшиеся записи
    if domains_batch:
        cursor.executemany("""
            INSERT OR IGNORE INTO malicious_domains 
            (domain, threat_type, date_added, source)
            VALUES (?, ?, ?, ?)
        """, domains_batch)
        imported_count += cursor.rowcount
    
    ti_instance.conn.commit()
    logger.info(
        f"Импорт из OpenPhish завершен: "
        f"обработано строк {total_lines:,}, "
        f"импортировано {imported_count:,}, пропущено {skipped_count:,}"
    )
    
    ti_instance.cache.clear()


def main():
    """Основная функция скрипта"""
    parser = argparse.ArgumentParser(
        description='Обновление локальной базы индикаторов компрометации',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  # Обновить из обоих источников (автоматическая загрузка)
  python scripts/update_threat_intel.py --urlhaus --openphish
  
  # Обновить только URLhaus из локального файла
  python scripts/update_threat_intel.py --urlhaus --urlhaus-file path/to/urlhaus.csv
  
  # Обновить только OpenPhish из локального файла
  python scripts/update_threat_intel.py --openphish --openphish-file path/to/openphish.txt
  
  # Указать путь к БД
  python scripts/update_threat_intel.py --urlhaus --db-path custom/path/ti.db
        """
    )
    
    parser.add_argument('--urlhaus', action='store_true', help='Обновить данные из URLhaus')
    parser.add_argument('--openphish', action='store_true', help='Обновить данные из OpenPhish')
    parser.add_argument('--urlhaus-file', type=str, default=None,
                       help='Путь к локальному CSV файлу URLhaus')
    parser.add_argument('--openphish-file', type=str, default=None,
                       help='Путь к локальному файлу фида OpenPhish')
    parser.add_argument('--db-path', type=str, default=None,
                       help='Путь к файлу базы данных')
    parser.add_argument('--download-dir', type=str, default=None,
                       help='Директория для сохранения загруженных фидов')
    
    args = parser.parse_args()
    
    if not args.urlhaus and not args.openphish:
        parser.error("Необходимо указать хотя бы один источник: --urlhaus или --openphish")
    
    # Определяем путь к БД
    db_path = Path(args.db_path) if args.db_path else \
              Path(__file__).parent.parent / "data" / "threat_intelligence" / "ti.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    logger.info(f"Используется база данных: {db_path}")
    
    ti = ThreatIntelligence(str(db_path))
    
    try:
        if args.urlhaus:
            logger.info("=" * 60)
            logger.info("Обновление из URLhaus")
            logger.info("=" * 60)
            if args.urlhaus_file is None:
                args.urlhaus_file = download_urlhaus_feed(args.download_dir)
            update_from_urlhaus(ti, args.urlhaus_file)
        
        if args.openphish:
            logger.info("=" * 60)
            logger.info("Обновление из OpenPhish")
            logger.info("=" * 60)
            if args.openphish_file is None:
                args.openphish_file = download_openphish_feed(args.download_dir)
            update_from_openphish(ti, args.openphish_file)
        
        logger.info("=" * 60)
        logger.info("Обновление базы данных завершено успешно")
        logger.info("=" * 60)
        
    finally:
        ti.close()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())