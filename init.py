"""
Init Script Module
Скрипт инициализации системы: создание БД, обновление баз угроз, запуск веб-интерфейса
"""

import sys
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(BASE_DIR))

from src.threat_intelligence import ThreatIntelligence
from scripts.update_threat_intel import (
    download_urlhaus_feed,
    download_openphish_feed,
    update_from_urlhaus,
    update_from_openphish
)


def init_database():
    """Создание базы данных threat intelligence"""
    db_path = BASE_DIR / "data" / "threat_intelligence" / "ti_database.db"
    ThreatIntelligence(str(db_path)).close()


def update_threat_intelligence():
    """Обновление баз данных threat intelligence"""
    db_path = BASE_DIR / "data" / "threat_intelligence" / "ti_database.db"
    ti = ThreatIntelligence(str(db_path))
    
    try:
        urlhaus_file = download_urlhaus_feed()
        if urlhaus_file:
            update_from_urlhaus(ti, urlhaus_file)
        
        openphish_file = download_openphish_feed()
        if openphish_file:
            update_from_openphish(ti, openphish_file)
    finally:
        ti.close()


def launch_web_interface():
    """Запуск веб-интерфейса Streamlit"""
    app_path = BASE_DIR / "web_interface" / "app.py"
    subprocess.run([sys.executable, "-m", "streamlit", "run", str(app_path)])


def main():
    """Основная функция инициализации"""
    init_database()
    update_threat_intelligence()
    launch_web_interface()


if __name__ == "__main__":
    main()

