# EML Phishing Analyzer

Автоматизированная система детектирования фишинговых писем с использованием гибридного подхода (машинное обучение + эвристические правила).

## Описание

Система анализирует email-сообщения в формате .eml и выдает вердикт о легитимности письма на основе:
- Машинного обучения 
- Эвристических правил
- Локальной базы индикаторов компрометации (URLhaus, OpenPhish)


## Структура проекта
```
eml-phishing-analyzer/
├── data/
│   ├── raw/                    # Исходные датасеты
│   │   ├── nazario/            # Nazario Phishing Corpus (фишинг)
│   │   └── enron/              # Enron Email Dataset (легитимные)
│   ├── processed/              # Предобработанные датасеты (train/val/test)
│   ├── models/                 # Обученная модель + TfidfVectorizer
│   └── threat_intelligence/
│       └── indicators.db       # SQLite база (URLhaus, OpenPhish)
├── src/                        # Модули системы
│   ├── __init__.py
│   ├── utils.py                # Вспомогательные функции
│   ├── email_parser.py         # Модуль 1: Парсинг .eml файлов
│   ├── header_analyzer.py      # Модуль 2: Анализ заголовков
│   ├── url_domain_analyzer.py  # Модуль 3: Анализ URL и доменов
│   ├── threat_intelligence.py  # Модуль 4: Работа с TI-базой
│   ├── translation.py          # Модуль 5: Определение языка и перевод
│   ├── feature_extractor.py    # Модуль 6: Извлечение признаков
│   ├── rules_engine.py         # Модуль 7: Эвристические правила
│   ├── ml_classifier.py        # Модуль 8: ML-классификация
│   └── aggregator.py           # Модуль 9: Агрегация результатов
├── scripts/
│   └── update_threat_intel.py  # Обновление базы индикаторов
├── web_interface/
│   └── app.py                  # Модуль 10: Streamlit веб-интерфейс
├── notebooks/                  # Jupyter ноутбуки для разработки
│   ├── dataset_and_features.ipynb            # Подготовка данных и признаков
│   └── model_training_and_comparison.ipynb   # Обучение и сравнение моделей
├── requirements.txt
└── README.md
```


