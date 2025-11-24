# EML Phishing Analyzer

Автоматизированная система детектирования фишинговых писем с использованием гибридного подхода (машинное обучение + эвристические правила).

## Описание

Система анализирует email-сообщения в формате .eml и выдает вердикт о легитимности письма на основе:
- Машинного обучения (70% веса в финальном решении)
- Эвристических правил (30% веса в финальном решении)
- Локальной базы индикаторов компрометации (URLhaus, OpenPhish)

**Ключевые особенности:**
- Полная автономность работы (офлайн после первичной настройки)
- Поддержка русского и английского языков
- Автоматический перевод русских писем для анализа
- Детальные отчеты с объяснением решения

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

## Установка

### 1. Клонирование репозитория
```bash
git clone <repository-url>
cd eml-phishing-analyzer
```

### 2. Установка зависимостей
```bash
pip install -r requirements.txt
```

### 3. Загрузка ресурсов NLTK
```python
python -c "import nltk; nltk.download('punkt'); nltk.download('stopwords'); nltk.download('wordnet'); nltk.download('omw-1.4')"
```

### 4. Загрузка языковых пакетов Argos Translate
```python
python -c "import argostranslate.package; argostranslate.package.update_package_index(); available = argostranslate.package.get_available_packages(); ru_en = next(filter(lambda x: x.from_code == 'ru' and x.to_code == 'en', available)); argostranslate.package.install_from_path(ru_en.download())"
```

### 5. Подготовка датасетов

- Загрузите **Nazario Phishing Corpus** и разместите в `data/raw/nazario/`
- Загрузите **Enron Email Dataset** и разместите в `data/raw/enron/`

### 6. Создание базы индикаторов компрометации
```bash
python scripts/update_threat_intel.py
```

## Использование

### Разработка и обучение моделей

#### 1. Подготовка данных

Откройте `notebooks/dataset_and_features.ipynb` и последовательно выполните:
- Загрузку и парсинг Nazario и Enron датасетов
- Exploratory Data Analysis (EDA)
- Балансировку выборок
- Извлечение признаков (синтетические + TF-IDF)
- Split на train/validation/test (70%/15%/15%)
- Сохранение в `data/processed/`

#### 2. Обучение и сравнение моделей

Откройте `notebooks/model_training_and_comparison.ipynb` и выполните:
- Обучение 5 алгоритмов (Logistic Regression, SVM, Random Forest, Naive Bayes, XGBoost)
- Кросс-валидацию на train set
- Сравнение на validation set
- Подбор гиперпараметров для лучшей модели
- Подбор весов агрегации (ml_weight, rule_weight)
- Финальную оценку на test set
- Сохранение лучшей модели и векторизатора в `data/models/`

### Запуск веб-интерфейса

После обучения модели запустите веб-приложение:
```bash
streamlit run web_interface/app.py
```

Интерфейс будет доступен по адресу: http://localhost:8501

### Обновление базы угроз

Для обновления локальной базы индикаторов компрометации:
```bash
python scripts/update_threat_intel.py
```

## Архитектура системы

### Pipeline обработки письма
```
Email Parser → Header Analyzer → URL Analyzer → 
Threat Intelligence ← Translation → Feature Extractor → 
Rules Engine ↘
                Aggregator → Web Interface
ML Classifier ↗
```

### Модули системы

**1. Email Parser Module** (`email_parser.py`)
- Парсинг .eml файлов (eml_parser)
- Извлечение заголовков, тела, вложений, URL и доменов
- Обработка multipart структур
- Вычисление SHA-256 хэшей вложений

**2. Header Analyzer Module** (`header_analyzer.py`)
- Парсинг SPF/DKIM/DMARC из Authentication-Results
- Сопоставление доменов From/Reply-To/Return-Path
- Проверка аномалии: "Re:" без References
- Валидация обязательных заголовков

**3. URL & Domain Analyzer Module** (`url_domain_analyzer.py`)
- Парсинг доменов (tldextract)
- Эвристический анализ доменов
- Детектирование URL-shorteners
- Обнаружение IP-адресов в URL

**4. Threat Intelligence Module** (`threat_intelligence.py`)
- Управление SQLite базой индикаторов
- Проверка URL/доменов/IP по локальной базе
- Интеграция с URLhaus и OpenPhish
- Кэширование результатов

**5. Translation Module** (`translation.py`)
- Определение языка текста (langdetect)
- Автоматический перевод ru→en (Argos Translate)
- Обработка Subject и body письма

**6. Feature Extractor Module** (`feature_extractor.py`)
- Извлечение синтетических признаков (counts, lengths, binary indicators)
- Предобработка текста (NLTK: токенизация, лемматизация, стоп-слова)
- TF-IDF векторизация
- Объединение всех признаков в единый вектор

**7. Rules Engine Module** (`rules_engine.py`)
- Проверка SPF/DKIM/DMARC
- Проверка несоответствия доменов
- Проверка репутации по TI-базе
- Проверка опасных вложений
- Формирование risk score (0-100)

**8. ML Classifier Module** (`ml_classifier.py`)
- Загрузка обученной модели
- Inference: feature vector → prediction
- Вычисление confidence score (0-1)

**9. Aggregator & Decision Module** (`aggregator.py`)
- Weighted average: ML confidence × 0.7 + normalized risk × 0.3
- Определение финального вердикта
- Формирование детализированного отчета

**10. Web Interface Module** (`app.py`)
- Streamlit интерфейс
- Загрузка .eml файлов
- Визуализация результатов анализа
- Экспорт отчетов

## Технологический стек

- **Python 3.12**
- **Парсинг email:** eml-parser, BeautifulSoup4, urlextract, tldextract
- **ML:** scikit-learn, XGBoost, pandas, numpy
- **NLP:** NLTK
- **Перевод:** Argos Translate, langdetect
- **БД:** SQLite
- **Веб:** Streamlit

## Требования к системе

### Функциональные требования
- Анализ .eml файлов с поддержкой RFC 5322 и MIME
- Детектирование фишинга на основе ML и правил
- Поддержка русского и английского языков
- Формирование детальных отчетов

### Нефункциональные требования
- **Производительность:** анализ письма ≤ 5 секунд
- **Точность:** Accuracy ≥ 95% (английские письма), ~90-92% (русские письма)
- **Автономность:** работа без интернета после первичной настройки
- **Расширяемость:** модульная архитектура

## Датасеты

**Phishing emails:**
- Nazario Phishing Corpus (2015-2024): https://monkey.org/~jose/phishing/

**Legitimate emails:**
- Enron Email Dataset: https://www.cs.cmu.edu/~enron/

**Threat Intelligence:**
- URLhaus: https://urlhaus.abuse.ch/
- OpenPhish: https://openphish.com/

## Разделение данных

- **Train:** 70% (обучение моделей)
- **Validation:** 15% (подбор весов агрегации и гиперпараметров)
- **Test:** 15% (финальная оценка)

