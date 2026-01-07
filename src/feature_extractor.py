"""
Feature Extractor Module
Извлечение признаков и векторизация текста
"""

import re
import pickle
from pathlib import Path
from typing import Dict, Any, Tuple, List, Optional
from urllib.parse import urlparse
import tldextract

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS
from sklearn.preprocessing import MinMaxScaler
import nltk
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer
from nltk.corpus import stopwords
from bs4 import BeautifulSoup

from .utils import IP_PATTERN, extract_hostname_from_url

# Инициализация NLTK компонентов
for resource in ['tokenizers/punkt', 'corpora/stopwords', 'corpora/wordnet']:
    try:
        nltk.data.find(resource)
    except LookupError:
        nltk.download(resource.split('/')[-1], quiet=True)

lemmatizer = WordNetLemmatizer()
STOP_WORDS = set(stopwords.words('english'))

# Артефакты датасета - слова, специфичные для конкретных датасетов, которые не должны попадать в TF-IDF признаки
DATASET_ARTIFACTS = {
    'jose',      # Имя из тестовых данных Nazario
    'enron',     # Название компании из Enron датасета
    'ect',       # Сокращение из Enron датасета 
    'monkey',    # Часть домена monkey.org из тестовых данных
    'org',       # Часть доменов .org (фильтруется только как отдельное слово)
    'nazario',
    'corp',
    'houston',
    'usaa',
    'dow',
    'jones'        
}

# Объединяем стоп-слова и артефакты датасета
ALL_STOP_WORDS = STOP_WORDS | DATASET_ARTIFACTS

# Ключевые слова срочности (английские - т.к. текст уже переведен)
URGENCY_KEYWORDS = {
    'urgent', 'immediately', 'asap', 'as soon as possible', 'hurry',
    'expire', 'expiring', 'expires', 'expiration', 'deadline',
    'action required', 'verify', 'verify now', 'confirm', 'update',
    'suspended', 'suspend', 'locked', 'lock', 'blocked', 'block',
    'security', 'security alert', 'unauthorized', 'fraud', 'fraudulent',
    'verify account', 'verify email', 'click here', 'click now',
    'limited time', 'limited offer', 'act now', 'don\'t miss'
}

# Константы для анализа доменов (только из текста)
SUSPICIOUS_TLDS = {
    '.xin', '.win', '.help', '.bond', '.cfd', '.finance',
    '.top', '.xyz', '.icu', '.support', '.vip', '.pro', '.sbs',
    '.site', '.online', '.click', '.tk', '.ml', '.ga', '.cf',
    '.gq', '.club', '.work'
}
LONG_DOMAIN_THRESHOLD = 20


class FeatureExtractor:
    """
    Класс для извлечения синтетических признаков и векторизации текста
    Хранит обученный TfidfVectorizer для консистентной трансформации
    """
    
    def __init__(self, max_features: int = 3000):
        """
        Args:
            max_features: максимальное количество признаков TF-IDF
        """
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=max_features,
            ngram_range=(1, 2),
            min_df=3,
            max_df=0.3,
            lowercase=True,
            strip_accents='unicode',
            token_pattern=r'\b[a-z]{3,}\b',
            sublinear_tf=True,
            stop_words='english',  
            use_idf=True,
            smooth_idf=True,
            norm='l2'
        )

        self.synthetic_scaler = MinMaxScaler()
        self.is_fitted = False
        self.is_scaler_fitted = False
    
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
        
        # Заменяем nbsp как подстроку на пробел
        html_text = html_text.replace('nbsp', ' ')
        
        try:
            soup = BeautifulSoup(html_text, 'html.parser')
            # Удаляем script и style блоки
            for script in soup(["script", "style"]):
                script.decompose()
            # Извлекаем текст
            text = soup.get_text(separator=' ', strip=True)
            # Заменяем nbsp как подстроку на пробел
            text = text.replace('nbsp', ' ')
            # Убираем множественные пробелы
            text = re.sub(r'\s+', ' ', text)
            return text.strip()
        except Exception:
            # Fallback: простое удаление тегов regex
            text = re.sub(r'<[^>]+>', ' ', html_text)
            # Заменяем nbsp как подстроку на пробел
            text = text.replace('nbsp', ' ')
            text = re.sub(r'\s+', ' ', text)
            return text.strip()
    
    @staticmethod
    def prepare_text_from_parsed_email(parsed_email: dict) -> str:
        """
        Подготовка текста из распарсенного письма для векторизации
        
        Returns:
            str: объединенный очищенный текст (subject + body)
        """
        subject = parsed_email.get('subject', '') or ''
        body_plain = parsed_email.get('body_plain', '') or ''
        body_html = parsed_email.get('body_html', '') or ''
        
        # Приоритет: body_plain > body_html (избегаем дублирования)
        body = body_plain if body_plain else body_html
        
        # Очистка HTML тегов (если есть)
        if body:
            body_clean = FeatureExtractor.strip_html_tags(body)
        else:
            body_clean = ''
        
        # Объединяем subject и body
        combined_text = f"{subject} {body_clean}".strip()
        return combined_text
    
    @staticmethod
    def _extract_ips_from_urls(urls: List[str]) -> List[str]:
        """
        Извлечение IP-адресов только из URL (только из текста письма)
        
        Args:
            urls: список URL из тела письма
            
        Returns:
            List[str]: список уникальных IP-адресов
        """
        ips = []
        for url in urls:
            hostname, is_ip = extract_hostname_from_url(url)
            if is_ip and hostname:
                # Валидация IP-адреса
                parts = hostname.split('.')
                if len(parts) == 4:
                    try:
                        if all(0 <= int(part) <= 255 for part in parts):
                            ips.append(hostname)
                    except ValueError:
                        continue
        return list(set(ips))
    
    @staticmethod
    def _extract_domains_from_urls(urls: List[str]) -> List[str]:
        """
        Извлечение доменов только из URL (только из текста письма)
        
        Args:
            urls: список URL из тела письма
            
        Returns:
            List[str]: список уникальных доменов
        """
        domains = []
        for url in urls:
            hostname, is_ip = extract_hostname_from_url(url)
            if not is_ip and hostname:
                # Удаляем www. префикс
                domain = hostname[4:] if hostname.lower().startswith('www.') else hostname
                domain = domain.lower()
                # Проверяем, что это валидный домен
                if re.match(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$', domain):
                    domains.append(domain)
        return list(set(domains))
    
    @staticmethod
    def _is_long_domain(domain: str) -> bool:
        """Проверяет, превышает ли домен порог длины"""
        return len(domain) > LONG_DOMAIN_THRESHOLD
    
    @staticmethod
    def _is_suspicious_tld(domain: str) -> bool:
        """Проверяет TLD на вхождение в список подозрительных зон"""
        try:
            extracted = tldextract.extract(domain)
            tld = f".{extracted.suffix}" if extracted.suffix else ""
        except Exception:
            parts = domain.split('.')
            tld = f".{parts[-1]}" if len(parts) > 1 else ""
        return tld.lower() in SUSPICIOUS_TLDS
    
    def extract_quantitative_features(self, parsed_email: dict) -> np.ndarray:
        """
        Извлечение количественных метрик: counts URL/attachments/IPs
        
        Returns:
            np.ndarray: raw features (без нормализации)
        """
        urls = parsed_email.get('urls', []) or []
        url_count = len(urls)
        attachment_count = len(parsed_email.get('attachments', []))
        ips_from_urls = self._extract_ips_from_urls(urls)
        ip_count = len(ips_from_urls)
        
        return np.array([url_count, attachment_count, ip_count], dtype=np.float32)

    
    def extract_structural_features(self, parsed_email: dict) -> np.ndarray:
        """
        Извлечение структурных характеристик: length Subject/body
        
        Returns:
            np.ndarray: raw features (без нормализации)
        """
        subject = parsed_email.get('subject', '') or ''
        body_plain = parsed_email.get('body_plain', '') or ''
        body_html = parsed_email.get('body_html', '') or ''
        
        body_length = len(body_plain) if body_plain else len(body_html)
        subject_len = len(subject)
        
        return np.array([subject_len, body_length], dtype=np.float32)

    
    def extract_binary_indicators(self, url_analysis: dict, parsed_email: dict) -> np.ndarray:
        """
        Извлечение бинарных индикаторов из тела письма
        has_long_domain и has_suspicious_tld анализируются только из доменов URL в теле письма (только из текста)
        
        Args:
            url_analysis: результат url_domain_analyzer.analyze_urls_and_domains()
            parsed_email: результат email_parser.parse_email()
        
        Returns:
            np.ndarray: [has_url_shortener, has_long_domain, has_suspicious_tld, has_ip_in_url]
        """
        has_url_shortener = 1 if url_analysis.get('has_url_shortener', False) else 0
        has_ip_in_url = 1 if url_analysis.get('has_ip_in_url', False) else 0
        
        urls = parsed_email.get('urls', []) or []
        domains_from_urls = self._extract_domains_from_urls(urls)
        
        has_long_domain = 1 if any(self._is_long_domain(domain) for domain in domains_from_urls) else 0
        has_suspicious_tld = 1 if any(self._is_suspicious_tld(domain) for domain in domains_from_urls) else 0
        
        return np.array([
            has_url_shortener,
            has_long_domain,
            has_suspicious_tld,
            has_ip_in_url
        ], dtype=np.float32)
    
    def extract_linguistic_features(self, text: str) -> np.ndarray:
        """
        Извлечение лингвистических метрик: urgency keywords
        
        Returns:
            np.ndarray: raw features (без нормализации)
        """
        if not text:
            return np.array([0.0], dtype=np.float32)
        
        text_lower = text.lower()
        urgency_count = sum(
            len(re.findall(r'\b' + re.escape(keyword) + r'\b', text_lower, re.IGNORECASE))
            for keyword in URGENCY_KEYWORDS
        )
        return np.array([float(urgency_count)], dtype=np.float32)
        
    def preprocess_text(self, text: str) -> str:
        """
        Предобработка текста для векторизации:
        очистка HTML, удаление email/URL,
        токенизация, лемматизация, фильтрация стоп-слов и артефактов
        """
        if not text:
            return ""
        
        if '<' in text and '>' in text:
            text = FeatureExtractor.strip_html_tags(text)
        
        text = re.sub(
            r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
            ' ',
            text
        )
        
        text = re.sub(r'https?://\S+', ' ', text)
        text = re.sub(r'www\.\S+', ' ', text)
        text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ' ', text)
        text = re.sub(r'[^a-zA-Z\s]', ' ', text)
        text = text.replace('nbsp', ' ')
        text = re.sub(r'\s+', ' ', text).strip()
        
        try:
            tokens = word_tokenize(text.lower())
        except Exception:
            tokens = text.lower().split()
        
        processed_tokens = []
        for token in tokens:
            if not re.match(r'^[a-z]+$', token):
                continue
            
            lemmatized = lemmatizer.lemmatize(token)
            
            if (lemmatized not in ALL_STOP_WORDS and len(lemmatized) >= 3):
                processed_tokens.append(lemmatized)
        
        return ' '.join(processed_tokens)
    
    def fit_vectorizer(self, texts: list):
        """Обучение TF-IDF векторизатора"""
        if not texts:
            raise ValueError("Texts list cannot be empty")
        
        processed_texts = [self.preprocess_text(str(text)) for text in texts]
        self.tfidf_vectorizer.fit(processed_texts)
        self.is_fitted = True
    
    def fit_scaler(self, synthetic_features_list: list):
        """
        Args:
            synthetic_features_list: список массивов синтетических признаков
        """
        if not synthetic_features_list:
            raise ValueError("Synthetic features list cannot be empty")
        
        # Преобразуем в 2D массив (n_samples, n_features)
        features_matrix = np.array(synthetic_features_list, dtype=np.float32)
        self.synthetic_scaler.fit(features_matrix)
        self.is_scaler_fitted = True
    
    def vectorize_text(self, text: str) -> np.ndarray:
        """TF-IDF векторизация текста"""
        if not self.is_fitted:
            raise ValueError("Vectorizer must be fitted before vectorization")
        
        processed_text = self.preprocess_text(text or '')
        vector = self.tfidf_vectorizer.transform([processed_text])
        return vector.toarray()[0].astype(np.float32)
    
    def combine_features(self, tfidf_vector: np.ndarray, 
                        synthetic_features: np.ndarray) -> np.ndarray:
        """Объединение TF-IDF векторов и синтетических признаков"""
        return np.concatenate([tfidf_vector, synthetic_features]).astype(np.float32)
    
    def extract_all_features(
        self, 
        parsed_email: dict, 
        translated_text: str,
        url_analysis: dict
    ) -> Dict[str, Any]:
        """Главный метод для извлечения всех признаков из письма"""
        
        quantitative = self.extract_quantitative_features(parsed_email)
        structural = self.extract_structural_features(parsed_email)
        binary = self.extract_binary_indicators(url_analysis, parsed_email)
        linguistic = self.extract_linguistic_features(translated_text)
        
        # Объединение всех синтетических признаков (raw значения)
        synthetic_features_array = np.concatenate([
            quantitative, 
            structural, 
            binary, 
            linguistic
        ])
        
        # Применяем MinMaxScaler один раз на все синтетические признаки
        if self.is_scaler_fitted:
            synthetic_features_2d = synthetic_features_array.reshape(1, -1)
            synthetic_features_normalized = self.synthetic_scaler.transform(synthetic_features_2d)
            # Ограничиваем значения в диапазон [0, 1] на случай выхода за пределы обучающего диапазона
            synthetic_features_normalized = np.clip(synthetic_features_normalized, 0.0, 1.0)
            synthetic_features_array = synthetic_features_normalized.flatten()
        
        tfidf_vector = self.vectorize_text(translated_text)
        feature_vector = self.combine_features(tfidf_vector, synthetic_features_array)
        
        synthetic_features_dict = {
            'quantitative': {
                'url_count': int(quantitative[0]),
                'attachment_count': int(quantitative[1]),
                'ip_count': int(quantitative[2])
            },
            'structural': {
                'subject_length': int(structural[0]),
                'body_length': int(structural[1])
            },
            'binary': {
                'has_url_shortener': int(binary[0]),
                'has_long_domain': int(binary[1]),
                'has_suspicious_tld': int(binary[2]),
                'has_ip_in_url': int(binary[3])
            },
            'linguistic': {
                'urgency_markers_count': int(linguistic[0])
            }
        }
        
        return {
            'tfidf_vector': tfidf_vector,
            'synthetic_features': synthetic_features_dict,
            'feature_vector': feature_vector
        }
    
    def save_vectorizer(self, path: str):
        """Сохранение обученного TfidfVectorizer и MinMaxScaler"""
        if not self.is_fitted:
            raise ValueError("Cannot save unfitted vectorizer")
        
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump({
                'vectorizer': self.tfidf_vectorizer, 
                'is_fitted': self.is_fitted,
                'scaler': self.synthetic_scaler,
                'is_scaler_fitted': self.is_scaler_fitted
            }, f)
    
    def load_vectorizer(self, path: str):
        """Загрузка обученного TfidfVectorizer и MinMaxScaler"""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Vectorizer file not found: {path}")
        
        with open(path, 'rb') as f:
            data = pickle.load(f)
            self.tfidf_vectorizer = data['vectorizer']
            self.is_fitted = data.get('is_fitted', True)
            if 'scaler' in data:
                self.synthetic_scaler = data['scaler']
                self.is_scaler_fitted = data.get('is_scaler_fitted', False)
            else:
                self.synthetic_scaler = MinMaxScaler()
                self.is_scaler_fitted = False