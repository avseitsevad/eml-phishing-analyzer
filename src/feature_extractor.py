"""
Feature Extractor Module
Извлечение признаков и векторизация текста
"""

import re
import logging
import pickle
from pathlib import Path
from typing import Dict, Any, Tuple

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
import nltk
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer
from nltk.corpus import stopwords

logger = logging.getLogger(__name__)

# Инициализация NLTK компонентов
for resource in ['tokenizers/punkt', 'corpora/stopwords', 'corpora/wordnet']:
    try:
        nltk.data.find(resource)
    except LookupError:
        nltk.download(resource.split('/')[-1], quiet=True)

lemmatizer = WordNetLemmatizer()
STOP_WORDS = set(stopwords.words('english'))

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


class FeatureExtractor:
    """
    Класс для извлечения синтетических признаков и векторизации текста
    Хранит обученный TfidfVectorizer для консистентной трансформации
    """
    
    def __init__(self, max_features: int = 5000):
        """
        Инициализация экстрактора признаков
        
        Args:
            max_features: максимальное количество признаков TF-IDF
        """
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=max_features,
            ngram_range=(1, 2),  # Униграммы и биграммы
            min_df=2,  # Минимальная частота документа
            max_df=0.95,  # Максимальная частота документа
            lowercase=True,
            strip_accents='unicode'
        )
        self.is_fitted = False
    
    def extract_quantitative_features(self, parsed_email: dict) -> Tuple[np.ndarray, np.ndarray]:
        """
        Извлечение количественных метрик: counts URL/attachments/IPs
        Применяется логарифмическая нормализация (log1p) для совместимости с TF-IDF векторами
        
        Args:
            parsed_email: результат email_parser.parse_email()
        
        Returns:
            tuple: (normalized_features, raw_features)
        """
        url_count = len(parsed_email.get('urls', []))
        attachment_count = len(parsed_email.get('attachments', []))
        ip_count = len(parsed_email.get('ips', []))
        
        raw_features = np.array([url_count, attachment_count, ip_count], dtype=np.float32)
        # Логарифмическая нормализация: log(1 + x)
        normalized_features = np.log1p(raw_features)
        return normalized_features, raw_features
    
    def extract_structural_features(self, parsed_email: dict) -> Tuple[np.ndarray, np.ndarray]:
        """
        Извлечение структурных характеристик: length Subject/body
        Применяется логарифмическая нормализация (log1p)
        
        Args:
            parsed_email: результат email_parser.parse_email()
        
        Returns:
            tuple: (normalized_features, raw_features)
        """
        subject = parsed_email.get('subject', '') or ''
        body_plain = parsed_email.get('body_plain', '') or ''
        body_html = parsed_email.get('body_html', '') or ''
        
        # Используем длину body_plain или body_html (что доступно)
        body_length = len(body_plain) if body_plain else len(body_html)
        
        subject_len = len(subject)
        raw_features = np.array([subject_len, body_length], dtype=np.float32)
        normalized_features = np.log1p(raw_features)
        return normalized_features, raw_features
    
    def extract_binary_indicators(self, url_analysis: dict) -> np.ndarray:
        """
        Извлечение бинарных индикаторов с использованием результатов url_domain_analyzer
        
        Args:
            url_analysis: результат url_domain_analyzer.analyze_urls_and_domains()
        
        Returns:
            np.ndarray: [has_url_shortener, has_long_domain, has_suspicious_tld, has_ip_in_url]
        """
        has_url_shortener = 1 if url_analysis.get('has_url_shortener', False) else 0
        has_long_domain = 1 if url_analysis.get('has_long_domain', False) else 0
        has_suspicious_tld = 1 if url_analysis.get('has_suspicious_tld', False) else 0
        has_ip_in_url = 1 if url_analysis.get('has_ip_in_url', False) else 0
        
        return np.array([
            has_url_shortener,
            has_long_domain,
            has_suspicious_tld,
            has_ip_in_url
        ], dtype=np.float32)
    
    def extract_linguistic_features(self, text: str) -> Tuple[np.ndarray, np.ndarray]:
        """
        Извлечение лингвистических метрик: urgency keywords
        Применяется логарифмическая нормализация (log1p)
        
        Args:
            text: переведенный текст письма (на английском)
        
        Returns:
            tuple: (normalized_features, raw_features)
        """
        if not text:
            raw_features = np.array([0.0], dtype=np.float32)
            return np.log1p(raw_features), raw_features
        
        text_lower = text.lower()
        urgency_count = sum(
            len(re.findall(r'\b' + re.escape(keyword) + r'\b', text_lower, re.IGNORECASE))
            for keyword in URGENCY_KEYWORDS
        )
        raw_features = np.array([float(urgency_count)], dtype=np.float32)
        normalized_features = np.log1p(raw_features)
        return normalized_features, raw_features
    
    def preprocess_text(self, text: str) -> str:
        """Предобработка текста: токенизация, лемматизация, удаление стоп-слов"""
        if not text:
            return ""
        
        try:
            tokens = word_tokenize(text.lower())
        except Exception as e:
            logger.error(f"Tokenization failed: {e}")
            tokens = text.lower().split()
        
        processed_tokens = []
        for token in tokens:
            if not re.match(r'^[a-zA-Z]+$', token):
                continue
            lemmatized = lemmatizer.lemmatize(token)
            if lemmatized not in STOP_WORDS and len(lemmatized) > 2:
                processed_tokens.append(lemmatized)
        
        return ' '.join(processed_tokens)
    
    def fit_vectorizer(self, texts: list):
        """Обучение TF-IDF векторизатора на обучающей выборке"""
        if not texts:
            raise ValueError("Texts list cannot be empty")
        
        processed_texts = [self.preprocess_text(str(text)) for text in texts]
        self.tfidf_vectorizer.fit(processed_texts)
        self.is_fitted = True
        logger.info(f"TF-IDF vectorizer fitted on {len(texts)} texts, "
                   f"vocabulary size: {len(self.tfidf_vectorizer.vocabulary_)}")
    
    def vectorize_text(self, text: str) -> np.ndarray:
        """TF-IDF векторизация текста"""
        if not self.is_fitted:
            raise ValueError("Vectorizer must be fitted before vectorization. Call fit_vectorizer() first.")
        
        if not hasattr(self.tfidf_vectorizer, 'vocabulary_') or not self.tfidf_vectorizer.vocabulary_:
            raise ValueError("Vectorizer vocabulary is empty. Call fit_vectorizer() first.")
        
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
        """
        Главный метод для извлечения всех признаков из письма
        
        Args:
            parsed_email: результат email_parser.parse_email() (плоская структура)
            translated_text: ПЕРЕВЕДЕННЫЙ текст из translation.translate_parsed_email()
            url_analysis: результат url_domain_analyzer.analyze_urls_and_domains()
        
        Returns:
            dict: {
                'tfidf_vector': np.ndarray,
                'synthetic_features': dict,
                'feature_vector': np.ndarray
            }
        """
        # Извлечение синтетических признаков
        quantitative_norm, quantitative_raw = self.extract_quantitative_features(parsed_email)
        structural_norm, structural_raw = self.extract_structural_features(parsed_email)
        binary = self.extract_binary_indicators(url_analysis)
        linguistic_norm, linguistic_raw = self.extract_linguistic_features(translated_text)
        
        # Объединение всех синтетических признаков (нормализованные значения)
        synthetic_features_array = np.concatenate([
            quantitative_norm, 
            structural_norm, 
            binary, 
            linguistic_norm
        ])
        
        # TF-IDF векторизация ПЕРЕВЕДЕННОГО текста
        tfidf_vector = self.vectorize_text(translated_text)
        
        # Объединение TF-IDF и синтетических признаков
        feature_vector = self.combine_features(tfidf_vector, synthetic_features_array)
        
        # Формирование словаря для детализации (исходные значения)
        synthetic_features_dict = {
            'quantitative': {
                'url_count': int(quantitative_raw[0]),
                'attachment_count': int(quantitative_raw[1]),
                'ip_count': int(quantitative_raw[2])
            },
            'structural': {
                'subject_length': int(structural_raw[0]),
                'body_length': int(structural_raw[1])
            },
            'binary': {
                'has_url_shortener': int(binary[0]),
                'has_long_domain': int(binary[1]),
                'has_suspicious_tld': int(binary[2]),
                'has_ip_in_url': int(binary[3])
            },
            'linguistic': {
                'urgency_markers_count': int(linguistic_raw[0])
            }
        }
        
        return {
            'tfidf_vector': tfidf_vector,
            'synthetic_features': synthetic_features_dict,
            'feature_vector': feature_vector
        }
    
    def save_vectorizer(self, path: str):
        """Сохранение обученного TfidfVectorizer"""
        if not self.is_fitted:
            raise ValueError("Cannot save unfitted vectorizer")
        
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump({
                'vectorizer': self.tfidf_vectorizer, 
                'is_fitted': self.is_fitted
            }, f)
        logger.info(f"Vectorizer saved to {path}")
    
    def load_vectorizer(self, path: str):
        """Загрузка обученного TfidfVectorizer"""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Vectorizer file not found: {path}")
        
        with open(path, 'rb') as f:
            data = pickle.load(f)
            self.tfidf_vectorizer = data['vectorizer']
            self.is_fitted = data.get('is_fitted', True)
        
        vocab_size = len(self.tfidf_vectorizer.vocabulary_) if hasattr(self.tfidf_vectorizer, 'vocabulary_') else 0
        logger.info(f"Vectorizer loaded from {path}, vocabulary size: {vocab_size}")