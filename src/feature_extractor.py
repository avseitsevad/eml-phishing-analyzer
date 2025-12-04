"""
Feature Extractor Module
Извлечение признаков и векторизация текста
"""

import re
import logging
import pickle
from pathlib import Path

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

from .utils import URL_SHORTENERS

# Опасные расширения файлов
DANGEROUS_EXTENSIONS = {
    '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js',
    '.jar', '.app', '.deb', '.pkg', '.dmg', '.msi', '.dll', '.lnk',
    '.hta', '.wsf', '.ps1', '.sh', '.run', '.bin'
}

# Ключевые слова срочности
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
    
    def extract_quantitative_features(self, parsed_email: dict, urls: list, 
                                     attachments: list) -> np.ndarray:
        """Извлечение количественных метрик: counts URL/attachments/IPs"""
        url_count = len(urls) if urls else 0
        attachment_count = len(attachments) if attachments else 0
        ip_count = len(parsed_email.get('ips', []))
        return np.array([url_count, attachment_count, ip_count], dtype=np.float32)
    
    def extract_structural_features(self, subject: str, body: str) -> np.ndarray:
        """Извлечение структурных характеристик: length Subject/body"""
        return np.array([len(subject or ''), len(body or '')], dtype=np.float32)
    
    def extract_binary_indicators(self, attachments: list, urls: list) -> np.ndarray:
        """Извлечение бинарных индикаторов: dangerous extensions, shorteners"""
        has_dangerous_extensions = 0
        if attachments:
            for attachment in attachments:
                filename = attachment.get('filename', '') if isinstance(attachment, dict) else str(attachment)
                if any(filename.lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS):
                    has_dangerous_extensions = 1
                    break
        
        has_url_shorteners = 0
        if urls:
            url_text = ' '.join(str(url).lower() for url in urls)
            if any(shortener in url_text for shortener in URL_SHORTENERS):
                has_url_shorteners = 1
        
        return np.array([has_dangerous_extensions, has_url_shorteners], dtype=np.float32)
    
    def extract_linguistic_features(self, text: str) -> np.ndarray:
        """Извлечение лингвистических метрик: urgency keywords"""
        if not text:
            return np.array([0.0], dtype=np.float32)
        
        text_lower = text.lower()
        urgency_count = sum(
            len(re.findall(r'\b' + re.escape(keyword) + r'\b', text_lower, re.IGNORECASE))
            for keyword in URGENCY_KEYWORDS
        )
        return np.array([float(urgency_count)], dtype=np.float32)
    
    def preprocess_text(self, text: str) -> str:
        """Предобработка текста: токенизация, лемматизация, удаление стоп-слов"""
        if not text:
            return ""
        
        tokens = word_tokenize(text.lower())
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
        logger.info(f"TF-IDF vectorizer fitted on {len(texts)} texts")
    
    def vectorize_text(self, text: str) -> np.ndarray:
        """TF-IDF векторизация текста (требует предварительного fit)"""
        if not self.is_fitted:
            raise ValueError("Vectorizer must be fitted before vectorization. Call fit_vectorizer() first.")
        
        processed_text = self.preprocess_text(text or '')
        vector = self.tfidf_vectorizer.transform([processed_text])
        return vector.toarray()[0].astype(np.float32)
    
    def combine_features(self, tfidf_vector: np.ndarray, 
                        synthetic_features: np.ndarray) -> np.ndarray:
        """Объединение TF-IDF векторов и синтетических признаков"""
        return np.concatenate([tfidf_vector, synthetic_features]).astype(np.float32)
    
    def extract_all_features(self, parsed_email: dict, translated_text: str) -> np.ndarray:
        """Главный метод для извлечения всех признаков из письма"""
        urls = parsed_email.get('urls', [])
        attachments = parsed_email.get('attachments_metadata', [])
        headers = parsed_email.get('headers', {})
        body_data = parsed_email.get('body', {})
        
        subject = headers.get('subject', '') or ''
        body_text = body_data.get('text', '') or body_data.get('html', '') or ''
        
        quantitative = self.extract_quantitative_features(parsed_email, urls, attachments)
        structural = self.extract_structural_features(subject, body_text)
        binary = self.extract_binary_indicators(attachments, urls)
        linguistic = self.extract_linguistic_features(translated_text)
        
        synthetic_features = np.concatenate([quantitative, structural, binary, linguistic])
        tfidf_vector = self.vectorize_text(translated_text)
        
        return self.combine_features(tfidf_vector, synthetic_features)
    
    def save_vectorizer(self, path: str):
        """Сохранение обученного TfidfVectorizer"""
        if not self.is_fitted:
            raise ValueError("Cannot save unfitted vectorizer")
        
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump({'vectorizer': self.tfidf_vectorizer, 'is_fitted': self.is_fitted}, f)
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
        logger.info(f"Vectorizer loaded from {path}")