"""
ML Classifier Module
Классификация на основе машинного обучения
"""

import numpy as np


class MLClassifier:
    """
    Класс для загрузки и использования обученной ML-модели
    Хранит загруженную модель для многократного inference
    """
    
    def __init__(self):
        """Инициализация классификатора"""
        self.model = None
        self.model_name = None
        pass
    
    def load_model(self, model_path: str):
        """
        Загрузка предобученной модели (pickle/joblib)
        
        Args:
            model_path: путь к файлу модели
        """
        pass
    
    def predict(self, feature_vector: np.ndarray) -> int:
        """
        Inference: вектор признаков → предсказание
        
        Args:
            feature_vector: вектор признаков
            
        Returns:
            int: предсказание (0=legitimate, 1=phishing)
        """
        pass
    
    def predict_proba(self, feature_vector: np.ndarray) -> float:
        """
        Вычисление вероятности класса (confidence score 0-1)
        
        Args:
            feature_vector: вектор признаков
            
        Returns:
            float: вероятность класса phishing (0-1)
        """
        pass
    
    def get_prediction_with_confidence(self, feature_vector: np.ndarray) -> dict:
        """
        Получение предсказания и confidence score
        
        Args:
            feature_vector: вектор признаков
            
        Returns:
            dict: {
                'prediction': int (0/1),
                'confidence': float (0-1),
                'class_label': str ('legitimate'/'phishing')
            }
        """
        pass