"""
ML Classifier Module
Загрузка обученной модели и выполнение инференса по feature vector
"""

import pickle
import math
from pathlib import Path
from typing import Dict, Any, Optional, Union

import numpy as np


class MLClassifier:
    """
    ML-классификатор для инференса по feature vector.

    Основной интерфейс:
      - load_model(model_path)
      - classify_feature_vector(feature_vector) -> {prediction, confidence, phishing_probability, class_label}
    """

    def __init__(self):
        self.model = None
        self.classes_ = None

    def load_model(self, model_path: Union[str, Path]) -> None:
        """Загрузка обученной модели из .pkl"""
        model_path = Path(model_path)
        with open(model_path, "rb") as f:
            self.model = pickle.load(f)

        self.classes_ = getattr(self.model, "classes_", None)

    def _get_class_indices(self):
        """
        Возвращает индексы (legit_idx, phishing_idx) в массивах вероятностей/скорингов.
        Классический порядок: phishing=1, legit=0. Если классы отличаются, используется порядок classes_.
        """
        if self.classes_ is None:
            return 0, 1

        classes = list(self.classes_)

        if 0 in classes and 1 in classes:
            legit_idx = classes.index(0)
            phishing_idx = classes.index(1)
            return legit_idx, phishing_idx

        if len(classes) >= 2:
            return 0, 1

        return 0, 0

    def _sigmoid(self, x: float) -> float:
        """Численно устойчивый sigmoid"""
        if x >= 0:
            z = math.exp(-x)
            return 1.0 / (1.0 + z)
        else:
            z = math.exp(x)
            return z / (1.0 + z)

    def _predict_phishing_probability(self, X: np.ndarray) -> np.ndarray:
        """
        Возвращает P(phishing) для входных данных X (shape: (n, d)).
        Поддерживает:
          - predict_proba
          - decision_function (через sigmoid)
        """
        if self.model is None:
            raise ValueError("Model not loaded. Call load_model() first.")

        # predict_proba
        if hasattr(self.model, "predict_proba"):
            probas = self.model.predict_proba(X)
            probas = np.asarray(probas)
            _, phishing_idx = self._get_class_indices()
            return probas[:, phishing_idx].astype(np.float32)

        # decision_function
        if hasattr(self.model, "decision_function"):
            scores = self.model.decision_function(X)
            scores = np.asarray(scores)

            # Вариант (n, 2)
            if scores.ndim == 2 and scores.shape[1] >= 2:
                _, phishing_idx = self._get_class_indices()
                scores = scores[:, phishing_idx]
            else:
                scores = scores.reshape(-1)

            return np.array([self._sigmoid(float(s)) for s in scores], dtype=np.float32)

        # fallback
        return np.zeros(X.shape[0], dtype=np.float32)

    def classify_feature_vector(self, feature_vector: np.ndarray) -> Dict[str, Any]:
        """
        Инференс по одному feature vector или матрице feature vectors.

        Вход:
          - feature_vector: shape (d,) или (1, d) или (n, d)

        Выход (для одного объекта):
          - prediction: 0/1
          - confidence: 0..1
          - phishing_probability: 0..1
          - class_label: 'phishing'/'legitimate'
        """
        if self.model is None:
            raise ValueError("Model not loaded. Call load_model() first.")

        fv = np.asarray(feature_vector)

        if fv.ndim == 1:
            X = fv.reshape(1, -1)
        else:
            X = fv

        pred = int(self.model.predict(X)[0])

        prob_phishing = float(self._predict_phishing_probability(X)[0])
        prob_legit = 1.0 - prob_phishing
        confidence = prob_phishing if pred == 1 else prob_legit

        return {
            "prediction": pred,
            "confidence": confidence,
            "phishing_probability": prob_phishing,
            "class_label": "phishing" if pred == 1 else "legitimate",
            "model_type": type(self.model).__name__
        }

    def classify_feature_matrix(self, X: np.ndarray) -> Dict[str, Any]:
        """
        Инференс по матрице признаков.

        Возвращает:
          - predictions: np.ndarray shape (n,)
          - phishing_probabilities: np.ndarray shape (n,)
          - confidences: np.ndarray shape (n,)
        """
        if self.model is None:
            raise ValueError("Model not loaded. Call load_model() first.")

        X = np.asarray(X)
        preds = self.model.predict(X).astype(int)
        probs = self._predict_phishing_probability(X).astype(np.float32)
        confs = np.where(preds == 1, probs, 1.0 - probs).astype(np.float32)

        return {
            "predictions": preds,
            "phishing_probabilities": probs,
            "confidences": confs,
            "model_type": type(self.model).__name__
        }
