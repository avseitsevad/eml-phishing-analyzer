"""
Email Analysis Pipeline Module
Класс для интеграции всех модулей и выполнения полного анализа письма
"""

import time
from pathlib import Path
from typing import Dict, Any, Optional, Union
from concurrent.futures import ThreadPoolExecutor, as_completed

from .email_parser import parse_email
from .translation import Translator
from .feature_extractor import FeatureExtractor
from .header_analyzer import analyze_headers
from .url_domain_analyzer import analyze_urls_and_domains
from .threat_intelligence import ThreatIntelligence
from .rules_engine import evaluate_all_rules
from .ml_classifier import MLClassifier
from .aggregator import aggregate_and_decide


class EmailAnalysisPipeline:
    """
    Класс для интеграции всех модулей и выполнения полного анализа письма
    Инициализирует все компоненты со состоянием и вызывает функции анализа
    """
    
    def __init__(self, base_dir: Optional[Path] = None):
        """
        Инициализация всех модулей:
        - ThreatIntelligence (с подключением к БД)
        - Translator (с загрузкой моделей)
        - FeatureExtractor (с загрузкой TfidfVectorizer)
        - MLClassifier (с загрузкой обученной модели)
        
        Args:
            base_dir: базовая директория проекта. Если не указана, определяется автоматически
        """
        if base_dir is None:
            # Определяем базовую директорию относительно этого файла
            base_dir = Path(__file__).parent.parent.resolve()
        
        self.base_dir = base_dir
        self.models_dir = base_dir / 'data' / 'models'
        self.ti_db_path = base_dir / 'data' / 'threat_intelligence' / 'ti_database.db'
        self.weights_path = self.models_dir / 'optimal_weights.json'
        
        # Инициализация компонентов
        self.translator = Translator()
        self.feature_extractor = FeatureExtractor()
        self.ml_classifier = MLClassifier()
        self.threat_intelligence = ThreatIntelligence(str(self.ti_db_path))
        
        # Загрузка обученных моделей
        self._load_models()
    
    def _load_models(self):
        """Загрузка обученных моделей и векторизатора"""
        vectorizer_path = self.models_dir / 'tfidf_vectorizer.pkl'
        self.feature_extractor.load_vectorizer(str(vectorizer_path))
        
        model_path = self.models_dir / 'logreg.pkl'
        self.ml_classifier.load_model(model_path)
    
    def analyze_email(self, eml_file_content: Union[str, bytes], progress_callback=None, use_parallel: bool = True) -> Dict[str, Any]:
        """
        Полный pipeline анализа письма с поддержкой параллельного выполнения независимых модулей
        
        Args:
            eml_file_content: содержимое .eml файла (str или bytes)
            progress_callback: функция для обновления прогресса (опционально)
                Должна принимать (message: str, percent: int)
            use_parallel: использовать параллельное выполнение независимых модулей (по умолчанию True)
            
        Returns:
            dict: детальный отчет с вердиктом и всеми результатами анализа
        """
        start_time = time.time()
        results = {
            'parsed_email': None,
            'translated_text': None,
            'header_analysis': None,
            'url_analysis': None,
            'ti_results': None,
            'features': None,
            'ml_result': None,
            'rules_result': None,
            'aggregation_result': None,
            'analysis_time': 0
        }
        
        try:
            # Шаг 1: Парсинг письма (базовый шаг, от него зависят все остальные)
            if progress_callback:
                progress_callback("Выполняется парсинг письма...", 10)
            
            parsed = parse_email(eml_file_content)
            results['parsed_email'] = parsed
            
            # Параллельное выполнение независимых модулей (шаги 2-5)
            if use_parallel:
                if progress_callback:
                    progress_callback("Выполняется параллельный анализ...", 20)
                
                # Подготовка данных для параллельного выполнения
                prepared_text = FeatureExtractor.prepare_text_from_parsed_email(parsed)
                headers_dict = {
                    'from': parsed.get('from', ''),
                    'to': parsed.get('to', ''),
                    'subject': parsed.get('subject', ''),
                    'auth_results': parsed.get('auth_results', ''),
                    'reply_to': parsed.get('reply_to', ''),
                    'return_path': parsed.get('return_path', ''),
                    'received_headers': parsed.get('received_headers', []),
                    'references': parsed.get('references', '')
                }
                
                # Функции для параллельного выполнения
                def translate_task():
                    """Задача перевода текста"""
                    detected_language = self.translator.detect_language(prepared_text) if prepared_text else 'en'
                    translated_text = self.translator.translate_text(prepared_text) if detected_language == 'ru' else prepared_text
                    return ('translation', {
                        'translated_text': translated_text,
                        'detected_language': detected_language
                    })
                
                def url_analysis_task():
                    """Задача анализа URL"""
                    return ('url_analysis', analyze_urls_and_domains(parsed))
                
                def header_analysis_task():
                    """Задача анализа заголовков"""
                    return ('header_analysis', analyze_headers(headers_dict))
                
                def ti_check_task():
                    """Задача проверки Threat Intelligence"""
                    return ('ti_results', self.threat_intelligence.check_reputation(
                        parsed.get('domains', []),
                        parsed.get('ips', [])
                    ))
                
                # Параллельное выполнение всех независимых задач
                with ThreadPoolExecutor(max_workers=4) as executor:
                    futures = {
                        executor.submit(translate_task): 'translation',
                        executor.submit(url_analysis_task): 'url_analysis',
                        executor.submit(header_analysis_task): 'header_analysis',
                        executor.submit(ti_check_task): 'ti_results'
                    }
                    
                    # Сбор результатов по мере их готовности
                    completed = 0
                    total = len(futures)
                    for future in as_completed(futures):
                        try:
                            task_name, result = future.result()
                            if task_name == 'translation':
                                results['translated_text'] = result['translated_text']
                                results['detected_language'] = result['detected_language']
                            else:
                                results[task_name] = result
                            
                            completed += 1
                            if progress_callback:
                                # Прогресс от 20% до 50% для параллельных задач
                                progress = 20 + int(30 * completed / total)
                                progress_callback(f"Выполняется параллельный анализ... ({completed}/{total})", progress)
                        except Exception as e:
                            # Если одна из задач упала, логируем и продолжаем
                            print(f"Ошибка в задаче {futures[future]}: {e}")
                            raise
            else:
                # Последовательное выполнение (старый способ)
                # Шаг 2: Подготовка и перевод текста
                if progress_callback:
                    progress_callback("Выполняется перевод и анализ текста...", 20)
                
                prepared_text = FeatureExtractor.prepare_text_from_parsed_email(parsed)
                detected_language = self.translator.detect_language(prepared_text) if prepared_text else 'en'
                translated_text = self.translator.translate_text(prepared_text) if detected_language == 'ru' else prepared_text
                results['translated_text'] = translated_text
                results['detected_language'] = detected_language
                
                # Шаг 3: Анализ URL и доменов
                if progress_callback:
                    progress_callback("Выполняется анализ URL...", 30)
                
                url_analysis = analyze_urls_and_domains(parsed)
                results['url_analysis'] = url_analysis
                
                # Шаг 4: Анализ заголовков
                if progress_callback:
                    progress_callback("Выполняется анализ заголовков...", 40)
                
                headers_dict = {
                    'from': parsed.get('from', ''),
                    'to': parsed.get('to', ''),
                    'subject': parsed.get('subject', ''),
                    'auth_results': parsed.get('auth_results', ''),
                    'reply_to': parsed.get('reply_to', ''),
                    'return_path': parsed.get('return_path', ''),
                    'received_headers': parsed.get('received_headers', []),
                    'references': parsed.get('references', '')
                }
                header_analysis = analyze_headers(headers_dict)
                results['header_analysis'] = header_analysis
                
                # Шаг 5: Проверка репутации (Threat Intelligence)
                if progress_callback:
                    progress_callback("Выполняется проверка индикаторов в TI-базе...", 50)
                
                ti_results = self.threat_intelligence.check_reputation(
                    parsed.get('domains', []),
                    parsed.get('ips', [])
                )
                results['ti_results'] = ti_results
            
            # Получаем результаты для дальнейшего использования
            translated_text = results['translated_text']
            url_analysis = results['url_analysis']
            header_analysis = results['header_analysis']
            ti_results = results['ti_results']
            
            # Шаг 6: Извлечение признаков (зависит от translated_text и url_analysis)
            if progress_callback:
                progress_callback("Выполняется извлечение признаков...", 60)
            
            features = self.feature_extractor.extract_all_features(
                parsed, translated_text, url_analysis
            )
            results['features'] = features
            
            # Параллельное выполнение ML классификации и оценки правил (шаги 7-8)
            if use_parallel:
                if progress_callback:
                    progress_callback("Выполняется ML классификация и эвристический анализ...", 70)
                
                # Функции для параллельного выполнения
                def ml_classification_task():
                    """Задача ML классификации"""
                    return ('ml_result', self.ml_classifier.classify_feature_vector(features['feature_vector']))
                
                def rules_evaluation_task():
                    """Задача оценки правил"""
                    return ('rules_result', evaluate_all_rules(header_analysis, parsed, ti_results))
                
                # Параллельное выполнение ML классификации и оценки правил
                with ThreadPoolExecutor(max_workers=2) as executor:
                    futures = {
                        executor.submit(ml_classification_task): 'ml_result',
                        executor.submit(rules_evaluation_task): 'rules_result'
                    }
                    
                    # Сбор результатов по мере их готовности
                    completed = 0
                    total = len(futures)
                    for future in as_completed(futures):
                        try:
                            task_name, result = future.result()
                            results[task_name] = result
                            
                            completed += 1
                            if progress_callback:
                                # Прогресс от 70% до 80% для параллельных задач
                                progress = 70 + int(10 * completed / total)
                                progress_callback(f"Выполняется ML классификация и эвристический анализ... ({completed}/{total})", progress)
                        except Exception as e:
                            # Если одна из задач упала, логируем и продолжаем
                            print(f"Ошибка в задаче {futures[future]}: {e}")
                            raise
            else:
                # Последовательное выполнение (старый способ)
                # Шаг 7: ML классификация (зависит от features)
                if progress_callback:
                    progress_callback("Выполняется ML классификация...", 70)
                
                ml_result = self.ml_classifier.classify_feature_vector(features['feature_vector'])
                results['ml_result'] = ml_result
                
                # Шаг 8: Оценка правил (зависит от header_analysis и ti_results)
                if progress_callback:
                    progress_callback("Выполняется эвристический анализ...", 80)
                
                rules_result = evaluate_all_rules(header_analysis, parsed, ti_results)
                results['rules_result'] = rules_result
            
            # Получаем результаты для агрегации
            ml_result = results['ml_result']
            rules_result = results['rules_result']
            
            # Шаг 9: Агрегация результатов (зависит от ml_result и rules_result)
            if progress_callback:
                progress_callback("Выполняется агрегация результатов...", 90)
            
            aggregation_result = aggregate_and_decide(
                ml_result=ml_result,
                rules_result=rules_result,
                weights_path=str(self.weights_path) if self.weights_path.exists() else None
            )
            results['aggregation_result'] = aggregation_result
            
            if progress_callback:
                progress_callback("Анализ завершен", 100)
            
            results['analysis_time'] = time.time() - start_time
            
            return results
            
        except Exception as e:
            results['error'] = str(e)
            results['analysis_time'] = time.time() - start_time
            raise

