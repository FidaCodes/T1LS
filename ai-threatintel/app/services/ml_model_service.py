"""
ML Model Integration Service

This service handles querying customer-specific ML models for threat predictions.
It provides a unified interface to query trained models and format their predictions
into SourceVerdict format for the aggregation service.
"""

import os
import pickle
import joblib
import numpy as np
from typing import Dict, Optional, Any, List
from datetime import datetime
from pathlib import Path

from app.services.verdict_aggregation import (
    SourceVerdict, 
    ThreatLevel, 
    SourceType
)


class MLModelService:
    """
    Service for querying customer-specific ML models
    
    Handles:
    - Loading customer-specific trained models
    - Feature extraction from IOCs
    - Prediction with confidence scores
    - Translation to SourceVerdict format
    """
    
    def __init__(self, models_base_path: str = None):
        """
        Initialize ML model service
        
        Args:
            models_base_path: Base directory where customer models are stored
        """
        if models_base_path is None:
            # Default to ml/models directory
            project_root = Path(__file__).parent.parent.parent.parent
            models_base_path = project_root / "ml" / "models"
        
        self.models_base_path = Path(models_base_path)
        self.model_cache = {}  # Cache loaded models
    
    def _get_customer_model_path(self, customer_id: str, model_type: str = "random_forest") -> Path:
        """
        Get the path to a customer's trained model
        
        Args:
            customer_id: Unique identifier for the customer
            model_type: Type of model (random_forest, gradient_boosting, neural_network)
            
        Returns:
            Path to the model file
        """
        return self.models_base_path / f"customer_{customer_id}" / model_type / "model.pkl"
    
    def _load_model(self, customer_id: str, model_type: str = "random_forest") -> Optional[Any]:
        """
        Load a customer's ML model from disk
        
        Args:
            customer_id: Customer identifier
            model_type: Type of model to load
            
        Returns:
            Loaded model or None if not found
        """
        cache_key = f"{customer_id}_{model_type}"
        
        # Check cache first
        if cache_key in self.model_cache:
            return self.model_cache[cache_key]
        
        model_path = self._get_customer_model_path(customer_id, model_type)
        
        if not model_path.exists():
            return None
        
        try:
            # Try loading with joblib first (sklearn models)
            model = joblib.load(model_path)
            self.model_cache[cache_key] = model
            return model
        except Exception as e:
            try:
                # Fallback to pickle
                with open(model_path, 'rb') as f:
                    model = pickle.load(f)
                    self.model_cache[cache_key] = model
                    return model
            except Exception as e2:
                print(f"Error loading model for customer {customer_id}: {e}, {e2}")
                return None
    
    def _load_preprocessor(self, customer_id: str) -> Optional[Any]:
        """
        Load the feature preprocessor for a customer's model
        
        Args:
            customer_id: Customer identifier
            
        Returns:
            Loaded preprocessor or None if not found
        """
        preprocessor_path = self.models_base_path / f"customer_{customer_id}" / "preprocessor" / "preprocessor.pkl"
        
        if not preprocessor_path.exists():
            return None
        
        try:
            return joblib.load(preprocessor_path)
        except Exception as e:
            print(f"Error loading preprocessor for customer {customer_id}: {e}")
            return None
    
    def _extract_features(self, ioc: str, ioc_type: str, context_data: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Extract features from an IOC for ML prediction
        
        Args:
            ioc: The indicator (IP, domain, URL, hash)
            ioc_type: Type of IOC
            context_data: Additional context from threat intel sources
            
        Returns:
            Dictionary of features
        """
        features = {
            'ioc': ioc,
            'ioc_type': ioc_type,
            'length': len(ioc)
        }
        
        # IOC-type specific features
        if ioc_type == 'ip':
            features.update(self._extract_ip_features(ioc))
        elif ioc_type == 'domain':
            features.update(self._extract_domain_features(ioc))
        elif ioc_type == 'url':
            features.update(self._extract_url_features(ioc))
        elif ioc_type == 'hash':
            features.update(self._extract_hash_features(ioc))
        
        # Add context data if available
        if context_data:
            # Extract relevant metrics from threat intel sources
            if 'virustotal' in context_data:
                vt_data = context_data['virustotal']
                features['vt_malicious_count'] = vt_data.get('malicious_count', 0)
                features['vt_suspicious_count'] = vt_data.get('suspicious_count', 0)
                features['vt_total_engines'] = vt_data.get('total_engines', 0)
                features['vt_reputation'] = vt_data.get('reputation', 0)
            
            if 'abuseipdb' in context_data:
                abuse_data = context_data['abuseipdb']
                features['abuse_confidence'] = abuse_data.get('abuse_confidence', 0)
                features['abuse_report_count'] = abuse_data.get('total_reports', 0)
        
        return features
    
    def _extract_ip_features(self, ip: str) -> Dict[str, Any]:
        """Extract features specific to IP addresses"""
        features = {}
        
        try:
            octets = ip.split('.')
            if len(octets) == 4:
                features['ip_first_octet'] = int(octets[0])
                features['ip_second_octet'] = int(octets[1])
                features['ip_third_octet'] = int(octets[2])
                features['ip_fourth_octet'] = int(octets[3])
                
                # Check for private IP ranges
                first = int(octets[0])
                features['is_private'] = (
                    first == 10 or
                    (first == 172 and 16 <= int(octets[1]) <= 31) or
                    (first == 192 and int(octets[1]) == 168)
                )
        except:
            pass
        
        return features
    
    def _extract_domain_features(self, domain: str) -> Dict[str, Any]:
        """Extract features specific to domains"""
        features = {}
        
        features['domain_length'] = len(domain)
        features['subdomain_count'] = domain.count('.')
        features['has_hyphen'] = '-' in domain
        features['digit_count'] = sum(c.isdigit() for c in domain)
        features['vowel_count'] = sum(c.lower() in 'aeiou' for c in domain)
        features['consonant_count'] = sum(c.isalpha() and c.lower() not in 'aeiou' for c in domain)
        
        # TLD extraction
        parts = domain.split('.')
        if len(parts) > 1:
            features['tld'] = parts[-1]
            features['tld_length'] = len(parts[-1])
        
        # Entropy (randomness measure)
        try:
            from collections import Counter
            import math
            counts = Counter(domain)
            entropy = -sum((count/len(domain)) * math.log2(count/len(domain)) for count in counts.values())
            features['entropy'] = entropy
        except:
            features['entropy'] = 0
        
        return features
    
    def _extract_url_features(self, url: str) -> Dict[str, Any]:
        """Extract features specific to URLs"""
        features = {}
        
        features['url_length'] = len(url)
        features['has_ip'] = any(c.isdigit() for c in url.split('/')[2] if '/' in url)
        features['slash_count'] = url.count('/')
        features['question_mark_count'] = url.count('?')
        features['ampersand_count'] = url.count('&')
        features['equal_count'] = url.count('=')
        features['at_symbol'] = '@' in url
        features['double_slash_count'] = url.count('//')
        
        # Protocol
        features['is_https'] = url.startswith('https://')
        features['is_http'] = url.startswith('http://')
        
        # Suspicious patterns
        features['has_suspicious_words'] = any(
            word in url.lower() 
            for word in ['admin', 'login', 'bank', 'secure', 'account', 'update', 'verify']
        )
        
        return features
    
    def _extract_hash_features(self, hash_str: str) -> Dict[str, Any]:
        """Extract features specific to file hashes"""
        features = {}
        
        features['hash_length'] = len(hash_str)
        features['is_md5'] = len(hash_str) == 32
        features['is_sha1'] = len(hash_str) == 40
        features['is_sha256'] = len(hash_str) == 64
        features['hex_valid'] = all(c in '0123456789abcdefABCDEF' for c in hash_str)
        
        return features
    
    def _convert_prediction_to_threat_level(self, prediction: float, prediction_proba: Optional[float] = None) -> ThreatLevel:
        """
        Convert model prediction to ThreatLevel enum
        
        Args:
            prediction: Model prediction (0 = benign, 1 = malicious for binary classification)
            prediction_proba: Probability/confidence of prediction
            
        Returns:
            ThreatLevel enum value
        """
        # For binary classification
        if prediction == 0:
            return ThreatLevel.SAFE
        elif prediction == 1:
            # Use probability to determine severity if available
            if prediction_proba is not None:
                if prediction_proba >= 0.9:
                    return ThreatLevel.CRITICAL
                elif prediction_proba >= 0.75:
                    return ThreatLevel.HIGH
                elif prediction_proba >= 0.6:
                    return ThreatLevel.MEDIUM
                else:
                    return ThreatLevel.LOW
            else:
                return ThreatLevel.HIGH  # Default to HIGH if malicious without probability
        
        return ThreatLevel.UNKNOWN
    
    def predict(
        self,
        customer_id: str,
        ioc: str,
        ioc_type: str,
        context_data: Optional[Dict] = None,
        model_type: str = "random_forest"
    ) -> Optional[SourceVerdict]:
        """
        Query customer-specific ML model for threat prediction
        
        Args:
            customer_id: Customer identifier
            ioc: Indicator to analyze
            ioc_type: Type of IOC
            context_data: Additional context from other threat intel sources
            model_type: Type of model to use
            
        Returns:
            SourceVerdict with prediction or None if model not available
        """
        # Load model
        model = self._load_model(customer_id, model_type)
        if model is None:
            return None
        
        # Extract features
        features = self._extract_features(ioc, ioc_type, context_data)
        
        # Load preprocessor if available
        preprocessor = self._load_preprocessor(customer_id)
        
        try:
            # Prepare features for prediction
            # This is simplified - in practice, you'd need to match the exact feature set used during training
            feature_names = list(features.keys())
            feature_values = [features.get(name, 0) for name in feature_names]
            
            # For demonstration, assuming numeric features only
            numeric_features = []
            for val in feature_values:
                if isinstance(val, (int, float)):
                    numeric_features.append(val)
                elif isinstance(val, bool):
                    numeric_features.append(1 if val else 0)
                else:
                    # Skip non-numeric features for now
                    pass
            
            if not numeric_features:
                return None
            
            # Reshape for single prediction
            X = np.array(numeric_features).reshape(1, -1)
            
            # Apply preprocessor if available
            if preprocessor:
                try:
                    X = preprocessor.transform(X)
                except:
                    pass  # Proceed without preprocessing if it fails
            
            # Make prediction
            prediction = model.predict(X)[0]
            
            # Get prediction probability if available
            confidence = 0.75  # Default confidence
            try:
                if hasattr(model, 'predict_proba'):
                    proba = model.predict_proba(X)[0]
                    confidence = float(max(proba))  # Confidence is the max probability
                    prediction_proba = float(proba[1]) if len(proba) > 1 else confidence
                else:
                    prediction_proba = None
            except:
                prediction_proba = None
            
            # Convert to threat level
            threat_level = self._convert_prediction_to_threat_level(prediction, prediction_proba)
            
            # Create SourceVerdict
            verdict = SourceVerdict(
                source_name=f"Customer-{customer_id}-ML",
                source_type=SourceType.CUSTOMER_ML_MODEL,
                threat_level=threat_level,
                confidence=confidence,
                raw_score=float(prediction),
                details={
                    'model_type': model_type,
                    'prediction': int(prediction),
                    'prediction_probability': prediction_proba,
                    'features_used': len(numeric_features),
                    'model_path': str(self._get_customer_model_path(customer_id, model_type))
                },
                timestamp=datetime.now(),
                metadata={
                    'customer_id': customer_id,
                    'ioc': ioc,
                    'ioc_type': ioc_type
                }
            )
            
            return verdict
            
        except Exception as e:
            print(f"Error making prediction with customer {customer_id} model: {e}")
            return None
    
    def get_available_customers(self) -> List[str]:
        """
        Get list of customers with trained models
        
        Returns:
            List of customer IDs
        """
        customers = []
        
        if not self.models_base_path.exists():
            return customers
        
        for item in self.models_base_path.iterdir():
            if item.is_dir() and item.name.startswith('customer_'):
                customer_id = item.name.replace('customer_', '')
                customers.append(customer_id)
        
        return customers
    
    def model_exists(self, customer_id: str, model_type: str = "random_forest") -> bool:
        """
        Check if a model exists for a customer
        
        Args:
            customer_id: Customer identifier
            model_type: Type of model
            
        Returns:
            True if model exists, False otherwise
        """
        model_path = self._get_customer_model_path(customer_id, model_type)
        return model_path.exists()
