"""
Machine Learning predictor module for anomaly detection with Random Forest.
"""

import joblib
import pickle
import numpy as np
from typing import Tuple, Dict, Any, Optional
import logging
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder

class MLPredictor:
    """
    ML predictor for network intrusion detection using Random Forest.
    
    Attributes:
        model: Trained RandomForest model.
        scaler: StandardScaler for feature normalization.
        label_encoder: LabelEncoder for attack type decoding.
        threshold: Anomaly detection threshold.
        metadata: Model metadata including feature names.
        n_features_expected: Expected number of features.
    """
    
    def __init__(self, model_path: str, scaler_path: str, encoder_path: str, threshold: float = 0.7):
        """
        Initialize ML predictor with trained models.
        
        Args:
            model_path: Path to RandomForest model pickle file.
            scaler_path: Path to StandardScaler pickle file.
            encoder_path: Path to LabelEncoder pickle file.
            threshold: Probability threshold for anomaly detection.
        
        Raises:
            FileNotFoundError: If model files are not found.
            Exception: If model loading fails.
        """
        self.logger = logging.getLogger(__name__)
        self.threshold = threshold
        
        try:
            # Load model
            self.model = joblib.load(model_path)
            self.logger.info(f"Model loaded from {model_path}")
            
            # Load scaler
            self.scaler = joblib.load(scaler_path)
            self.logger.info(f"Scaler loaded from {scaler_path}")
            
            # Load label encoder
            self.label_encoder = joblib.load(encoder_path)
            self.logger.info(f"Label encoder loaded from {encoder_path}")
            
            # Load metadata if available
            metadata_path = Path(model_path).parent / 'model_metadata.pkl'
            if metadata_path.exists():
                with open(metadata_path, 'rb') as f:
                    self.metadata = pickle.load(f)
                self.logger.info("Model metadata loaded")
            else:
                self.metadata = {}
                self.logger.warning("Model metadata not found")
            
            # Get expected number of features
            self.n_features_expected = self.model.n_features_in_
            self.logger.info(f"Model expects {self.n_features_expected} features")
            
        except FileNotFoundError as e:
            self.logger.error(f"Model file not found: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Failed to load ML models: {e}")
            raise
    
    def predict(self, features: list) -> Tuple[str, float, str, str]:
        """
        Make prediction on extracted features.
        
        Args:
            features: List of feature values.
        
        Returns:
            Tuple containing:
            - prediction: "Normal" or "Anomalous"
            - confidence: Probability score (0.0 to 1.0)
            - severity: Severity level ("None", "Low", "Medium", "High", "Critical")
            - attack_type: Type of attack detected
        
        Raises:
            ValueError: If features are invalid.
            Exception: If prediction fails.
        """
        try:
            # Validate input
            if not features:
                raise ValueError("Empty feature list provided")
            
            # Ensure correct number of features
            features = self._adjust_feature_length(features)
            
            # Convert to numpy array and reshape
            features_array = np.array(features).reshape(1, -1)
            
            # Scale features
            features_scaled = self.scaler.transform(features_array)
            
            # Get prediction probabilities
            if hasattr(self.model, 'predict_proba'):
                probabilities = self.model.predict_proba(features_scaled)[0]
            else:
                # For models without predict_proba
                prediction = self.model.predict(features_scaled)[0]
                probabilities = [1.0 if prediction == 0 else 0.0, 
                               0.0 if prediction == 0 else 1.0]
            
            # Get class prediction
            class_idx = self.model.predict(features_scaled)[0]
            
            # Decode attack type
            attack_type = self._decode_attack_type(class_idx)
            
            # Determine if anomaly
            is_anomaly = attack_type != "Normal"
            
            if is_anomaly:
                # Anomalous traffic
                prediction = "Anomalous"
                # Use probability of the predicted class
                confidence = probabilities[class_idx] if len(probabilities) > class_idx else 0.5
                severity = self._determine_severity(confidence, attack_type)
            else:
                # Normal traffic
                prediction = "Normal"
                confidence = probabilities[class_idx] if len(probabilities) > class_idx else 0.5
                severity = "None"
                attack_type = "Normal"
            
            self.logger.debug(f"Prediction: {prediction}, Confidence: {confidence:.3f}, "
                           f"Severity: {severity}, Attack: {attack_type}")
            
            return prediction, float(confidence), severity, attack_type
            
        except Exception as e:
            self.logger.error(f"Prediction error: {e}")
            # Return safe default
            return "Normal", 0.0, "None", "Normal"
    
    def _adjust_feature_length(self, features: list) -> list:
        """
        Adjust feature list to match expected length.
        
        Args:
            features: Input feature list.
        
        Returns:
            Adjusted feature list with correct length.
        """
        n_features = len(features)
        
        if n_features < self.n_features_expected:
            # Pad with zeros
            padding = [0.0] * (self.n_features_expected - n_features)
            self.logger.warning(f"Features padded: {n_features} -> {self.n_features_expected}")
            return features + padding
        elif n_features > self.n_features_expected:
            # Truncate
            self.logger.warning(f"Features truncated: {n_features} -> {self.n_features_expected}")
            return features[:self.n_features_expected]
        else:
            return features
    
    def _decode_attack_type(self, class_idx: int) -> str:
        """
        Decode numeric class index to attack type name.
        
        Args:
            class_idx: Numeric class index.
        
        Returns:
            Attack type name.
        """
        try:
            if hasattr(self.label_encoder, 'inverse_transform'):
                attack_name = self.label_encoder.inverse_transform([class_idx])[0]
            else:
                # Fallback to mapping from metadata
                attack_mapping = self.metadata.get('attack_mapping', {})
                attack_name = attack_mapping.get(str(class_idx), f'Attack_{class_idx}')
            
            return str(attack_name)
        except Exception:
            return "Unknown"
    
    def _determine_severity(self, confidence: float, attack_type: str) -> str:
        """
        Determine severity level based on confidence and attack type.
        
        Args:
            confidence: Prediction confidence (0.0 to 1.0).
            attack_type: Type of attack detected.
        
        Returns:
            Severity level string.
        """
        # Adjust thresholds based on attack type
        if attack_type in ["DDoS", "DoS", "Botnet"]:
            # These attacks are more critical
            if confidence >= 0.9:
                return "Critical"
            elif confidence >= 0.7:
                return "High"
            elif confidence >= 0.5:
                return "Medium"
            else:
                return "Low"
        elif attack_type in ["Probe", "PortScan", "Reconnaissance"]:
            # Scanning/probing attacks
            if confidence >= 0.8:
                return "High"
            elif confidence >= 0.6:
                return "Medium"
            elif confidence >= 0.4:
                return "Low"
            else:
                return "Info"
        else:
            # Other attacks
            if confidence >= 0.85:
                return "Critical"
            elif confidence >= 0.65:
                return "High"
            elif confidence >= 0.45:
                return "Medium"
            else:
                return "Low"
    
    def get_feature_importance(self, top_n: int = 20) -> Dict[str, float]:
        """
        Get feature importance from RandomForest model.
        
        Args:
            top_n: Number of top features to return.
        
        Returns:
            Dictionary of feature names and importance scores.
        """
        try:
            if hasattr(self.model, 'feature_importances_'):
                importances = self.model.feature_importances_
                feature_names = self.metadata.get('feature_names',
                                                 [f"Feature_{i}" for i in range(len(importances))])
                
                # Sort by importance
                indices = np.argsort(importances)[::-1]
                
                top_features = {}
                for i in range(min(top_n, len(importances))):
                    idx = indices[i]
                    top_features[feature_names[idx]] = float(importances[idx])
                
                return top_features
            else:
                return {}
        except Exception as e:
            self.logger.error(f"Error getting feature importance: {e}")
            return {}
    
    def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about the loaded model.
        
        Returns:
            Dictionary with model information.
        """
        info = {
            'model_type': type(self.model).__name__,
            'n_features': self.n_features_expected,
            'n_classes': len(self.label_encoder.classes_) if hasattr(self.label_encoder, 'classes_') else 'Unknown',
            'threshold': self.threshold,
            'classes': list(self.label_encoder.classes_) if hasattr(self.label_encoder, 'classes_') else []
        }
        
        # Add RandomForest specific info
        if hasattr(self.model, 'n_estimators'):
            info['n_estimators'] = self.model.n_estimators
            info['max_depth'] = self.model.max_depth
            info['oob_score'] = getattr(self.model, 'oob_score_', 'Not available')
        
        return info
