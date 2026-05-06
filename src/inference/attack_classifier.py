import pandas as pd
import numpy as np
import json
from pathlib import Path
from config import config
from utils.logger import get_logger

logger = get_logger("AttackClassifier")


class AttackClassifier:
    """
    Classify detected attacks into specific attack types:
    - sql_injection
    - script_injection
    - path_traversal
    - command_injection
    - mixed_attack
    - other_attack
    
    Requires that the attack detection model has already classified
    the request as an attack (prediction=1).
    """
    
    def __init__(self, model, metadata):
        """
        Initialize classifier with trained model and metadata.
        
        Args:
            model: Trained multiclass classifier (XGBoost)
            metadata: Dictionary containing:
                - class_mapping: Dict mapping class names to numeric codes
                - class_reverse_mapping: Dict mapping numeric codes to class names
                - features: List of feature names required by the model
        """
        self.model = model
        self.metadata = metadata
        self.class_mapping = metadata.get('class_mapping', {})
        self.class_reverse_mapping = metadata.get('class_reverse_mapping', {})
        self.features = metadata.get('features', [])
        
        logger.info(f"AttackClassifier initialized with {len(self.features)} features")
        logger.info(f"Classes: {self.class_reverse_mapping}")

    def classify(self, features: dict) -> dict:
        """
        Classify attack type based on engineered features.
        
        Args:
            features: Dictionary with engineered features (scaled).
                     Must include all features in self.features.
        
        Returns:
            dict: {
                'attack_type': str (e.g., 'sql_injection'),
                'confidence': float (0-1),
                'probabilities': dict (class: probability)
            }
            
        Raises:
            ValueError: If required features are missing
            KeyError: If feature names don't match expected features
        """
        # Validate required features
        missing_features = [f for f in self.features if f not in features]
        if missing_features:
            logger.warning(f"Missing features for classification: {missing_features}")
            raise ValueError(f"Missing required features: {missing_features}")
        
        try:
            # Create dataframe with features in correct order
            df = pd.DataFrame([features])
            
            # Handle NaN and infinity values
            for feat in self.features:
                if pd.isna(df[feat].iloc[0]):
                    logger.debug(f"Feature {feat} is NaN, filling with 0")
                    df[feat] = 0
            
            df = df.replace([np.inf, -np.inf], 0)
            
            # Select features in correct order
            X = df[self.features]
            
            # Get prediction
            pred = self.model.predict(X)[0]
            
            # Get prediction probabilities
            if hasattr(self.model, 'predict_proba'):
                proba = self.model.predict_proba(X)[0]
                probabilities = {
                    self.class_reverse_mapping[i]: float(proba[i])
                    for i in range(len(proba))
                }
            else:
                probabilities = {self.class_reverse_mapping[pred]: 1.0}
            
            attack_type = self.class_reverse_mapping[pred]
            confidence = float(max(probabilities.values()))
            
            logger.info(f"Classification: {attack_type} (confidence: {confidence:.2%})")
            
            return {
                'attack_type': attack_type,
                'confidence': confidence,
                'probabilities': probabilities
            }
            
        except Exception as e:
            logger.error(f"Error during classification: {str(e)}")
            raise
    
    def classify_proba(self, features: dict) -> dict:
        """
        Get classification probabilities for all attack types.
        
        Args:
            features: Dictionary with engineered features (scaled).
        
        Returns:
            dict: Probabilities for each attack type
        """
        missing_features = [f for f in self.features if f not in features]
        if missing_features:
            raise ValueError(f"Missing required features: {missing_features}")
        
        try:
            df = pd.DataFrame([features])
            
            for feat in self.features:
                if pd.isna(df[feat].iloc[0]):
                    df[feat] = 0
            
            df = df.replace([np.inf, -np.inf], 0)
            X = df[self.features]
            
            if hasattr(self.model, 'predict_proba'):
                proba = self.model.predict_proba(X)[0]
                return {
                    self.class_reverse_mapping[i]: float(proba[i])
                    for i in range(len(proba))
                }
            else:
                pred = self.model.predict(X)[0]
                return {self.class_reverse_mapping[pred]: 1.0}
        
        except Exception as e:
            logger.error(f"Error getting probabilities: {str(e)}")
            raise
