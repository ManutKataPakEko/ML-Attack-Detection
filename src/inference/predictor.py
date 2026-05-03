import pandas as pd
import numpy as np
from config import config
from utils.logger import get_logger

logger = get_logger("AttackPredictor")


class AttackPredictor:
    """
    Predict if a request is an attack using trained model.
    
    The model was trained with 20 features selected via SelectKBest from
    an initial 23 engineered features. Removed features:
    - path_special_chars
    - suspicious_headers
    - sql_injection_score
    
    Features are defined in config.FEATURE_NAMES and must match
    the training data from v0.1.1 feature engineering pipeline.
    """
    
    def __init__(self, model):
        """
        Initialize predictor with trained model.
        
        Args:
            model: Trained scikit-learn classifier
        """
        self.model = model
        self.features = config.FEATURE_NAMES
        
        logger.info(f"AttackPredictor initialized with {len(self.features)} features")
        logger.debug(f"Features: {self.features}")

    def predict(self, data: dict) -> int:
        """
        Predict if request is attack (1) or normal (0).
        
        Args:
            data: Dictionary with 20 engineered features selected by trained model.
                  Keys must match config.FEATURE_NAMES.
                  Note: Some IP-based and time-based features may be pre-filled 
                        with defaults and should be updated with actual statistics.
        
        Returns:
            int: 0 for normal, 1 for attack
            
        Raises:
            ValueError: If required features are missing
            KeyError: If feature names don't match training data
        """
        # Validate that all required features are present
        missing_features = [f for f in self.features if f not in data]
        if missing_features:
            logger.warning(f"Missing features: {missing_features}")
            raise ValueError(f"Missing required features: {missing_features}")
        
        # Create dataframe with features in correct order
        try:
            df = pd.DataFrame([data])
            
            # Ensure all features are numeric and handle NaN
            for feat in self.features:
                if pd.isna(df[feat].iloc[0]):
                    logger.warning(f"Feature {feat} is NaN, filling with 0")
                    df[feat] = df[feat].fillna(0)
            
            # Handle infinity values
            df = df.replace([np.inf, -np.inf], 0)
            
            # Select features in correct order
            X = df[self.features]
            
            # Make prediction
            pred = self.model.predict(X)
            prediction = int(pred[0])
            
            logger.debug(f"Prediction made: {prediction} (0=normal, 1=attack)")
            return prediction
            
        except KeyError as e:
            logger.error(f"Feature name mismatch: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error during prediction: {str(e)}")
            raise
    
    def predict_proba(self, data: dict) -> dict:
        """
        Get prediction probabilities for both classes.
        
        Args:
            data: Dictionary with 20 engineered features selected by trained model.
        
        Returns:
            dict: {'normal': prob_normal, 'attack': prob_attack}
        """
        missing_features = [f for f in self.features if f not in data]
        if missing_features:
            raise ValueError(f"Missing required features: {missing_features}")
        
        try:
            df = pd.DataFrame([data])
            
            # Clean data
            for feat in self.features:
                if pd.isna(df[feat].iloc[0]):
                    df[feat] = df[feat].fillna(0)
            
            df = df.replace([np.inf, -np.inf], 0)
            X = df[self.features]
            
            # Get probabilities if model supports it
            if hasattr(self.model, 'predict_proba'):
                proba = self.model.predict_proba(X)[0]
                return {
                    'normal': float(proba[0]),
                    'attack': float(proba[1])
                }
            else:
                # Fallback for models without predict_proba
                pred = self.model.predict(X)[0]
                return {
                    'normal': 0.0 if pred == 1 else 1.0,
                    'attack': 1.0 if pred == 1 else 0.0
                }
                
        except Exception as e:
            logger.error(f"Error getting prediction probabilities: {str(e)}")
            raise