import pickle
import json
from pathlib import Path
from config import config
from utils.logger import get_logger
from inference.attack_classifier import AttackClassifier

logger = get_logger("ClassifierLoader")


def load_attack_classifier():
    """
    Load trained attack classification model from disk.
    
    Supports environment variable configuration:
    - ATTACK_CLASSIFIER_MODEL_PATH: Path to pickled classification model
    - ATTACK_CLASSIFIER_METADATA_PATH: Path to JSON metadata file
    
    Returns:
        AttackClassifier instance
        
    Raises:
        FileNotFoundError: If model or metadata files not found
        pickle.UnpicklingError: If model file is corrupted
        json.JSONDecodeError: If metadata file is invalid JSON
    """
    model_path = config.ATTACK_CLASSIFIER_MODEL_PATH
    metadata_path = config.ATTACK_CLASSIFIER_METADATA_PATH
    
    # Convert to Path objects
    model_file = Path(model_path)
    metadata_file = Path(metadata_path)
    
    # Check if files exist
    if not model_file.exists():
        logger.error(f"Classifier model file not found: {model_path}")
        raise FileNotFoundError(f"Classifier model file not found at: {model_path}")
    
    if not metadata_file.exists():
        logger.error(f"Classifier metadata file not found: {metadata_path}")
        raise FileNotFoundError(f"Classifier metadata file not found at: {metadata_path}")
    
    try:
        logger.info(f"Loading classifier model from: {model_path}")
        with open(model_file, "rb") as f:
            model = pickle.load(f)
        logger.info(f"Model loaded successfully. Type: {type(model).__name__}")
        
        logger.info(f"Loading classifier metadata from: {metadata_path}")
        with open(metadata_file, "r") as f:
            metadata = json.load(f)
        logger.info(f"Metadata loaded successfully")
        
        # Convert string keys in class_mapping back to integers
        if 'class_mapping' in metadata and isinstance(metadata['class_mapping'], dict):
            # Convert keys back to int
            metadata['class_mapping'] = {
                int(k): v for k, v in metadata['class_mapping'].items()
            }
        
        if 'class_reverse_mapping' in metadata and isinstance(metadata['class_reverse_mapping'], dict):
            # Convert keys back to int
            metadata['class_reverse_mapping'] = {
                int(k): v for k, v in metadata['class_reverse_mapping'].items()
            }
        
        # Create and return classifier instance
        classifier = AttackClassifier(model, metadata)
        return classifier
        
    except pickle.UnpicklingError as e:
        logger.error(f"Failed to unpickle classifier model: {str(e)}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse classifier metadata JSON: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error loading classifier: {str(e)}")
        raise
