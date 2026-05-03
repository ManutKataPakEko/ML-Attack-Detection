import pickle
from pathlib import Path
from config import config
from utils.logger import get_logger

logger = get_logger("ModelLoader")


def load_model():
    """
    Load trained model from disk.
    
    Supports environment variable configuration:
    - MODEL_PATH: Path to pickled model file
    
    Returns:
        Loaded scikit-learn model object
        
    Raises:
        FileNotFoundError: If model file not found
        pickle.UnpicklingError: If model file is corrupted
    """
    model_path = config.MODEL_PATH
    
    # Convert to Path object for cross-platform compatibility
    model_file = Path(model_path)
    
    # Check if file exists
    if not model_file.exists():
        logger.error(f"Model file not found: {model_path}")
        raise FileNotFoundError(f"Model file not found at: {model_path}")
    
    try:
        logger.info(f"Loading model from: {model_path}")
        with open(model_file, "rb") as f:
            model = pickle.load(f)
        logger.info(f"Model loaded successfully. Type: {type(model).__name__}")
        return model
    except pickle.UnpicklingError as e:
        logger.error(f"Failed to unpickle model: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error loading model: {str(e)}")
        raise