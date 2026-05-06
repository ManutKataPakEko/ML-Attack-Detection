"""
Configuration module for Attack Detection System.
Supports environment variables, .env files, and docker-compose environments.

Priority order:
1. Environment variables (e.g., set in docker-compose.yaml)
2. .env file (for local development)
3. Hardcoded defaults
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file if it exists (for local development)
# docker-compose will inject these as env vars directly
env_file = Path(__file__).parent.parent / ".env"
if env_file.exists():
    load_dotenv(env_file)


class Config:
    """Central configuration for attack detection service."""
    
    # ========== Model Configuration ==========
    MODEL_PATH = os.getenv(
        "MODEL_PATH",
        "models/attack-detection-v0.1.1.pkl"
    )
    
    # Attack Classification Model
    ATTACK_CLASSIFIER_MODEL_PATH = os.getenv(
        "ATTACK_CLASSIFIER_MODEL_PATH",
        "models/attack-classification-v0.1.1.pkl"
    )
    
    ATTACK_CLASSIFIER_METADATA_PATH = os.getenv(
        "ATTACK_CLASSIFIER_METADATA_PATH",
        "models/attack-classification-v0.1.1-metadata.json"
    )
    
    # ========== Database Configuration ==========
    DATABASE_URL = os.getenv(
        "DATABASE_URL",
        "sqlite:///./data/predictions.db"
    )
    
    # ========== gRPC Configuration ==========
    GRPC_PORT = os.getenv(
        "GRPC_PORT",
        "50051"
    )
    
    GRPC_WORKERS = int(os.getenv(
        "GRPC_WORKERS",
        "10"
    ))
    
    # ========== REST API Configuration ==========
    REST_PORT = int(os.getenv(
        "REST_PORT",
        "8000"
    ))
    
    REST_HOST = os.getenv(
        "REST_HOST",
        "0.0.0.0"
    )
    
    REST_RELOAD = os.getenv(
        "REST_RELOAD",
        "false"
    ).lower() == "true"
    
    # ========== Logging Configuration ==========
    LOG_LEVEL = os.getenv(
        "LOG_LEVEL",
        "INFO"
    )
    
    LOG_DIR = os.getenv(
        "LOG_DIR",
        "logs"
    )
    
    # ========== Feature Configuration ==========
    # Number of features expected by the model
    # Model was trained with SelectKBest and selected 20 out of 23 engineered features
    NUM_FEATURES = 20
    
    # Feature names (must match training data)
    # These are the 20 features selected by the trained model
    FEATURE_NAMES = [
        # URL/Path Features (5 out of 6)
        'path_depth', 'path_encoded_chars', 'query_param_count',
        'query_special_chars', 'suspicious_path',
        # HTTP Header Features (2 out of 3)
        'header_count', 'user_agent_length',
        # Request Body Features (2)
        'body_contains_code', 'body_special_chars_ratio',
        # IP-based Features (3)
        'ip_attack_rate', 'ip_request_count', 'is_high_risk_ip',
        # Time-based Features (5)
        'hour', 'day_of_week', 'is_business_hours', 'is_night_time',
        'request_freq_per_hour',
        # Encoding & Pattern Features (4 out of 5)
        'has_url_encoding', 'has_double_encoding', 'has_directory_traversal'
    ]
    
    # Features NOT selected by the model (removed by SelectKBest)
    REMOVED_FEATURES = ['path_special_chars', 'suspicious_headers', 'sql_injection_score']
    
    # ========== Data Configuration ==========
    DATA_DIR = os.getenv(
        "DATA_DIR",
        "data"
    )
    
    PROCESSED_DATA_DIR = os.getenv(
        "PROCESSED_DATA_DIR",
        "data/processed/v0.1.1"
    )
    
    # ========== Environment Detection ==========
    @classmethod
    def is_docker(cls) -> bool:
        """Check if running in Docker container."""
        return os.path.exists("/.dockerenv")
    
    @classmethod
    def is_production(cls) -> bool:
        """Check if running in production environment."""
        return os.getenv("ENV", "development").lower() == "production"
    
    @classmethod
    def get_all_settings(cls) -> dict:
        """Get all configuration settings as dictionary."""
        return {
            "model_path": cls.MODEL_PATH,
            "database_url": cls.DATABASE_URL,
            "grpc_port": cls.GRPC_PORT,
            "grpc_workers": cls.GRPC_WORKERS,
            "rest_port": cls.REST_PORT,
            "rest_host": cls.REST_HOST,
            "rest_reload": cls.REST_RELOAD,
            "log_level": cls.LOG_LEVEL,
            "log_dir": cls.LOG_DIR,
            "num_features": cls.NUM_FEATURES,
            "is_docker": cls.is_docker(),
            "is_production": cls.is_production(),
        }


# Export singleton config instance
config = Config()
