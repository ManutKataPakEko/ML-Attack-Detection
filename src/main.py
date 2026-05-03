"""
Start gRPC and REST API servers for attack detection service.

This script runs two worker processes:
1. gRPC server on GRPC_PORT (default 50051)
2. FastAPI REST server on REST_PORT (default 8000)

Both share a SQLite database at data/predictions.db

Environment Variables (all optional, defaults provided):
    MODEL_PATH       - Path to pickled model file (default: models/best_model.pkl)
    GRPC_PORT        - gRPC server port (default: 50051)
    GRPC_WORKERS     - Number of gRPC worker threads (default: 10)
    REST_PORT        - REST API port (default: 8000)
    REST_HOST        - REST API host (default: 0.0.0.0)
    DATABASE_URL     - Database connection URL (default: sqlite:///./data/predictions.db)
    LOG_LEVEL        - Logging level (default: INFO)
    ENV              - Environment: production or development (default: development)

Docker Compose Usage:
    environment:
      - MODEL_PATH=/app/models/best_model.pkl
      - GRPC_PORT=50051
      - REST_PORT=8000
      - DATABASE_URL=postgresql://user:pass@db:5432/mlops_db
      - ENV=production

Local Development:
    Create .env file in project root with same variables
"""

import multiprocessing
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Add src to path for imports
SRC_DIR = os.path.join(os.path.dirname(__file__), "src")
sys.path.insert(0, SRC_DIR)

# Load .env for local development (docker-compose injects directly)
env_file = Path(__file__).parent / ".env"
if env_file.exists():
    load_dotenv(env_file)

# Import config after .env is loaded
from config import config
from utils.logger import get_logger

logger = get_logger("Main")


def run_grpc():
    """Run gRPC server in separate process."""
    import grpc
    from concurrent import futures
    from inference.model_loader import load_model
    from inference.predictor import AttackPredictor
    from service.attack_service import AttackService
    import proto.attack_pb2_grpc as attack_pb2_grpc
    from api.database import init_db

    # Initialize database
    logger.info("Initializing database...")
    init_db()

    # Load model
    logger.info("Loading attack detection model...")
    model = load_model()

    # Initialize predictor
    predictor = AttackPredictor(model)

    # Start gRPC server
    port = config.GRPC_PORT
    workers = config.GRPC_WORKERS
    
    logger.info(f"Starting gRPC server on port {port} with {workers} workers...")
    
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=workers))
    attack_pb2_grpc.add_AttackDetectionServicer_to_server(
        AttackService(predictor),
        server
    )
    server.add_insecure_port(f"[::]:{port}")

    server.start()
    logger.info(f"✓ gRPC server running on port {port}")
    server.wait_for_termination()


def run_rest():
    """Run FastAPI REST server in separate process."""
    import uvicorn

    port = config.REST_PORT
    host = config.REST_HOST
    reload = config.REST_RELOAD

    logger.info(f"Starting REST API on {host}:{port} (reload={reload})...")
    uvicorn.run(
        "api.app:app",
        host=host,
        port=port,
        reload=reload,
        log_level=config.LOG_LEVEL.lower()
    )


if __name__ == "__main__":
    # Log startup configuration
    logger.info("=" * 60)
    logger.info("Attack Detection Service Starting")
    logger.info("=" * 60)
    logger.info(f"Environment: {config.is_production() and 'PRODUCTION' or 'DEVELOPMENT'}")
    logger.info(f"Running in Docker: {config.is_docker()}")
    logger.info(f"Model Path: {config.MODEL_PATH}")
    logger.info(f"Database: {config.DATABASE_URL}")
    logger.info(f"gRPC Port: {config.GRPC_PORT}")
    logger.info(f"REST Port: {config.REST_PORT}")
    logger.info("=" * 60)

    # Start workers
    grpc_proc = multiprocessing.Process(target=run_grpc, name="grpc-worker")
    rest_proc = multiprocessing.Process(target=run_rest, name="rest-worker")

    grpc_proc.start()
    rest_proc.start()

    logger.info("✓ All workers started. Press Ctrl+C to shutdown.")

    try:
        grpc_proc.join()
        rest_proc.join()
    except KeyboardInterrupt:
        logger.info("\nShutting down...")
        grpc_proc.terminate()
        rest_proc.terminate()
        grpc_proc.join(timeout=5)
        rest_proc.join(timeout=5)
        logger.info("✓ Shutdown complete")