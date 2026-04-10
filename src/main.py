"""
start.py — jalankan gRPC server dan FastAPI REST sebagai 2 worker process terpisah.
Keduanya share file SQLite yang sama (data/predictions.db).

Cara pakai:
    python start.py

Env vars:
    GRPC_PORT   (default 50051)
    REST_PORT   (default 8000)
    DB_PATH     (default data/predictions.db)
"""

import multiprocessing
import os
import sys
from dotenv import load_dotenv

SRC_DIR = os.path.join(os.path.dirname(__file__), "src")

load_dotenv()

def run_grpc():
    sys.path.insert(0, SRC_DIR)

    import grpc
    from concurrent import futures
    from inference.model_loader import load_model
    from inference.predictor import AttackPredictor
    from service.attack_service import AttackService
    import proto.attack_pb2_grpc as attack_pb2_grpc
    from api.database import init_db

    init_db()  # pastikan tabel ada sebelum mulai terima request

    model = load_model()
    predictor = AttackPredictor(model)

    port = os.environ.get("GRPC_PORT", "50051")
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    attack_pb2_grpc.add_AttackDetectionServicer_to_server(AttackService(predictor), server)
    server.add_insecure_port(f"[::]:{port}")

    print(f"[gRPC] Running on port {port}")
    server.start()
    server.wait_for_termination()


def run_rest():
    sys.path.insert(0, SRC_DIR)

    import uvicorn
    port = int(os.environ.get("REST_PORT", "8000"))
    print(f"[REST] Running on port {port}")
    uvicorn.run("api.app:app", host="0.0.0.0", port=port, reload=False)


if __name__ == "__main__":
    grpc_proc = multiprocessing.Process(target=run_grpc, name="grpc-worker")
    rest_proc  = multiprocessing.Process(target=run_rest,  name="rest-worker")

    grpc_proc.start()
    rest_proc.start()

    print("[start] gRPC + REST workers running. Ctrl+C to stop.")

    try:
        grpc_proc.join()
        rest_proc.join()
    except KeyboardInterrupt:
        print("\n[start] Shutting down...")
        grpc_proc.terminate()
        rest_proc.terminate()