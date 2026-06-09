"""
LK-07: Model Registry Management
- Registrasi, versioning, dan transisi stage model
- Verifikasi inferensi model Production
- Sinkronisasi metadata dengan DVC (simpan ke models/ lalu dvc add)

MLflow endpoint: MLFLOW_TRACKING_URI=http://mlflow:5000 (docker-compose)
Fallback       : http://localhost:5000
"""

import os
import json
import logging
import argparse
import subprocess
import pandas as pd
import mlflow
import mlflow.pyfunc
from mlflow.tracking import MlflowClient
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
MLFLOW_TRACKING_URI = os.getenv("MLFLOW_TRACKING_URI", "http://localhost:5000")
MODEL_NAME          = "log-attack-detector"

REPO_ROOT   = Path(__file__).resolve().parents[1]
MODELS_DIR  = REPO_ROOT / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

# Kolom fitur — harus sinkron dengan FEATURE_COLS di train.py
FEATURE_COLS = [
    "path_depth", "path_special_chars", "path_encoded_chars",
    "query_param_count", "query_special_chars", "suspicious_path",
    "header_count", "suspicious_headers", "user_agent_length",
    "body_contains_code", "body_special_chars_ratio",
    "ip_attack_rate", "ip_request_count", "is_high_risk_ip",
    "hour", "day_of_week", "is_business_hours", "is_night_time",
    "request_freq_per_hour",
    "has_url_encoding", "has_double_encoding",
    "has_directory_traversal", "sql_injection_score",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_client() -> MlflowClient:
    mlflow.set_tracking_uri(MLFLOW_TRACKING_URI)
    logger.info(f"MLflow URI: {MLFLOW_TRACKING_URI}")
    return MlflowClient()


def _dvc_track_models(message: str):
    """DVC add models/ + git commit (non-fatal jika gagal)."""
    try:
        subprocess.run(
            ["dvc", "add", "models"],
            cwd=REPO_ROOT, check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "add", "models.dvc", ".gitignore"],
            cwd=REPO_ROOT, check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "commit", "-m", message],
            cwd=REPO_ROOT, check=False, capture_output=True,
        )
        logger.info(f"DVC tracked models/: {message}")
    except Exception as e:
        logger.warning(f"DVC track non-fatal: {e}")


# ── Actions ───────────────────────────────────────────────────────────────────

def list_model_versions(client: MlflowClient, model_name: str = MODEL_NAME):
    """Tampilkan semua versi model beserta stage dan metrik utama."""
    try:
        versions = client.search_model_versions(f"name='{model_name}'")
    except Exception as e:
        logger.error(f"Gagal mengambil versi model: {e}")
        return []

    if not versions:
        logger.info(f"Belum ada versi untuk model '{model_name}'.")
        return []

    logger.info(f"\n{'='*70}")
    logger.info(f"Model Registry: {model_name}  |  {len(versions)} version(s)")
    logger.info(f"{'='*70}")
    logger.info(f"  {'Ver':<5} {'Stage':<14} {'Run ID':<12} {'Status':<12} {'F1':>7} {'AUC':>7}")
    logger.info(f"  {'-'*63}")
    for v in sorted(versions, key=lambda x: int(x.version)):
        try:
            run = client.get_run(v.run_id)
            f1  = run.data.metrics.get("f1_score", float("nan"))
            auc = run.data.metrics.get("roc_auc",  float("nan"))
        except Exception:
            f1 = auc = float("nan")
        logger.info(
            f"  v{v.version:<4} {v.current_stage:<14} {v.run_id[:10]:<12} "
            f"{v.status:<12} {f1:>7.4f} {auc:>7.4f}"
        )
    logger.info(f"{'='*70}")
    return versions


def register_from_run(
    client: MlflowClient,
    run_id: str,
    model_name: str = MODEL_NAME,
    stage: str = "Staging",
) -> str:
    """
    Daftarkan model dari MLflow run_id ke Model Registry,
    lalu pindahkan ke stage yang diminta.
    Returns: version string
    """
    model_uri = f"runs:/{run_id}/model"
    logger.info(f"Registering run {run_id[:8]} → '{model_name}' ...")
    mv = mlflow.register_model(model_uri, model_name)
    logger.info(f"Registered: version={mv.version}")

    client.transition_model_version_stage(
        name=model_name,
        version=mv.version,
        stage=stage,
    )
    logger.info(f"v{mv.version} → {stage}")
    return mv.version


def promote_to_production(
    client: MlflowClient,
    version: str,
    model_name: str = MODEL_NAME,
    dvc_track: bool = True,
):
    """
    Pindahkan versi tertentu ke Production.
    Versi Production lama diarsipkan.
    Metadata disimpan ke models/ dan di-track DVC.
    """
    # Arsipkan Production lama
    for prod in client.get_latest_versions(model_name, stages=["Production"]):
        logger.info(f"Archiving current Production v{prod.version}")
        client.transition_model_version_stage(
            name=model_name,
            version=prod.version,
            stage="Archived",
            archive_existing_versions=False,
        )

    # Naikkan ke Production
    client.transition_model_version_stage(
        name=model_name,
        version=version,
        stage="Production",
    )
    logger.info(f"v{version} → Production")

    # Simpan metadata
    meta = save_model_metadata(client, version, model_name)

    # Buat symlink production model jika file .pkl tersedia
    run_id   = meta["run_id"]
    pkl_path = MODELS_DIR / f"model_{run_id[:8]}.pkl"
    prod_pkl = MODELS_DIR / "attack-detection-v0.1.1.pkl"
    if pkl_path.exists():
        prod_pkl.unlink(missing_ok=True)
        prod_pkl.symlink_to(pkl_path.name)
        logger.info(f"Production symlink: {prod_pkl.name} → {pkl_path.name}")

    # DVC track
    if dvc_track:
        _dvc_track_models(f"model: promote v{version} to Production")

    return meta


def save_model_metadata(
    client: MlflowClient,
    version: str,
    model_name: str = MODEL_NAME,
) -> dict:
    """
    Simpan metadata model ke:
      models/model_registry_metadata_v<version>.json
      models/production_model_metadata.json  (selalu versi Production terkini)
    """
    mv  = client.get_model_version(model_name, version)
    run = client.get_run(mv.run_id)

    metadata = {
        "model_name":  model_name,
        "version":     version,
        "stage":       mv.current_stage,
        "run_id":      mv.run_id,
        "metrics":     dict(run.data.metrics),
        "params":      dict(run.data.params),
        "tags":        dict(run.data.tags),
        "created_at":  mv.creation_timestamp,
        "updated_at":  mv.last_updated_timestamp,
        "source":      mv.source,
        "description": mv.description or "",
        "mlflow_uri":  MLFLOW_TRACKING_URI,
    }

    for fname in [
        f"model_registry_metadata_v{version}.json",
        "production_model_metadata.json",
    ]:
        path = MODELS_DIR / fname
        with open(path, "w") as f:
            json.dump(metadata, f, indent=2)
        logger.info(f"Metadata → {path}")

    return metadata


def verify_inference(
    model_name: str = MODEL_NAME,
    stage: str = "Production",
):
    """
    Load model dari MLflow Registry dan uji dengan sampel request HTTP.
    Sampel mencakup pola serangan umum pada OJS (SQLi, path traversal, normal).
    """
    logger.info(f"\n=== Inference Verification: {model_name} [{stage}] ===")
    model_uri = f"models:/{model_name}/{stage}"
    logger.info(f"Loading: {model_uri}")

    model = mlflow.pyfunc.load_model(model_uri)
    logger.info(f"Model class: {type(model)}")

    # Sampel test — kolom sesuai FEATURE_COLS
    zero = {c: 0 for c in FEATURE_COLS}
    test_cases = [
        {
            "name": "SQL Injection",
            "features": {**zero,
                "sql_injection_score": 5, "query_special_chars": 8,
                "path_special_chars": 3, "query_param_count": 2,
                "status_code_4xx": 0,
            },
            "expected": 1,
        },
        {
            "name": "Path Traversal",
            "features": {**zero,
                "has_directory_traversal": 1, "path_encoded_chars": 3,
                "has_double_encoding": 1, "path_depth": 8,
            },
            "expected": 1,
        },
        {
            "name": "Normal Request",
            "features": {**zero,
                "path_depth": 2, "hour": 10, "is_business_hours": 1,
                "day_of_week": 2,
            },
            "expected": 0,
        },
        {
            "name": "Bot User-Agent",
            "features": {**zero,
                "suspicious_headers": 1, "user_agent_length": 8,
                "ip_request_count": 500, "request_freq_per_hour": 120,
            },
            "expected": 1,
        },
    ]

    correct = 0
    logger.info(f"\n  {'Test Case':<22} {'Pred':<10} {'Expected':<10} {'OK?'}")
    logger.info(f"  {'-'*52}")
    for tc in test_cases:
        # Hanya gunakan kolom yang tersedia di model
        df   = pd.DataFrame([tc["features"]])
        pred = model.predict(df)
        raw  = int(pred[0])
        ok   = raw == tc["expected"]
        correct += int(ok)
        label = "ATTACK" if raw == 1 else "NORMAL"
        exp   = "ATTACK" if tc["expected"] == 1 else "NORMAL"
        logger.info(f"  {tc['name']:<22} {label:<10} {exp:<10} {'OK' if ok else 'MISMATCH'}")

    logger.info(f"\n  Accuracy on test cases: {correct}/{len(test_cases)}")
    logger.info("=== Inference verification complete ===")
    return correct == len(test_cases)


def compare_model_versions(
    client: MlflowClient,
    v1: str,
    v2: str,
    model_name: str = MODEL_NAME,
) -> str:
    """Bandingkan metrik dua versi model. Returns versi yang lebih baik."""
    logger.info(f"\n=== Compare v{v1} vs v{v2} ===")

    mv1, mv2   = client.get_model_version(model_name, v1), client.get_model_version(model_name, v2)
    run1, run2 = client.get_run(mv1.run_id), client.get_run(mv2.run_id)

    metrics_keys = ["accuracy", "f1_score", "precision", "recall", "roc_auc", "cv_f1_mean"]

    logger.info(f"\n  {'Metric':<18} {'v'+v1:<12} {'v'+v2:<12} {'Delta':<10} {'Better'}")
    logger.info(f"  {'-'*62}")
    for m in metrics_keys:
        val1  = run1.data.metrics.get(m, 0.0)
        val2  = run2.data.metrics.get(m, 0.0)
        delta = val2 - val1
        arrow = "↑" if delta > 0.0001 else ("↓" if delta < -0.0001 else "→")
        better = f"v{v2}" if delta > 0 else (f"v{v1}" if delta < 0 else "tie")
        logger.info(f"  {m:<18} {val1:<12.4f} {val2:<12.4f} {arrow}{abs(delta):.4f}    {better}")

    f1_v1 = run1.data.metrics.get("f1_score", 0)
    f1_v2 = run2.data.metrics.get("f1_score", 0)
    winner = v2 if f1_v2 >= f1_v1 else v1
    logger.info(f"\n  Winner (F1): v{winner}")
    return winner


# ── Main ──────────────────────────────────────────────────────────────────────

def main(args):
    client = get_client()
    mn     = args.model_name

    if args.action == "list":
        list_model_versions(client, mn)

    elif args.action == "register":
        if not args.run_id:
            logger.error("--run-id diperlukan untuk action 'register'")
            return
        version = register_from_run(client, args.run_id, mn, stage=args.stage)
        logger.info(f"Registered as version {version} in stage {args.stage}")

    elif args.action == "promote":
        promote_to_production(client, args.version, mn, dvc_track=not args.no_dvc)

    elif args.action == "verify":
        ok = verify_inference(mn, args.stage)
        raise SystemExit(0 if ok else 1)

    elif args.action == "compare":
        if not args.v1 or not args.v2:
            logger.error("--v1 dan --v2 diperlukan untuk action 'compare'")
            return
        compare_model_versions(client, args.v1, args.v2, mn)

    elif args.action == "metadata":
        save_model_metadata(client, args.version, mn)

    else:
        logger.error(f"Action tidak dikenal: {args.action}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MLOps - Model Registry Manager")
    parser.add_argument("--action",     type=str, default="list",
                        choices=["list", "register", "promote", "verify", "compare", "metadata"],
                        help="Aksi yang dijalankan")
    parser.add_argument("--model-name", type=str, default=MODEL_NAME)
    parser.add_argument("--version",    type=str, default="1",
                        help="Versi model (untuk promote/metadata)")
    parser.add_argument("--stage",      type=str, default="Staging",
                        choices=["Staging", "Production", "Archived"],
                        help="Stage tujuan (register/verify)")
    parser.add_argument("--run-id",     type=str, default=None,
                        help="MLflow run_id sumber model (untuk action register)")
    parser.add_argument("--v1",         type=str, default=None,
                        help="Versi pertama (compare)")
    parser.add_argument("--v2",         type=str, default=None,
                        help="Versi kedua (compare)")
    parser.add_argument("--no-dvc",     action="store_true",
                        help="Skip DVC tracking setelah promote")
    args = parser.parse_args()
    main(args)