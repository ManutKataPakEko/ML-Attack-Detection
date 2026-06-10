"""
LK-06 & LK-07: Model Training dengan MLflow Integration
- Logging parameter, metrik, dan artefak model
- Registrasi ke MLflow Model Registry
- Support multiple experiment runs (hyperparameter tuning)

Terintegrasi dengan:
  - ingest_data.py  → tarik data terbaru dari PostgreSQL + DVC track
  - preprocess.py   → cleaning, feature engineering, scale/select
  - DVC             → versioning data & model artifacts
  - MLflow          → http://mlflow:5000 (docker-compose service)
"""

import os
import sys
import json
import logging
import argparse
import subprocess
import warnings
import numpy as np
import pandas as pd
import mlflow
import mlflow.sklearn
import mlflow.xgboost
import joblib
from pathlib import Path
from datetime import datetime

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix, classification_report,
)
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
# train.py ada di src/training/train.py → parents[0]=src/training, [1]=src, [2]=repo root
REPO_ROOT      = Path(__file__).resolve().parents[2]
PROCESSED_DIR  = REPO_ROOT / "data" / "processed" / "v0.1.1"
RAW_DATA_DIR   = REPO_ROOT / "data" / "raw" / "ojs-request-log"
MODELS_DIR     = REPO_ROOT / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

# ── MLflow ────────────────────────────────────────────────────────────────────
# Ambil dari env (di-set docker-compose sebagai MLFLOW_TRACKING_URI=http://mlflow:5000)
# Fallback ke localhost kalau dijalankan di luar container
MLFLOW_TRACKING_URI = os.getenv("MLFLOW_TRACKING_URI", "http://localhost:5000")
EXPERIMENT_NAME     = "log-attack-detection"

# ── Features — harus sinkron dengan preprocess.py ENGINEERED_FEATURES ────────
# SelectKBest di preprocess.py memilih top-20; daftarkan semua kandidat
# supaya load_dataset() fleksibel jika kolom berbeda antar versi dataset.
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

# ── Performance gate (LK-08) ──────────────────────────────────────────────────
PERFORMANCE_THRESHOLD = {
    "accuracy":  0.85,
    "f1_score":  0.82,
    "precision": 0.80,
    "recall":    0.80,
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _run(cmd: list, cwd=REPO_ROOT, check=True, silent=False):
    """Jalankan subprocess dengan logging ringkas."""
    logger.info(f"$ {' '.join(str(c) for c in cmd)}")
    result = subprocess.run(
        cmd, cwd=cwd, check=check,
        capture_output=silent, text=True,
    )
    return result


def _dvc_add_and_commit(paths: list[str], message: str):
    """DVC add + git commit untuk daftar path."""
    try:
        _run(["dvc", "add"] + paths, silent=True)
        dvc_files = [p + ".dvc" for p in paths] + [".gitignore"]
        _run(["git", "add"] + dvc_files, silent=True)
        _run(["git", "commit", "-m", message], check=False, silent=True)
        logger.info(f"DVC tracked & committed: {paths}")
    except Exception as e:
        logger.warning(f"DVC/git step non-fatal error: {e}")


# ── Step 0: Ingest (opsional, dipanggil via --ingest) ────────────────────────

def run_ingest(target_date: str = None, days_back: int = 1, push: bool = False):
    """
    Panggil ingest_data.py untuk mengambil data terbaru dari PostgreSQL.
    target_date : string 'YYYY-MM-DD', default = hari ini
    push        : True → dvc add/push + git push setelah ingest
    """
    logger.info("=== [Step 0] Data Ingestion ===")
    cmd = [
        sys.executable,
        str(REPO_ROOT / "src" / "data" / "ingest_data.py"),
        "--days-back", str(days_back),
        "--table", "predictions",
    ]
    if target_date:
        cmd += ["--date", target_date]
    if push:
        cmd.append("--push")
    _run(cmd)
    logger.info("Ingest selesai.")


# ── Step 1: Preprocess (opsional, dipanggil via --preprocess) ────────────────

def run_preprocess(target_date: str = None, append: bool = True, n_features: int = 20):
    """
    Panggil preprocess.py untuk cleaning + feature engineering + scale/select.
    append  : True → append ke dataset processed (Continual Learning)
    """
    logger.info("=== [Step 1] Preprocessing ===")
    cmd = [
        sys.executable,
        str(REPO_ROOT / "src" / "data" / "preprocess.py"),
        "--n-features", str(n_features),
    ]
    if target_date:
        cmd += ["--date", target_date]
    if append:
        cmd.append("--append")
    _run(cmd)
    logger.info("Preprocessing selesai.")


# ── Step 2: Load dataset ──────────────────────────────────────────────────────

def load_dataset() -> tuple[pd.DataFrame, pd.Series]:
    """
    Load features_engineered_dataset.csv hasil preprocess.py.
    Kolom target: 'label' (sudah di-encode 0/1 oleh preprocess).
    """
    dataset_path = PROCESSED_DIR / "features_engineered_dataset.csv"
    if not dataset_path.exists():
        raise FileNotFoundError(
            f"Dataset tidak ditemukan: {dataset_path}\n"
            "Jalankan dulu: python src/data/ingest_data.py && python src/data/preprocess.py\n"
            "Atau gunakan flag --ingest --preprocess pada train.py."
        )

    df = pd.read_csv(dataset_path)
    logger.info(f"Dataset dimuat: {df.shape}")

    # Ambil kolom fitur yang tersedia (subset dari FEATURE_COLS)
    available = [c for c in FEATURE_COLS if c in df.columns]

    # Fallback: kalau semua fitur ada tapi kolom label tidak, coba label_encoded
    if "label" in df.columns:
        y = df["label"]
    elif "label_encoded" in df.columns:
        y = df["label_encoded"]
    else:
        raise ValueError("Kolom 'label' atau 'label_encoded' tidak ditemukan di dataset.")

    X = df[available].fillna(0)
    logger.info(
        f"Fitur: {len(available)}, Sampel: {len(X)}, "
        f"Attack ratio: {y.mean():.2%}"
    )
    return X, y


# ── Step 3: Evaluasi ──────────────────────────────────────────────────────────

def evaluate_model(model, X_test, y_test) -> dict:
    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else y_pred

    metrics = {
        "accuracy":       round(accuracy_score(y_test, y_pred), 4),
        "precision":      round(precision_score(y_test, y_pred, zero_division=0), 4),
        "recall":         round(recall_score(y_test, y_pred, zero_division=0), 4),
        "f1_score":       round(f1_score(y_test, y_pred, zero_division=0), 4),
        "roc_auc":        round(roc_auc_score(y_test, y_proba), 4),
        "test_samples":   len(y_test),
        "attack_samples": int(y_test.sum()),
    }

    cm = confusion_matrix(y_test, y_pred)
    metrics["true_negatives"]  = int(cm[0][0])
    metrics["false_positives"] = int(cm[0][1])
    metrics["false_negatives"] = int(cm[1][0])
    metrics["true_positives"]  = int(cm[1][1])

    logger.info(f"\n{classification_report(y_test, y_pred, target_names=['Normal', 'Attack'])}")
    return metrics


def check_performance_gate(metrics: dict) -> bool:
    passed = True
    logger.info("--- Performance Gate ---")
    for metric, threshold in PERFORMANCE_THRESHOLD.items():
        value  = metrics.get(metric, 0)
        status = "PASS" if value >= threshold else "FAIL"
        logger.info(f"  [{status}] {metric}: {value:.4f} (min: {threshold})")
        if value < threshold:
            passed = False
    return passed


# ── Step 4: Train + MLflow logging ───────────────────────────────────────────

def train_and_log(
    params: dict,
    run_name: str = None,
    register: bool = False,
    dataset_version: str = "v0.1.1",
) -> dict:
    """
    Latih XGBoost, log semua artefak ke MLflow (http://mlflow:5000),
    simpan model .pkl ke models/ lalu DVC-track.
    """
    mlflow.set_tracking_uri(MLFLOW_TRACKING_URI)
    mlflow.set_experiment(EXPERIMENT_NAME)

    X, y = load_dataset()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y,
    )

    rname = run_name or f"xgb_{datetime.now().strftime('%H%M%S')}"

    with mlflow.start_run(run_name=rname) as run:
        run_id = run.info.run_id
        logger.info(f"MLflow Run ID : {run_id}  |  Experiment: {EXPERIMENT_NAME}")
        logger.info(f"Tracking URI  : {MLFLOW_TRACKING_URI}")

        # ── Log params ────────────────────────────────────────────────────────
        mlflow.log_param("model_type",       "XGBoostClassifier")
        mlflow.log_param("dataset_version",  dataset_version)
        mlflow.log_param("n_features",       X.shape[1])
        mlflow.log_param("train_samples",    len(X_train))
        mlflow.log_param("test_samples",     len(X_test))
        mlflow.log_param("feature_cols",     ",".join(X.columns.tolist()))
        for k, v in params.items():
            mlflow.log_param(k, v)

        # ── Train ─────────────────────────────────────────────────────────────
        logger.info(f"Training: {params}")
        model = XGBClassifier(
            **params,
            random_state=42,
            eval_metric="logloss",
            use_label_encoder=False,
        )
        model.fit(
            X_train, y_train,
            eval_set=[(X_test, y_test)],
            verbose=False,
        )

        # ── Evaluate ──────────────────────────────────────────────────────────
        metrics = evaluate_model(model, X_test, y_test)

        # Cross-validation F1
        cv       = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_scores = cross_val_score(model, X, y, cv=cv, scoring="f1")
        metrics["cv_f1_mean"] = round(float(cv_scores.mean()), 4)
        metrics["cv_f1_std"]  = round(float(cv_scores.std()),  4)

        for k, v in metrics.items():
            mlflow.log_metric(k, v)

        # ── Log model ke MLflow ───────────────────────────────────────────────
        mlflow.xgboost.log_model(
            model,
            artifact_path="model",
            registered_model_name="log-attack-detector" if register else None,
            input_example=X_test.head(1),
        )

        # ── Feature importance ────────────────────────────────────────────────
        importance_df = pd.DataFrame({
            "feature":    X.columns.tolist(),
            "importance": model.feature_importances_,
        }).sort_values("importance", ascending=False)
        imp_path = "/tmp/feature_importance.csv"
        importance_df.to_csv(imp_path, index=False)
        mlflow.log_artifact(imp_path, artifact_path="reports")

        # ── Simpan model lokal → models/<run_id[:8]>.pkl ──────────────────────
        local_model_path = MODELS_DIR / f"model_{run_id[:8]}.pkl"
        joblib.dump(model, local_model_path)
        mlflow.log_artifact(str(local_model_path), artifact_path="pkl")
        logger.info(f"Model saved locally: {local_model_path}")

        # ── DVC track models/ ─────────────────────────────────────────────────
        _dvc_add_and_commit(
            ["models"],
            f"model: train run {rname} ({run_id[:8]})",
        )

        # ── Performance gate ──────────────────────────────────────────────────
        gate_passed = check_performance_gate(metrics)
        mlflow.log_param("gate_passed", gate_passed)
        mlflow.set_tag("gate_status",   "PASSED" if gate_passed else "FAILED")
        mlflow.set_tag("mlflow.note.content",
                       f"Trained {datetime.now().isoformat()} | gate={'PASSED' if gate_passed else 'FAILED'}")

        logger.info(
            f"Metrics → accuracy={metrics['accuracy']} "
            f"f1={metrics['f1_score']} auc={metrics['roc_auc']} "
            f"cv_f1={metrics['cv_f1_mean']}±{metrics['cv_f1_std']}"
        )

        return {
            "run_id":      run_id,
            "run_name":    rname,
            "metrics":     metrics,
            "gate_passed": gate_passed,
            "params":      params,
        }


# ── Hyperparameter configs ────────────────────────────────────────────────────

HYPERPARAMETER_CONFIGS = [
    {
        "name": "baseline",
        "params": {
            "n_estimators": 100, "max_depth": 6,
            "learning_rate": 0.1, "subsample": 0.8, "colsample_bytree": 0.8,
        },
    },
    {
        "name": "deep_trees",
        "params": {
            "n_estimators": 200, "max_depth": 8,
            "learning_rate": 0.05, "subsample": 0.9, "colsample_bytree": 0.7,
        },
    },
    {
        "name": "fast_shallow",
        "params": {
            "n_estimators": 150, "max_depth": 4,
            "learning_rate": 0.2, "subsample": 0.7, "colsample_bytree": 0.9,
        },
    },
    {
        "name": "regularized",
        "params": {
            "n_estimators": 200, "max_depth": 6,
            "learning_rate": 0.08, "subsample": 0.85, "colsample_bytree": 0.75,
            "reg_alpha": 0.1, "reg_lambda": 1.5,
        },
    },
]


# ── Main ──────────────────────────────────────────────────────────────────────

def main(args):
    logger.info("=== MLflow Training Pipeline ===")
    logger.info(f"MLflow tracking URI : {MLFLOW_TRACKING_URI}")

    # ── Opsional: jalankan ingest + preprocess sebelum training ───────────────
    if args.ingest:
        run_ingest(
            target_date=args.date,
            days_back=args.days_back,
            push=args.dvc_push,
        )

    if args.preprocess:
        run_preprocess(
            target_date=args.date,
            append=args.append,
            n_features=args.n_features,
        )

        # DVC track data setelah preprocess
        if args.dvc_push:
            _dvc_add_and_commit(
                ["data/raw/ojs-request-log", "data/processed"],
                f"data: preprocess {args.date or 'latest'}",
            )
            try:
                _run(["dvc", "push"])
            except Exception as e:
                logger.warning(f"dvc push gagal (remote mungkin belum dikonfigurasi): {e}")

    # ── Training ──────────────────────────────────────────────────────────────
    if args.run_all:
        results = []
        for cfg in HYPERPARAMETER_CONFIGS:
            logger.info(f"\n--- Run: {cfg['name']} ---")
            result = train_and_log(
                params=cfg["params"],
                run_name=cfg["name"],
                register=False,
            )
            results.append(result)

        # Pilih run terbaik berdasarkan F1
        best = max(results, key=lambda r: r["metrics"]["f1_score"])
        logger.info(
            f"\nBest run : {best['run_name']} ({best['run_id'][:8]}) "
            f"| F1={best['metrics']['f1_score']}"
        )

        # Register best model ke MLflow Model Registry
        if best["gate_passed"] and args.register:
            mlflow.set_tracking_uri(MLFLOW_TRACKING_URI)
            client = mlflow.tracking.MlflowClient()
            model_uri = f"runs:/{best['run_id']}/model"
            mv = mlflow.register_model(model_uri, "log-attack-detector")
            logger.info(f"Model registered: version={mv.version}")

            client.transition_model_version_stage(
                name="log-attack-detector",
                version=mv.version,
                stage="Staging",
            )
            logger.info("Model transitioned → Staging")

            # Simpan symlink/alias model production
            prod_path = MODELS_DIR / "attack-detection-v0.1.1.pkl"
            best_pkl  = MODELS_DIR / f"model_{best['run_id'][:8]}.pkl"
            if best_pkl.exists():
                prod_path.unlink(missing_ok=True)
                prod_path.symlink_to(best_pkl.name)
                logger.info(f"Production symlink: {prod_path} → {best_pkl.name}")

        # Simpan ringkasan semua run
        summary_path = REPO_ROOT / "mlflow_results_summary.json"
        with open(summary_path, "w") as f:
            json.dump(
                [
                    {
                        "run_id":      r["run_id"],
                        "run_name":    r["run_name"],
                        "metrics":     r["metrics"],
                        "gate_passed": r["gate_passed"],
                    }
                    for r in results
                ],
                f, indent=2,
            )
        logger.info(f"Summary saved → {summary_path}")

    else:
        # Single run
        params = {
            "n_estimators":    args.n_estimators,
            "max_depth":       args.max_depth,
            "learning_rate":   args.learning_rate,
            "subsample":       args.subsample,
            "colsample_bytree":args.colsample_bytree,
        }
        result = train_and_log(
            params=params,
            run_name=args.run_name,
            register=args.register,
        )

        if result["gate_passed"]:
            logger.info("Model PASSED performance gate.")
        else:
            logger.warning("Model FAILED performance gate.")
            if args.strict:
                raise SystemExit(1)

    logger.info("=== Training Pipeline Complete ===")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MLOps - Model Training")

    # ── Pipeline flags ────────────────────────────────────────────────────────
    parser.add_argument("--ingest",      action="store_true",
                        help="Jalankan ingest_data.py sebelum training")
    parser.add_argument("--preprocess",  action="store_true",
                        help="Jalankan preprocess.py sebelum training")
    parser.add_argument("--date",        type=str, default=None,
                        help="Tanggal target ingest/preprocess (YYYY-MM-DD). Default: hari ini")
    parser.add_argument("--days-back",   type=int, default=1,
                        help="Rentang hari ingest (default: 1)")
    parser.add_argument("--append",      action="store_true", default=True,
                        help="Append ke dataset processed (Continual Learning, default: True)")
    parser.add_argument("--n-features",  type=int, default=20,
                        help="Jumlah top features SelectKBest (default: 20)")
    parser.add_argument("--dvc-push",    action="store_true",
                        help="DVC add + push setelah ingest/preprocess")

    # ── Training flags ────────────────────────────────────────────────────────
    parser.add_argument("--run-all",          action="store_true",
                        help="Jalankan semua konfigurasi hyperparameter")
    parser.add_argument("--register",         action="store_true",
                        help="Register model terbaik ke MLflow Model Registry")
    parser.add_argument("--strict",           action="store_true",
                        help="Exit code 1 jika tidak lulus gate")
    parser.add_argument("--run-name",         type=str, default=None)
    parser.add_argument("--n-estimators",     type=int,   default=100)
    parser.add_argument("--max-depth",        type=int,   default=6)
    parser.add_argument("--learning-rate",    type=float, default=0.1)
    parser.add_argument("--subsample",        type=float, default=0.8)
    parser.add_argument("--colsample-bytree", type=float, default=0.8)

    args = parser.parse_args()
    main(args)