"""
LK-04: Data Ingestion Script
Mengambil data log dari PostgreSQL (tabel: predictions)
dan menyimpannya sebagai CSV dengan struktur folder per tanggal.
Mendukung Continual Learning pipeline.
"""

import os
import logging
import argparse
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
from sqlalchemy import create_engine, text

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
DB_HOST     = os.getenv("DB_HOST",     "localhost")
DB_PORT     = os.getenv("DB_PORT",     "9929")
DB_NAME     = os.getenv("DB_NAME",     "attack_detection")
DB_USER     = os.getenv("DB_USER",     "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "g1ojsjaya")

SCRIPT_DIR      = Path(__file__).resolve().parent
GIT_REPO_PATH   = SCRIPT_DIR.parent
RAW_DATA_DIR    = GIT_REPO_PATH / "data" / "raw" / "ojs-request-log"

GIT_BRANCH      = "main"
HF_REMOTE_NAME  = "hf"


# ── DB Engine ─────────────────────────────────────────────────────────────────
def get_engine():
    db_url = (
        f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}"
        f"@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )
    return create_engine(db_url)


# ── Ingest ────────────────────────────────────────────────────────────────────
def ingest_from_postgres(
    target_date,
    table: str = "predictions",
    days_back: int = 1,
) -> pd.DataFrame:
    """
    Ambil data dari PostgreSQL.
    - target_date  : tanggal akhir data yang diambil (datetime.date)
    - days_back    : rentang hari ke belakang dari target_date
    """
    date_from = target_date - timedelta(days=days_back - 1)
    date_to   = target_date

    query = text(f"""
        SELECT *
        FROM {table}
        WHERE label IS NOT NULL
          AND DATE(timestamp) BETWEEN :date_from AND :date_to
        ORDER BY timestamp ASC;
    """)

    logger.info(
        f"Fetching from '{table}' "
        f"[{date_from} → {date_to}] ..."
    )

    with get_engine().connect() as conn:
        df = pd.read_sql(query, conn, params={"date_from": date_from, "date_to": date_to})

    logger.info(f"Fetched {len(df)} rows from Postgres.")
    return df


# ── Save ──────────────────────────────────────────────────────────────────────
def save_partitioned(df: pd.DataFrame, target_date) -> Path:
    """
    Simpan DataFrame ke CSV dengan struktur folder:
        data/raw/ojs-request-log/<year>/<month>/predictions_<date>.csv
    """
    folder = RAW_DATA_DIR / str(target_date.year) / f"{target_date.month:02d}"
    folder.mkdir(parents=True, exist_ok=True)

    out_path = folder / f"predictions_{target_date}.csv"
    df.to_csv(out_path, index=False)
    logger.info(f"Saved {len(df)} rows → {out_path}")
    return out_path


# ── DVC ───────────────────────────────────────────────────────────────────────
def dvc_track(file_path: Path):
    logger.info("Tracking file with DVC...")
    subprocess.run(
        ["dvc", "add", str(file_path)],
        cwd=GIT_REPO_PATH,
        check=True,
    )
    logger.info("DVC tracking completed.")


def dvc_push():
    logger.info("Pushing data to DVC remote...")
    subprocess.run(["dvc", "push"], cwd=GIT_REPO_PATH, check=True)
    logger.info("DVC push completed.")


# ── Git ───────────────────────────────────────────────────────────────────────
def git_push(target_date):
    logger.info("Pushing metadata to GitHub...")
    subprocess.run(["git", "add", "."], cwd=GIT_REPO_PATH, check=True)
    subprocess.run(
        ["git", "commit", "-m", f"data: ingest predictions {target_date}"],
        cwd=GIT_REPO_PATH,
        check=False,   # False → tidak gagal kalau nothing to commit
    )
    subprocess.run(
        ["git", "push", "origin", GIT_BRANCH],
        cwd=GIT_REPO_PATH,
        check=True,
    )
    logger.info("GitHub push completed.")


# ── HuggingFace ───────────────────────────────────────────────────────────────
def hf_push():
    logger.info("Pushing data/ to Hugging Face...")
    subprocess.run(
        [
            "huggingface-cli", "upload",
            "AkbarFikri/ojs-request-log",
            "./data", "data",
            "--repo-type=dataset",
        ],
        cwd=GIT_REPO_PATH,
        check=True,
    )
    logger.info("Hugging Face push completed.")


# ── Main ──────────────────────────────────────────────────────────────────────
def main(args):
    logger.info("=== Starting Data Ingestion ===")

    target_date = (
        datetime.strptime(args.date, "%Y-%m-%d").date()
        if args.date
        else datetime.now().date()
    )
    logger.info(f"Target date  : {target_date}")
    logger.info(f"Days back    : {args.days_back}")
    logger.info(f"Table        : {args.table}")

    # 1. Fetch from Postgres
    df = ingest_from_postgres(
        target_date=target_date,
        table=args.table,
        days_back=args.days_back,
    )

    if df.empty:
        logger.warning("No data returned from Postgres. Exiting.")
        return

    # 2. Save partitioned CSV
    saved_path = save_partitioned(df, target_date)

    # 3. Summary
    logger.info(f"Label distribution:\n{df['label'].value_counts().to_string()}")
    if "attack_type" in df.columns:
        logger.info(f"Attack type distribution:\n{df['attack_type'].value_counts().to_string()}")

    # 4. Optionally push
    if args.push:
        dvc_track(saved_path)
        dvc_push()
        git_push(target_date)

    if args.push_hf:
        hf_push()

    logger.info("=== Data Ingestion Complete ===")
    return saved_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="MLOps Log Attack Detection - Data Ingestion (Postgres)"
    )
    parser.add_argument(
        "--date",
        type=str,
        default=None,
        help="Tanggal target data (YYYY-MM-DD). Default: hari ini.",
    )
    parser.add_argument(
        "--days-back",
        type=int,
        default=1,
        help="Ambil data N hari ke belakang dari --date. Default: 1 (hari ini saja).",
    )
    parser.add_argument(
        "--table",
        type=str,
        default="predictions",
        help="Nama tabel Postgres sumber data. Default: predictions.",
    )
    parser.add_argument(
        "--push",
        action="store_true",
        help="Jalankan dvc add/push + git push setelah ingest.",
    )
    parser.add_argument(
        "--push-hf",
        action="store_true",
        help="Push data/ ke Hugging Face setelah ingest.",
    )
    args = parser.parse_args()
    main(args)