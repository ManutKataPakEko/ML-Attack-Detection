import os
import subprocess
from datetime import datetime
from pathlib import Path

import pandas as pd
from sqlalchemy import create_engine


# =========================
# CONFIGURATION
# =========================
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "9929")
DB_NAME = os.getenv("DB_NAME", "attack_detection")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "g1ojsjaya")

SCRIPT_DIR = Path(__file__).resolve().parent
GIT_REPO_PATH = SCRIPT_DIR.parent
EXPORT_BASE_PATH = GIT_REPO_PATH / "data" / "raw" / "ojs-request-log"

GIT_BRANCH = "main"
HF_REMOTE_NAME = "hf"
HF_BRANCH = "main"


# =========================
# CORE FUNCTIONS
# =========================
def get_target_date():
    return datetime.now().date()


def get_engine():
    db_url = (
        f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}"
        f"@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )
    return create_engine(db_url)


def export_predictions():
    target_date = get_target_date()

    export_folder = EXPORT_BASE_PATH / str(target_date.year) / f"{target_date.month:02d}"
    export_folder.mkdir(parents=True, exist_ok=True)

    output_file = export_folder / f"predictions_{target_date}.csv"

    query = f"""
        SELECT *
        FROM predictions
        WHERE label IS NOT NULL
          AND DATE(timestamp) = '{target_date}'
        ORDER BY timestamp ASC;
    """

    print(f"[INFO] Running query for {target_date}")

    df = pd.read_sql(query, get_engine())
    df.to_csv(output_file, index=False)

    print(f"[INFO] Exported {len(df)} rows → {output_file}")

    return output_file


# =========================
# DVC HANDLING
# =========================
def dvc_track(file_path: Path):
    print("[INFO] Tracking file with DVC...")

    subprocess.run(
        ["dvc", "add", str(file_path)],
        cwd=GIT_REPO_PATH,
        check=True
    )

    print("[INFO] DVC tracking completed.")


def dvc_push():
    print("[INFO] Pushing data to DVC remote...")

    subprocess.run(
        ["dvc", "push"],
        cwd=GIT_REPO_PATH,
        check=True
    )

    print("[INFO] DVC push completed.")


# =========================
# GIT PUSH (GitHub)
# =========================
def git_push():
    print("[INFO] Pushing metadata to GitHub...")

    subprocess.run(["git", "add", "."], cwd=GIT_REPO_PATH, check=True)

    subprocess.run(
        ["git", "commit", "-m", f"Auto update {datetime.now().date()}"],
        cwd=GIT_REPO_PATH,
        check=False,
    )

    subprocess.run(
        ["git", "push", "origin", GIT_BRANCH],
        cwd=GIT_REPO_PATH,
        check=True,
    )

    print("[INFO] GitHub push completed.")


# =========================
# HUGGING FACE PUSH (DATA ONLY)
# =========================
def hf_push_data_only():
    print("[INFO] Pushing ONLY data/ folder to Hugging Face...")

    try:
        subprocess.run(
            ["git", "push", "hf", f"main:main", "--force"],
            cwd=GIT_REPO_PATH,
            check=True,
        )
    except:
        subprocess.run(
            ["git", "push", "hf", f"main:main"],
            cwd=GIT_REPO_PATH,
            check=True,
        )


# =========================
# MAIN PIPELINE
# =========================
if __name__ == "__main__":
    try:
        exported_file = export_predictions()

        dvc_track(exported_file)
        dvc_push()

        git_push()
        hf_push_data_only()

        print("[SUCCESS] Daily pipeline completed.")

    except Exception as e:
        print(f"[ERROR] {e}")
        raise