import os
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
from sqlalchemy import create_engine


# =========================
# CONFIGURATION
# =========================
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "your_database")
DB_USER = os.getenv("DB_USER", "your_user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "your_password")

# Local folder where exported CSV will be stored
EXPORT_BASE_PATH = Path("/opt/predictions_backup/daily_exports")

# Git repository path (must already be initialized)
GIT_REPO_PATH = Path("/opt/predictions_backup")
GIT_BRANCH = "main"

# Hugging Face dataset repo URL
# Example:
# https://huggingface.co/datasets/username/dataset-name
HF_REPO_URL = os.getenv(
    "HF_REPO_URL",
    "https://huggingface.co/datasets/username/dataset-name"
)

HF_BRANCH = "main"

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

    print(f"Running query for date: {target_date}")

    engine = get_engine()
    df = pd.read_sql(query, engine)

    df.to_csv(output_file, index=False)
    print(f"Exported {len(df)} rows to: {output_file}")

    return output_file

def git_push(file_path: Path):
    print("Pushing to GitHub...")

    subprocess.run(["git", "-C", str(GIT_REPO_PATH), "add", str(file_path)], check=True)
    subprocess.run(
        [
            "git", "-C", str(GIT_REPO_PATH),
            "commit", "-m", f"Auto backup predictions for {datetime.now().date()}"
        ],
        check=False,
    )
    subprocess.run(
        ["git", "-C", str(GIT_REPO_PATH), "push", "origin", GIT_BRANCH],
        check=True,
    )

    print("GitHub push completed.")


def hf_push():
    print("Pushing to Hugging Face...")

    # Assumes same folder is also a HF git repo remote
    # Example:
    # git remote add hf https://huggingface.co/datasets/username/dataset-name

    subprocess.run(
        ["git", "-C", str(GIT_REPO_PATH), "push", "hf", HF_BRANCH],
        check=True,
    )

    print("Hugging Face push completed.")

if __name__ == "__main__":
    try:
        exported_file = export_predictions()
        git_push(exported_file)
        hf_push()
        print("Daily export job completed successfully.")
    except Exception as e:
        print(f"Job failed: {e}")
        raise