"""
LK-04: Preprocessing Script
Sesuai notebook: 01_preprocessing_eda + 02_feature_engineering
Kolom sumber: id, timestamp, created_at, ip, method, path, query,
              body, headers, status_code, response_size,
              response_time_ms, label
"""

import re
import json
import logging
import argparse
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest, f_classif

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

SCRIPT_DIR    = Path(__file__).resolve().parent
GIT_REPO_PATH = SCRIPT_DIR.parent
RAW_DATA_DIR  = GIT_REPO_PATH / "data" / "raw" / "ojs-request-log"
PROCESSED_DIR = GIT_REPO_PATH / "data" / "processed" / "v0.1.1"
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

# Pola serangan (dipakai di path + query + body)
SUSPICIOUS_KEYWORDS = ["eval", "exec", "system", "shell", "cmd", "bash", "php", "sql"]
SQL_PATTERNS        = ["union", "select", "drop", "insert", "update", "delete", "or", "--"]
ATTACK_TOOLS        = ["curl", "wget", "python", "sqlmap", "nikto", "nmap"]


# ── 1. Helpers ────────────────────────────────────────────────────────────────

def parse_headers(header_str) -> dict:
    if pd.isna(header_str) or header_str in ("{}", "", None):
        return {}
    try:
        return json.loads(str(header_str))
    except Exception:
        return {}


def sql_score(text: str) -> int:
    """Hitung berapa SQL keyword yang muncul."""
    t = str(text).lower()
    return sum(1 for p in SQL_PATTERNS if p in t)


# ── 2. Clean ──────────────────────────────────────────────────────────────────

def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    logger.info(f"Cleaning data. Initial shape: {df.shape}")
    n0 = len(df)

    df = df.drop_duplicates()

    # Kolom wajib ada
    critical = [c for c in ["path", "method"] if c in df.columns]
    df = df.dropna(subset=critical)

    # Fill nullable kolom
    for col in ["query", "body"]:
        if col in df.columns:
            df[col] = df[col].fillna("")
    if "headers" in df.columns:
        df["headers"] = df["headers"].fillna("{}")

    # Parse timestamp
    for ts_col in ["timestamp", "created_at"]:
        if ts_col in df.columns:
            df[ts_col] = pd.to_datetime(df[ts_col], errors="coerce")

    df = df.dropna(subset=["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)

    logger.info(f"Cleaned: {n0} → {len(df)} rows ({n0 - len(df)} removed)")
    return df


# ── 3. Feature Engineering (sesuai notebook 01 + 02) ─────────────────────────

def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    logger.info("Extracting features...")
    df = df.copy()

    path  = df["path"].fillna("")
    query = df["query"].fillna("") if "query" in df.columns else pd.Series([""] * len(df))
    body  = df["body"].fillna("").astype(str) if "body" in df.columns else pd.Series([""] * len(df))

    # ── Path features (notebook 01 § 7, notebook 02 § 2) ─────────────────────
    df["path_length"]         = path.str.len()
    df["path_depth"]          = path.apply(lambda x: x.count("/")).clip(0, 20)
    df["path_special_chars"]  = path.apply(lambda x: len(re.findall(r"[^\w/.\-]", x)))
    df["path_encoded_chars"]  = path.apply(lambda x: x.count("%"))
    df["has_url_encoding"]    = path.apply(lambda x: int("%" in x))
    df["has_double_encoding"] = path.apply(lambda x: int("%25" in x))
    df["has_directory_traversal"] = path.apply(lambda x: int("../" in x or "..\\" in x))
    df["suspicious_path"]     = path.apply(
        lambda x: sum(1 for p in SUSPICIOUS_KEYWORDS if p in x.lower())
    )

    # ── Query features (notebook 02 § 2) ─────────────────────────────────────
    df["query_length"]        = query.str.len()
    df["query_param_count"]   = query.apply(
        lambda x: x.count("&") + (1 if x.strip() not in ("", "None") else 0)
    )
    df["query_special_chars"] = query.apply(
        lambda x: len(re.findall(r"[^\w&=.]", str(x)))
    )

    # ── SQL injection score (path + query, notebook 02 § 7) ──────────────────
    df["sql_injection_score"] = (
        path.apply(sql_score) + query.apply(sql_score)
    )

    # ── Body features (notebook 02 § 4) ──────────────────────────────────────
    df["body_length"]           = body.str.len()
    df["body_contains_code"]    = body.apply(
        lambda x: int(any(kw in x.lower() for kw in ["<?php", "shell_exec", "base64"]))
    )
    df["body_special_chars_ratio"] = body.apply(
        lambda x: len(re.findall(r"[^\w\s]", x)) / max(len(x), 1)
    )

    # ── Header features (notebook 02 § 3) ────────────────────────────────────
    headers_parsed = df["headers"].apply(parse_headers) if "headers" in df.columns \
        else pd.Series([{}] * len(df))

    df["header_count"]       = headers_parsed.apply(len)
    df["user_agent_length"]  = headers_parsed.apply(
        lambda h: len(h.get("User-Agent", ""))
    )
    df["suspicious_headers"] = headers_parsed.apply(
        lambda h: int(any(
            tool in h.get("User-Agent", "").lower()
            for tool in ATTACK_TOOLS
        ))
    )

    # ── HTTP Method (notebook 01 § 6) ─────────────────────────────────────────
    df["method_encoded"] = pd.Categorical(
        df["method"].fillna("GET"),
        categories=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
    ).codes

    # ── Status code (notebook 01) ─────────────────────────────────────────────
    df["status_code"] = pd.to_numeric(
        df.get("status_code", 200), errors="coerce"
    ).fillna(200).astype(int)
    df["status_4xx"]  = ((df["status_code"] >= 400) & (df["status_code"] < 500)).astype(int)
    df["status_5xx"]  = (df["status_code"] >= 500).astype(int)

    # ── Response (notebook 01) ────────────────────────────────────────────────
    df["response_size"]    = pd.to_numeric(
        df.get("response_size", 0), errors="coerce"
    ).fillna(0)
    df["response_time_ms"] = pd.to_numeric(
        df.get("response_time_ms", 0), errors="coerce"
    ).fillna(0)
    df["log_response_size"] = np.log1p(df["response_size"])

    # ── IP features (notebook 02 § 5) ─────────────────────────────────────────
    if "ip" in df.columns:
        ip_total  = df.groupby("ip").size()
        ip_attack = df[df["label"].str.lower() == "attack"].groupby("ip").size() \
            if "label" in df.columns else pd.Series(dtype=int)

        ip_attack_rate = (ip_attack / ip_total).fillna(0)

        df["ip_request_count"] = df["ip"].map(ip_total).fillna(1).astype(int)
        df["ip_attack_rate"]   = df["ip"].map(ip_attack_rate).fillna(0)
        df["is_high_risk_ip"]  = (df["ip_attack_rate"] > 0.5).astype(int)
    else:
        df["ip_request_count"] = 1
        df["ip_attack_rate"]   = 0.0
        df["is_high_risk_ip"]  = 0

    # ── Time features (notebook 02 § 6) ───────────────────────────────────────
    df["hour"]        = df["timestamp"].dt.hour
    df["day_of_week"] = df["timestamp"].dt.dayofweek
    df["is_business_hours"] = (
        (df["hour"] >= 9) & (df["hour"] <= 17)
    ).astype(int)
    df["is_night_time"] = (
        (df["hour"] >= 22) | (df["hour"] <= 5)
    ).astype(int)

    # Frekuensi request per IP per jam
    df["_timestamp_hour"] = df["timestamp"].dt.floor("h")
    ip_hour_freq = df.groupby(["ip", "_timestamp_hour"]).size() \
        if "ip" in df.columns else None

    if ip_hour_freq is not None:
        def get_freq(row):
            try:
                return ip_hour_freq.loc[(row["ip"], row["_timestamp_hour"])]
            except (KeyError, TypeError):
                return 1
        df["request_freq_per_hour"] = df.apply(get_freq, axis=1)
    else:
        df["request_freq_per_hour"] = 1

    df = df.drop(columns=["_timestamp_hour"], errors="ignore")

    # ── Label ─────────────────────────────────────────────────────────────────
    if "label" in df.columns:
        df["label_encoded"] = (df["label"].str.lower() == "attack").astype(int)

    logger.info(f"Feature extraction complete. Shape: {df.shape}")
    return df


# ── 4. Feature list (sesuai notebook 02 § 8) ─────────────────────────────────

ENGINEERED_FEATURES = [
    # Path
    "path_depth", "path_special_chars", "path_encoded_chars",
    "query_param_count", "query_special_chars", "suspicious_path",
    # Header
    "header_count", "suspicious_headers", "user_agent_length",
    # Body
    "body_contains_code", "body_special_chars_ratio",
    # IP
    "ip_attack_rate", "ip_request_count", "is_high_risk_ip",
    # Time
    "hour", "day_of_week", "is_business_hours", "is_night_time",
    "request_freq_per_hour",
    # Encoding / Pattern
    "has_url_encoding", "has_double_encoding",
    "has_directory_traversal", "sql_injection_score",
]


# ── 5. Scale + Select (notebook 02 § 9) ──────────────────────────────────────

def scale_and_select(
    df: pd.DataFrame,
    n_features: int = 20,
    existing_scaler=None,
    existing_selector=None,
):
    """
    Standarisasi + SelectKBest.
    Kalau ada existing scaler/selector (mode append), pakai yang lama
    supaya fitur konsisten antar batch.
    """
    avail = [c for c in ENGINEERED_FEATURES if c in df.columns]
    X = df[avail].copy().fillna(0)

    if "label_encoded" not in df.columns:
        logger.warning("label_encoded not found — skip feature selection, use all features")
        return df[avail + ["label_encoded"]].copy() if "label_encoded" in df.columns else df[avail].copy(), None, None

    y = df["label_encoded"]

    if existing_scaler is None:
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
    else:
        scaler = existing_scaler
        X_scaled = scaler.transform(X)

    X_scaled_df = pd.DataFrame(X_scaled, columns=avail)

    k = min(n_features, len(avail))
    if existing_selector is None:
        selector = SelectKBest(f_classif, k=k)
        selector.fit(X_scaled, y)
    else:
        selector = existing_selector

    selected = [avail[i] for i in selector.get_support(indices=True)]
    logger.info(f"Selected {len(selected)} features: {selected}")

    final = X_scaled_df[selected].copy()
    final["label"] = y.values
    return final, scaler, selector


# ── 6. Save ───────────────────────────────────────────────────────────────────

def save_processed(
    df_clean: pd.DataFrame,
    df_features: pd.DataFrame,
    append: bool,
):
    eda_path      = PROCESSED_DIR / "eda_cleaned_data.csv"
    features_path = PROCESSED_DIR / "features_engineered_dataset.csv"

    # EDA cleaned
    if append and eda_path.exists():
        existing = pd.read_csv(eda_path)
        # Parse timestamp agar drop_duplicates bisa kerja dengan benar
        if "timestamp" in existing.columns:
            existing["timestamp"] = pd.to_datetime(existing["timestamp"], errors="coerce")
        merged = pd.concat([existing, df_clean], ignore_index=True).drop_duplicates()
        merged.to_csv(eda_path, index=False)
        logger.info(f"[EDA] Appended → {eda_path} {merged.shape}")
    else:
        df_clean.to_csv(eda_path, index=False)
        logger.info(f"[EDA] Saved → {eda_path} {df_clean.shape}")

    # Features engineered
    if append and features_path.exists():
        existing_f = pd.read_csv(features_path)
        merged_f   = pd.concat([existing_f, df_features], ignore_index=True).drop_duplicates()
        merged_f.to_csv(features_path, index=False)
        logger.info(f"[Features] Appended → {features_path} {merged_f.shape}")
    else:
        df_features.to_csv(features_path, index=False)
        logger.info(f"[Features] Saved → {features_path} {df_features.shape}")


# ── 7. File discovery ─────────────────────────────────────────────────────────

def get_all_raw_files():
    files = sorted(RAW_DATA_DIR.rglob("*.csv"))
    if not files:
        logger.warning("No raw CSV files found in data/raw/ojs-request-log/")
    return files


def get_latest_raw_file():
    files = get_all_raw_files()
    return files[-1] if files else None


def get_raw_file_for_date(target_date):
    expected = (
        RAW_DATA_DIR
        / str(target_date.year)
        / f"{target_date.month:02d}"
        / f"predictions_{target_date}.csv"
    )
    if expected.exists():
        return expected
    logger.warning(f"File not found for date {target_date}: {expected}")
    return None


# ── 8. Pipeline ───────────────────────────────────────────────────────────────

def run_pipeline(raw_df: pd.DataFrame, append: bool, n_features: int = 20):
    df_clean    = clean_data(raw_df)
    df_feat     = extract_features(df_clean)
    df_final, scaler, selector = scale_and_select(df_feat, n_features=n_features)
    save_processed(df_clean, df_final, append=append)

    # Ringkasan
    if "label" in df_clean.columns:
        logger.info(f"Label distribution:\n{df_clean['label'].value_counts().to_string()}")
    logger.info(f"Attack rate: {df_final['label'].mean()*100:.2f}%" if "label" in df_final.columns else "")
    return df_clean, df_final


# ── 9. Main ───────────────────────────────────────────────────────────────────

def main(args):
    logger.info("=== Starting Preprocessing ===")

    if args.all:
        files = get_all_raw_files()
        if not files:
            logger.error("No raw files found.")
            return
        logger.info(f"Processing {len(files)} files (--all mode)...")
        dfs = []
        for f in files:
            logger.info(f"  Reading {f}")
            dfs.append(pd.read_csv(f))
        raw_df = pd.concat(dfs, ignore_index=True)
        run_pipeline(raw_df, append=False, n_features=args.n_features)

    else:
        if args.input_file:
            input_path = Path(args.input_file)
        elif args.date:
            target_date = datetime.strptime(args.date, "%Y-%m-%d").date()
            input_path  = get_raw_file_for_date(target_date)
        else:
            input_path = get_latest_raw_file()

        if input_path is None or not input_path.exists():
            logger.error(f"Input file not found: {input_path}")
            return

        logger.info(f"Processing: {input_path}")
        raw_df = pd.read_csv(input_path)
        run_pipeline(raw_df, append=args.append, n_features=args.n_features)

    logger.info("=== Preprocessing Complete ===")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="MLOps Log Attack Detection - Preprocessing"
    )
    parser.add_argument("--input-file", type=str, default=None,
                        help="Path file CSV mentah (override otomatis).")
    parser.add_argument("--date", type=str, default=None,
                        help="Proses file untuk tanggal tertentu (YYYY-MM-DD).")
    parser.add_argument("--all", action="store_true",
                        help="Proses semua file raw sekaligus (rebuild dari nol).")
    parser.add_argument("--append", action="store_true",
                        help="Append ke dataset processed yang ada (Continual Learning).")
    parser.add_argument("--n-features", type=int, default=20,
                        help="Jumlah top features yang dipilih SelectKBest. Default: 20.")
    args = parser.parse_args()
    main(args)