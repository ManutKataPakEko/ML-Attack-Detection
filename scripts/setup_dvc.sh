#!/usr/bin/env bash
# =============================================================================
#  LK-05: DVC Setup & Data Versioning Script
#
#  Usage:
#    bash scripts/setup_dvc.sh                             # Setup awal saja
#    bash scripts/setup_dvc.sh --start-date=2024-01-01    # Catchup dari tgl tertentu
#    bash scripts/setup_dvc.sh --continual                 # Ingest hari ini + setup cron
#    bash scripts/setup_dvc.sh --minio=http://host:9000    # Pakai MinIO remote
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

log()  { echo -e "\033[1;36m[DVC]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[OK]\033[0m  $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*"; exit 1; }

# ─── Parse arguments ──────────────────────────────────────────────────────────
CONTINUAL=false
START_DATE=""
MINIO_ENDPOINT=""
MINIO_BUCKET="mlops-data"
PUSH_HF=false
CRON_HOUR=2      # jam WIB untuk cron harian (default 02:00)

for arg in "$@"; do
    case $arg in
        --continual)      CONTINUAL=true ;;
        --start-date=*)   START_DATE="${arg#*=}" ;;
        --minio=*)        MINIO_ENDPOINT="${arg#*=}" ;;
        --bucket=*)       MINIO_BUCKET="${arg#*=}" ;;
        --push-hf)        PUSH_HF=true ;;
        --cron-hour=*)    CRON_HOUR="${arg#*=}" ;;
    esac
done

# ─── Step 1: Install DVC ──────────────────────────────────────────────────────
log "Step 1: Checking DVC installation..."
if ! command -v dvc &> /dev/null; then
    pip install "dvc[s3]" --quiet
    ok "DVC installed: $(dvc --version)"
else
    ok "DVC already installed: $(dvc --version)"
fi

# ─── Step 2: Initialize DVC ───────────────────────────────────────────────────
log "Step 2: Initializing DVC..."
if [ ! -d ".dvc" ]; then
    dvc init
    git add .dvc .dvcignore
    git commit -m "chore: initialize DVC" || true
    ok "DVC initialized"
else
    ok "DVC already initialized"
fi

# ─── Step 3: Folder structure ────────────────────────────────────────────────
log "Step 3: Ensuring folder structure..."
mkdir -p data/raw/ojs-request-log
mkdir -p data/processed/v0.1.1
ok "Folders ready"

# ─── Step 4: MinIO remote (opsional) ─────────────────────────────────────────
if [ -n "$MINIO_ENDPOINT" ]; then
    log "Step 4: Configuring MinIO remote..."
    dvc remote add -d minio s3://"$MINIO_BUCKET"/dvc-store 2>/dev/null || \
        dvc remote modify minio url s3://"$MINIO_BUCKET"/dvc-store
    dvc remote modify minio endpointurl "$MINIO_ENDPOINT"
    dvc remote modify minio access_key_id     "${MINIO_ACCESS_KEY:-minioadmin}"
    dvc remote modify minio secret_access_key "${MINIO_SECRET_KEY:-minioadmin}"
    git add .dvc/config
    git commit -m "chore: configure MinIO DVC remote" || true
    ok "MinIO remote configured: $MINIO_ENDPOINT/$MINIO_BUCKET"
fi

# ─── Step 5: Catchup — ingest dari START_DATE sampai kemarin ─────────────────
#
#  Logika:
#   - Jika --start-date diberikan, script akan loop hari per hari
#     mulai dari START_DATE sampai YESTERDAY.
#   - Untuk setiap hari: ingest → preprocess --append → dvc add → git commit
#   - Setelah loop selesai, menunggu cron untuk hari ini dan seterusnya.
#
if [ -n "$START_DATE" ]; then
    log "Step 5: Catchup mode — start-date=$START_DATE"

    TODAY=$(date +%Y-%m-%d)
    YESTERDAY=$(date -d "yesterday" +%Y-%m-%d 2>/dev/null || date -v-1d +%Y-%m-%d)

    CURRENT="$START_DATE"
    BATCH=0

    while [[ "$CURRENT" < "$TODAY" ]]; do
        log "  Processing date: $CURRENT"

        # Ingest dari Postgres untuk tanggal ini
        python src/data/ingest_data.py \
            --date "$CURRENT" \
            --days-back 1 \
            --table predictions || {
            warn "  Ingest failed for $CURRENT — skipping"
            CURRENT=$(date -d "$CURRENT + 1 day" +%Y-%m-%d 2>/dev/null \
                      || date -j -f "%Y-%m-%d" -v+1d "$CURRENT" +%Y-%m-%d)
            continue
        }

        # Preprocess & append
        python src/data/preprocess.py \
            --date "$CURRENT" \
            --append || warn "  Preprocess warning for $CURRENT"

        # DVC track
        dvc add data/raw/ojs-request-log/ data/processed/ 2>/dev/null || true

        BATCH=$((BATCH + 1))

        # Commit tiap 7 hari agar git log tidak terlalu panjang
        if (( BATCH % 7 == 0 )); then
            git add data/raw/ojs-request-log.dvc data/processed.dvc .gitignore 2>/dev/null || true
            git commit -m "data: catchup batch up to $CURRENT" || true
            ok "  Committed batch up to $CURRENT"
        fi

        # Maju ke hari berikutnya
        CURRENT=$(date -d "$CURRENT + 1 day" +%Y-%m-%d 2>/dev/null \
                  || date -j -f "%Y-%m-%d" -v+1d "$CURRENT" +%Y-%m-%d)
    done

    # Commit sisa batch yang belum di-commit
    git add data/raw/ojs-request-log.dvc data/processed.dvc .gitignore 2>/dev/null || true
    git commit -m "data: catchup complete up to $YESTERDAY" || true

    ok "Catchup complete. Total $BATCH day(s) processed."
    log "  Sekarang menunggu cron untuk hari ini ($TODAY) dan seterusnya."
fi

# ─── Step 6: Ingest hari ini (--continual atau fresh start tanpa start-date) ──
if [ "$CONTINUAL" = "true" ] && [ -z "$START_DATE" ]; then
    log "Step 6: Continual — ingesting today's data..."

    TODAY=$(date +%Y-%m-%d)

    OLD_HASH=""
    DVC_FILE="data/raw/ojs-request-log.dvc"
    [ -f "$DVC_FILE" ] && OLD_HASH=$(grep "md5:" "$DVC_FILE" | awk '{print $2}')

    python src/data/ingest_data.py \
        --date "$TODAY" \
        --days-back 1 \
        --table predictions

    python src/data/preprocess.py \
        --date "$TODAY" \
        --append

    dvc add data/raw/ojs-request-log/ data/processed/ 2>/dev/null || true

    NEW_HASH=$(grep "md5:" "$DVC_FILE" 2>/dev/null | awk '{print $2}')
    if [ "$OLD_HASH" != "$NEW_HASH" ]; then
        ok "Data version changed: ${OLD_HASH:-none} → $NEW_HASH"
    else
        warn "Data hash unchanged (tidak ada data baru untuk $TODAY?)"
    fi

    dvc diff HEAD 2>/dev/null || dvc status

    git add data/raw/ojs-request-log.dvc data/processed.dvc .gitignore 2>/dev/null || true
    git commit -m "data: daily ingest $TODAY" || true
    ok "Daily ingest committed"
fi

# ─── Step 7: Initial DVC track (kalau belum ada dan bukan catchup) ───────────
if [ -z "$START_DATE" ] && [ "$CONTINUAL" = "false" ]; then
    log "Step 7: Initial DVC tracking..."
    dvc add data/raw/ojs-request-log/ data/processed/ models/ 2>/dev/null || true
    git add data/raw/ojs-request-log.dvc data/processed.dvc models.dvc .gitignore 2>/dev/null || true
    git commit -m "data: initial DVC tracking" || true
    ok "Initial tracking done"
fi

# ─── Step 8: Push ke remote ───────────────────────────────────────────────────
if dvc remote list 2>/dev/null | grep -q "minio\|s3\|gs\|azure"; then
    log "Pushing data to DVC remote..."
    dvc push && ok "DVC push complete" || warn "DVC push failed (check credentials)"
fi

if [ "$PUSH_HF" = "true" ]; then
    log "Pushing data/ to Hugging Face..."
    huggingface-cli upload AkbarFikri/ojs-request-log ./data data \
        --repo-type=dataset && ok "HF push complete" || warn "HF push failed"
fi

# ─── Step 9: Setup cron harian ───────────────────────────────────────────────
#
#  Cron ini akan:
#   1. Jalankan ingest_data.py --date hari-ini
#   2. Jalankan preprocess.py --date hari-ini --append
#   3. DVC add + git commit + (opsional) dvc push & hf push
#
CRON_UTC=$(( (CRON_HOUR - 7 + 24) % 24 ))   # konversi WIB → UTC
CRON_SCRIPT="$REPO_ROOT/scripts/daily_ingest.sh"

log "Step 9: Setting up daily cron (${CRON_HOUR}:00 WIB = ${CRON_UTC}:00 UTC)..."

# Buat daily_ingest.sh yang dipanggil oleh cron
cat > "$CRON_SCRIPT" << DAILY
#!/usr/bin/env bash
# Auto-generated oleh setup_dvc.sh — jangan edit manual
set -e
cd "$REPO_ROOT"

TODAY=\$(date +%Y-%m-%d)
LOG_FILE="$REPO_ROOT/logs/daily_ingest_\${TODAY}.log"
mkdir -p "$REPO_ROOT/logs"

exec >> "\$LOG_FILE" 2>&1

echo "[\$(date)] Starting daily ingest for \$TODAY"

python src/data/ingest_data.py \\
    --date "\$TODAY" \\
    --days-back 1 \\
    --table predictions

python src/data/preprocess.py \\
    --date "\$TODAY" \\
    --append

dvc add data/raw/ojs-request-log/ data/processed/ 2>/dev/null || true

git add data/raw/ojs-request-log.dvc data/processed.dvc .gitignore 2>/dev/null || true
git commit -m "data: daily ingest \$TODAY" || true
git push origin main || true
DAILY

# Tambahkan baris push DVC jika ada remote
if dvc remote list 2>/dev/null | grep -q "minio\|s3\|gs\|azure"; then
    echo "dvc push || true" >> "$CRON_SCRIPT"
fi

# Tambahkan HF push jika diminta
if [ "$PUSH_HF" = "true" ]; then
    cat >> "$CRON_SCRIPT" << 'HFBLOCK'
huggingface-cli upload AkbarFikri/ojs-request-log ./data data \
    --repo-type=dataset || true
HFBLOCK
fi

echo "" >> "$CRON_SCRIPT"
echo "echo \"[\$(date)] Daily ingest complete for \$TODAY\"" >> "$CRON_SCRIPT"
chmod +x "$CRON_SCRIPT"

# Daftarkan ke crontab (idempoten — tidak menduplikat kalau sudah ada)
CRON_ENTRY="0 $CRON_UTC * * * $CRON_SCRIPT"
CRONTAB_CURRENT=$(crontab -l 2>/dev/null || true)

if echo "$CRONTAB_CURRENT" | grep -qF "$CRON_SCRIPT"; then
    ok "Cron already registered: $CRON_ENTRY"
else
    (echo "$CRONTAB_CURRENT"; echo "$CRON_ENTRY") | crontab -
    ok "Cron registered: $CRON_ENTRY"
fi

# ─── Summary ──────────────────────────────────────────────────────────────────
log ""
log "=== DVC Setup Complete ==="
log ""
log "  DVC tracked files:"
ls -la data/raw/ojs-request-log.dvc data/processed.dvc models.dvc 2>/dev/null || true
log ""
log "  Raw data (partitioned):"
find data/raw/ojs-request-log -name "*.csv" 2>/dev/null | sort | tail -5 || true
log ""
log "  Cron harian:"
crontab -l 2>/dev/null | grep "daily_ingest" || true
log ""
log "  Useful commands:"
log "    # Setup awal (tanpa ingest)"
log "    bash scripts/setup_dvc.sh"
log ""
log "    # Catchup dari tanggal tertentu"
log "    bash scripts/setup_dvc.sh --start-date=2024-01-01"
log ""
log "    # Ingest hari ini (manual)"
log "    bash scripts/setup_dvc.sh --continual"
log ""
log "    # Ingest + push HF"
log "    bash scripts/setup_dvc.sh --continual --push-hf"
log ""
log "    # Lihat cron log"
log "    tail -f logs/daily_ingest_\$(date +%Y-%m-%d).log"
log ""
log "    # DVC status & diff"
log "    dvc status | dvc diff HEAD~1 | dvc push | dvc pull"