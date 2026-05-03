import os
from contextlib import contextmanager

import psycopg2
import psycopg2.extras
from psycopg2.extras import Json

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/attack_detection"
)


@contextmanager
def get_conn():
    conn = psycopg2.connect(DATABASE_URL)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS predictions (
                    id          SERIAL PRIMARY KEY,
                    timestamp   TEXT        NOT NULL,
                    ip          TEXT,
                    method      TEXT,
                    path        TEXT,
                    query       TEXT,
                    body        TEXT,
                    headers     JSONB,
                    prediction  TEXT        NOT NULL CHECK (prediction IN ('Normal', 'Attack')),
                    label       TEXT                 CHECK (label IN ('Normal', 'Attack')),
                    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_predictions_created_at ON predictions (created_at DESC)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_predictions_prediction  ON predictions (prediction)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_predictions_label       ON predictions (label)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_predictions_headers     ON predictions USING gin (headers)")


def insert_prediction(data: dict) -> int:
    headers = data.get("headers") or {}
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO predictions
                    (timestamp, ip, method, path, query, body, headers, prediction)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    data.get("timestamp", ""),
                    data.get("ip", ""),
                    data.get("method", ""),
                    data.get("path", ""),
                    data.get("query", ""),
                    data.get("body", ""),
                    Json(headers),
                    data["prediction"],
                ),
            )
            return cur.fetchone()[0]


def update_label(prediction_id: int, label: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE predictions SET label = %s WHERE id = %s",
                (label, prediction_id),
            )


def get_predictions(date_from: str = None, date_to: str = None,
                    page: int = 1, page_size: int = 50,
                    labeled: bool = None) -> dict:
    where_clauses = []
    params = []

    if date_from:
        where_clauses.append("created_at::date >= %s")
        params.append(date_from)
    if date_to:
        where_clauses.append("created_at::date <= %s")
        params.append(date_to)

    # Filter labeled/unlabeled
    if labeled is True:
        where_clauses.append("label IS NOT NULL")
    elif labeled is False:
        where_clauses.append("label IS NULL")

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    offset = (page - 1) * page_size

    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(f"SELECT COUNT(*) FROM predictions {where_sql}", params)
            total = cur.fetchone()["count"]

            cur.execute(
                f"""
                SELECT
                    id, timestamp, ip, method, path, query, body, headers,
                    prediction, label,
                    TO_CHAR(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS') AS created_at
                FROM predictions
                {where_sql}
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
                """,
                params + [page_size, offset],
            )
            rows = cur.fetchall()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [dict(r) for r in rows],
    }


def get_stats(date_from: str = None, date_to: str = None) -> dict:
    where_clauses = []
    params = []

    if date_from:
        where_clauses.append("created_at::date >= %s")
        params.append(date_from)
    if date_to:
        where_clauses.append("created_at::date <= %s")
        params.append(date_to)

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT
                    COUNT(*)                                                          AS total,
                    COUNT(*) FILTER (WHERE prediction = 'Attack')                    AS total_attack,
                    COUNT(*) FILTER (WHERE prediction = 'Normal')                    AS total_normal,
                    COUNT(*) FILTER (WHERE label IS NOT NULL)                        AS total_labeled,
                    COUNT(*) FILTER (WHERE label = 'Attack')                         AS labeled_attack,
                    COUNT(*) FILTER (WHERE label = 'Normal')                         AS labeled_normal,
                    COUNT(*) FILTER (WHERE label IS NOT NULL AND label != prediction) AS corrections
                FROM predictions
                {where_sql}
                """,
                params,
            )
            row = cur.fetchone()

            cur.execute(
                f"""
                SELECT
                    created_at::date                                  AS day,
                    COUNT(*) FILTER (WHERE prediction = 'Attack')    AS attacks,
                    COUNT(*) FILTER (WHERE prediction = 'Normal')    AS normals
                FROM predictions
                {where_sql}
                GROUP BY day
                ORDER BY day ASC
                """,
                params,
            )
            timeline = cur.fetchall()

    return {
        "total":          int(row["total"] or 0),
        "total_attack":   int(row["total_attack"] or 0),
        "total_normal":   int(row["total_normal"] or 0),
        "total_labeled":  int(row["total_labeled"] or 0),
        "labeled_attack": int(row["labeled_attack"] or 0),
        "labeled_normal": int(row["labeled_normal"] or 0),
        "corrections":    int(row["corrections"] or 0),
        "timeline": [
            {"day": str(r["day"]), "attacks": int(r["attacks"]), "normals": int(r["normals"])}
            for r in timeline
        ],
    }