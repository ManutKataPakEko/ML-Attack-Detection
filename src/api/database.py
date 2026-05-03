import os
import json
from contextlib import contextmanager
from urllib.parse import urlparse
from typing import Optional, Dict, Any

from utils.logger import get_logger

logger = get_logger("Database")

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "sqlite:///./data/predictions.db"
)


def parse_database_url(url: str) -> Dict[str, Any]:
    """Parse database URL to determine type and connection params."""
    parsed = urlparse(url)
    
    if parsed.scheme == 'sqlite':
        # SQLite: sqlite:///path/to/db.db or sqlite:///:memory:
        path = parsed.path
        if not path.startswith('/'):
            path = '/' + path
        
        # Handle relative paths
        if path.startswith('//./'):
            # Convert ///./data/db.db to ./data/db.db
            path = '.' + path[2:]
        elif path.startswith('///'):
            # Convert ////data/db.db to /data/db.db (absolute)
            path = path[2:]
        
        return {
            'type': 'sqlite',
            'path': path,
            'url': url
        }
    
    elif parsed.scheme in ('postgresql', 'postgres'):
        # PostgreSQL: postgresql://user:password@host:port/dbname
        return {
            'type': 'postgresql',
            'user': parsed.username,
            'password': parsed.password,
            'host': parsed.hostname or 'localhost',
            'port': parsed.port or 5432,
            'database': parsed.path.lstrip('/'),
            'url': url
        }
    
    else:
        raise ValueError(f"Unsupported database type: {parsed.scheme}")


def get_db_type(url: str) -> str:
    """Get database type from connection URL."""
    return urlparse(url).scheme.split('+')[0]


# ========== SQLite Implementation ==========

def _get_sqlite_conn():
    """Get SQLite connection."""
    import sqlite3
    
    db_config = parse_database_url(DATABASE_URL)
    db_path = db_config['path']
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(db_path) or '.', exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def _get_sqlite_ctx():
    """Context manager for SQLite."""
    conn = _get_sqlite_conn()
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"SQLite error: {str(e)}")
        raise
    finally:
        conn.close()


def _init_sqlite_db(conn):
    """Initialize SQLite database schema."""
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS predictions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT        NOT NULL,
            ip          TEXT,
            method      TEXT,
            path        TEXT,
            query       TEXT,
            body        TEXT,
            headers     TEXT,
            prediction  TEXT        NOT NULL CHECK (prediction IN ('Normal', 'Attack')),
            label       TEXT        CHECK (label IN ('Normal', 'Attack')),
            created_at  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_predictions_created_at ON predictions (created_at DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_predictions_prediction  ON predictions (prediction)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_predictions_label       ON predictions (label)")
    conn.commit()


def _insert_sqlite_prediction(conn, data: dict):
    """Insert prediction to SQLite."""
    cursor = conn.cursor()
    headers_json = json.dumps(data.get('headers', {})) if isinstance(data.get('headers'), dict) else data.get('headers', '{}')
    
    cursor.execute("""
        INSERT INTO predictions (timestamp, ip, method, path, query, body, headers, prediction, label)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get('timestamp'),
        data.get('ip'),
        data.get('method'),
        data.get('path'),
        data.get('query'),
        data.get('body'),
        headers_json,
        data.get('prediction'),
        data.get('label')
    ))
    conn.commit()


# ========== PostgreSQL Implementation ==========

def _get_postgresql_conn():
    """Get PostgreSQL connection."""
    import psycopg2
    
    db_config = parse_database_url(DATABASE_URL)
    
    conn = psycopg2.connect(
        user=db_config['user'],
        password=db_config['password'],
        host=db_config['host'],
        port=db_config['port'],
        database=db_config['database']
    )
    return conn


@contextmanager
def _get_postgresql_ctx():
    """Context manager for PostgreSQL."""
    import psycopg2
    
    conn = _get_postgresql_conn()
    try:
        yield conn
        conn.commit()
    except psycopg2.Error as e:
        conn.rollback()
        logger.error(f"PostgreSQL error: {str(e)}")
        raise
    finally:
        conn.close()


def _init_postgresql_db(conn):
    """Initialize PostgreSQL database schema."""
    import psycopg2.extras
    
    cursor = conn.cursor()
    cursor.execute("""
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
            label       TEXT        CHECK (label IN ('Normal', 'Attack')),
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_predictions_created_at ON predictions (created_at DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_predictions_prediction  ON predictions (prediction)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_predictions_label       ON predictions (label)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_predictions_headers     ON predictions USING gin (headers)")
    conn.commit()


def _insert_postgresql_prediction(conn, data: dict):
    """Insert prediction to PostgreSQL."""
    import psycopg2.extras
    
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO predictions (timestamp, ip, method, path, query, body, headers, prediction, label)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        data.get('timestamp'),
        data.get('ip'),
        data.get('method'),
        data.get('path'),
        data.get('query'),
        data.get('body'),
        psycopg2.extras.Json(data.get('headers', {})),
        data.get('prediction'),
        data.get('label')
    ))
    conn.commit()


# ========== Unified Interface ==========

@contextmanager
def get_conn():
    """
    Get database connection based on DATABASE_URL.
    
    Supports:
    - SQLite: sqlite:///./path/to/db.db
    - PostgreSQL: postgresql://user:password@host:port/dbname
    """
    db_type = get_db_type(DATABASE_URL)
    
    if db_type == 'sqlite':
        with _get_sqlite_ctx() as conn:
            yield conn
    elif db_type in ('postgresql', 'postgres'):
        with _get_postgresql_ctx() as conn:
            yield conn
    else:
        raise ValueError(f"Unsupported database: {db_type}")


def init_db():
    """Initialize database schema (creates tables if needed)."""
    db_type = get_db_type(DATABASE_URL)
    logger.info(f"Initializing {db_type} database: {DATABASE_URL}")
    
    try:
        if db_type == 'sqlite':
            with _get_sqlite_ctx() as conn:
                _init_sqlite_db(conn)
        elif db_type in ('postgresql', 'postgres'):
            with _get_postgresql_ctx() as conn:
                _init_postgresql_db(conn)
        else:
            raise ValueError(f"Unsupported database: {db_type}")
        
        logger.info("✓ Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        raise


def insert_prediction(data: dict):
    """
    Insert prediction record into database.
    
    Args:
        data: Dictionary with prediction data:
            - timestamp: Request timestamp
            - ip: Client IP
            - method: HTTP method
            - path: Request path
            - query: Query string
            - body: Request body
            - headers: Request headers (dict or JSON string)
            - prediction: 'Normal' or 'Attack'
            - label: Optional, actual label if known
    """
    db_type = get_db_type(DATABASE_URL)
    
    try:
        if db_type == 'sqlite':
            with _get_sqlite_ctx() as conn:
                _insert_sqlite_prediction(conn, data)
        elif db_type in ('postgresql', 'postgres'):
            with _get_postgresql_ctx() as conn:
                _insert_postgresql_prediction(conn, data)
        else:
            raise ValueError(f"Unsupported database: {db_type}")
        
        logger.debug(f"Prediction inserted: {data.get('prediction')} from {data.get('ip')}")
    except Exception as e:
        logger.error(f"Failed to insert prediction: {str(e)}")
        raise


# ========== Dashboard/Query Functions ==========
# Note: These functions support both SQLite and PostgreSQL but with simplified functionality
# Full features (e.g., timezone conversion, advanced filtering) only available with PostgreSQL

def update_label(prediction_id: int, label: str):
    """Update the label (ground truth) for a prediction."""
    db_type = get_db_type(DATABASE_URL)
    
    try:
        if db_type == 'sqlite':
            with _get_sqlite_ctx() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE predictions SET label = ? WHERE id = ?",
                    (label, prediction_id)
                )
                conn.commit()
        elif db_type in ('postgresql', 'postgres'):
            with _get_postgresql_ctx() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE predictions SET label = %s WHERE id = %s",
                    (label, prediction_id)
                )
                conn.commit()
        
        logger.info(f"Updated label for prediction {prediction_id}: {label}")
    except Exception as e:
        logger.error(f"Failed to update label: {str(e)}")
        raise


def get_predictions(date_from: str = None, date_to: str = None,
                    page: int = 1, page_size: int = 50,
                    labeled: bool = None) -> dict:
    """
    Get paginated list of predictions with optional filtering.
    
    Args:
        date_from: Filter by start date (YYYY-MM-DD)
        date_to: Filter by end date (YYYY-MM-DD)
        page: Page number (1-indexed)
        page_size: Results per page
        labeled: True=has label, False=no label, None=all
    
    Returns:
        Dict with total, page, page_size, items
    """
    db_type = get_db_type(DATABASE_URL)
    
    try:
        where_clauses = []
        params = []
        
        if date_from:
            where_clauses.append("DATE(created_at) >= ?") if db_type == 'sqlite' else where_clauses.append("created_at::date >= %s")
            params.append(date_from)
        if date_to:
            where_clauses.append("DATE(created_at) <= ?") if db_type == 'sqlite' else where_clauses.append("created_at::date <= %s")
            params.append(date_to)
        
        if labeled is True:
            where_clauses.append("label IS NOT NULL")
        elif labeled is False:
            where_clauses.append("label IS NULL")
        
        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        offset = (page - 1) * page_size
        
        if db_type == 'sqlite':
            with _get_sqlite_ctx() as conn:
                cursor = conn.cursor()
                
                # Get total count
                cursor.execute(f"SELECT COUNT(*) as count FROM predictions {where_sql}", params)
                total = cursor.fetchone()[0]
                
                # Get paginated results
                cursor.execute(
                    f"""
                    SELECT id, timestamp, ip, method, path, query, body, headers,
                           prediction, label, created_at
                    FROM predictions
                    {where_sql}
                    ORDER BY created_at DESC
                    LIMIT ? OFFSET ?
                    """,
                    params + [page_size, offset]
                )
                rows = cursor.fetchall()
                
                items = []
                for row in rows:
                    items.append({
                        'id': row[0],
                        'timestamp': row[1],
                        'ip': row[2],
                        'method': row[3],
                        'path': row[4],
                        'query': row[5],
                        'body': row[6],
                        'headers': row[7],
                        'prediction': row[8],
                        'label': row[9],
                        'created_at': row[10]
                    })
        
        elif db_type in ('postgresql', 'postgres'):
            import psycopg2.extras
            with _get_postgresql_ctx() as conn:
                cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                
                # Get total count
                cursor.execute(f"SELECT COUNT(*) FROM predictions {where_sql}", params)
                total = cursor.fetchone()["count"]
                
                # Get paginated results
                cursor.execute(
                    f"""
                    SELECT id, timestamp, ip, method, path, query, body, headers,
                           prediction, label,
                           TO_CHAR(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS') AS created_at
                    FROM predictions
                    {where_sql}
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                    """,
                    params + [page_size, offset]
                )
                items = [dict(r) for r in cursor.fetchall()]
        
        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "items": items
        }
    
    except Exception as e:
        logger.error(f"Failed to get predictions: {str(e)}")
        raise


def get_stats(date_from: str = None, date_to: str = None) -> dict:
    """
    Get statistics about predictions.
    
    Args:
        date_from: Filter from date (YYYY-MM-DD)
        date_to: Filter to date (YYYY-MM-DD)
    
    Returns:
        Dict with total, attack, normal, labeled, corrections, timeline
    """
    db_type = get_db_type(DATABASE_URL)
    
    try:
        where_clauses = []
        params = []
        
        if date_from:
            where_clauses.append("DATE(created_at) >= ?") if db_type == 'sqlite' else where_clauses.append("created_at::date >= %s")
            params.append(date_from)
        if date_to:
            where_clauses.append("DATE(created_at) <= ?") if db_type == 'sqlite' else where_clauses.append("created_at::date <= %s")
            params.append(date_to)
        
        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        
        if db_type == 'sqlite':
            with _get_sqlite_ctx() as conn:
                cursor = conn.cursor()
                
                # Get overall stats
                cursor.execute(
                    f"""
                    SELECT
                        COUNT(*) as total,
                        SUM(CASE WHEN prediction = 'Attack' THEN 1 ELSE 0 END) as total_attack,
                        SUM(CASE WHEN prediction = 'Normal' THEN 1 ELSE 0 END) as total_normal,
                        SUM(CASE WHEN label IS NOT NULL THEN 1 ELSE 0 END) as total_labeled,
                        SUM(CASE WHEN label = 'Attack' THEN 1 ELSE 0 END) as labeled_attack,
                        SUM(CASE WHEN label = 'Normal' THEN 1 ELSE 0 END) as labeled_normal,
                        SUM(CASE WHEN label IS NOT NULL AND label != prediction THEN 1 ELSE 0 END) as corrections
                    FROM predictions
                    {where_sql}
                    """,
                    params
                )
                row = cursor.fetchone()
                
                # Get timeline stats
                cursor.execute(
                    f"""
                    SELECT
                        DATE(created_at) as day,
                        SUM(CASE WHEN prediction = 'Attack' THEN 1 ELSE 0 END) as attacks,
                        SUM(CASE WHEN prediction = 'Normal' THEN 1 ELSE 0 END) as normals
                    FROM predictions
                    {where_sql}
                    GROUP BY DATE(created_at)
                    ORDER BY day ASC
                    """,
                    params
                )
                timeline = cursor.fetchall()
                
                return {
                    "total": row[0] or 0,
                    "total_attack": row[1] or 0,
                    "total_normal": row[2] or 0,
                    "total_labeled": row[3] or 0,
                    "labeled_attack": row[4] or 0,
                    "labeled_normal": row[5] or 0,
                    "corrections": row[6] or 0,
                    "timeline": [
                        {
                            "day": str(t[0]),
                            "attacks": t[1] or 0,
                            "normals": t[2] or 0
                        }
                        for t in timeline
                    ]
                }
        
        elif db_type in ('postgresql', 'postgres'):
            import psycopg2.extras
            with _get_postgresql_ctx() as conn:
                cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                
                # Get overall stats
                cursor.execute(
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
                    params
                )
                row = cursor.fetchone()
                
                # Get timeline stats
                cursor.execute(
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
                    params
                )
                timeline = cursor.fetchall()
                
                return {
                    "total": int(row["total"] or 0),
                    "total_attack": int(row["total_attack"] or 0),
                    "total_normal": int(row["total_normal"] or 0),
                    "total_labeled": int(row["total_labeled"] or 0),
                    "labeled_attack": int(row["labeled_attack"] or 0),
                    "labeled_normal": int(row["labeled_normal"] or 0),
                    "corrections": int(row["corrections"] or 0),
                    "timeline": [
                        {
                            "day": str(r["day"]),
                            "attacks": int(r["attacks"] or 0),
                            "normals": int(r["normals"] or 0)
                        }
                        for r in timeline
                    ]
                }
    
    except Exception as e:
        logger.error(f"Failed to get stats: {str(e)}")
        raise