"""initial schema

Revision ID: 03a5686f3233
Revises: 
Create Date: 2026-04-10 08:31:44.693281

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '03a5686f3233'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
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
    op.execute("CREATE INDEX IF NOT EXISTS idx_predictions_created_at ON predictions (created_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_predictions_prediction  ON predictions (prediction)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_predictions_label       ON predictions (label)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_predictions_headers     ON predictions USING gin (headers)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS predictions")
