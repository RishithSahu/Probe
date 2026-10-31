"""FastAPI dependencies."""
from __future__ import annotations

from typing import Iterator

from sqlalchemy.orm import Session

from app.database.session import SessionLocal


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
