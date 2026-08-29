"""Small event-store wrapper around the SQLite helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from app.database import DEFAULT_DB_PATH, fetch_events, initialize_database, insert_events


class EventStore:
    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        initialize_database(self.db_path)

    def append(self, event: dict[str, object]) -> int:
        return self.append_many([event])[0]

    def append_many(self, events: Iterable[dict[str, object]]) -> list[int]:
        return insert_events(events, self.db_path)

    def list_events(self, limit: int | None = None) -> list[dict[str, object]]:
        return fetch_events(self.db_path, limit=limit)

