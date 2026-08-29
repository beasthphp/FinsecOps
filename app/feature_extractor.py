"""Aggregate raw security events into the model's one-hour feature rows."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from app.log_generator import BASELINE_USER_IPS


FEATURE_COLUMNS = [
    "login_hour",
    "failed_logins",
    "successful_logins",
    "unique_ips",
    "new_ip_flag",
    "file_access_count",
    "files_downloaded",
    "download_mb",
    "db_queries",
    "admin_access_count",
    "unique_resources",
]


@dataclass(frozen=True)
class BehaviorWindow:
    user_id: str
    role: str
    window_start: datetime
    events: list[dict[str, object]]
    features: dict[str, float]

    @property
    def timestamp(self) -> str:
        return max(parse_timestamp(event["timestamp"]) for event in self.events).isoformat()

    @property
    def window_start_text(self) -> str:
        return self.window_start.isoformat()

    @property
    def primary_source_ip(self) -> str:
        counts = Counter(str(event["source_ip"]) for event in self.events)
        return counts.most_common(1)[0][0]


def parse_timestamp(value: object) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed.replace(microsecond=0)


def floor_to_hour(value: object) -> datetime:
    parsed = parse_timestamp(value)
    return parsed.replace(minute=0, second=0, microsecond=0)


def extract_behavior_windows(
    events: Iterable[dict[str, object]],
    baseline_ips: dict[str, set[str]] | None = None,
) -> list[BehaviorWindow]:
    """Return one feature row per user and one-hour window."""

    baseline = baseline_ips or BASELINE_USER_IPS
    normalized = sorted(
        (normalize_event(event) for event in events),
        key=lambda item: (parse_timestamp(item["timestamp"]), str(item["user_id"])),
    )
    grouped: dict[tuple[str, datetime], list[dict[str, object]]] = defaultdict(list)
    for event in normalized:
        grouped[(str(event["user_id"]), floor_to_hour(event["timestamp"]))].append(event)

    seen_ips_by_user: dict[str, set[str]] = defaultdict(set)
    windows: list[BehaviorWindow] = []

    for (user_id, window_start), group in sorted(grouped.items(), key=lambda item: (item[0][1], item[0][0])):
        role = str(group[-1]["role"])
        known_ips = set(baseline.get(user_id, set())) | seen_ips_by_user[user_id]
        source_ips = {str(event["source_ip"]) for event in group}
        new_ip_flag = int(any(ip not in known_ips for ip in source_ips))
        features = build_features(group, window_start, new_ip_flag)
        windows.append(
            BehaviorWindow(
                user_id=user_id,
                role=role,
                window_start=window_start,
                events=group,
                features=features,
            )
        )
        seen_ips_by_user[user_id].update(source_ips)

    return windows


def build_features(
    events: list[dict[str, object]],
    window_start: datetime,
    new_ip_flag: int,
) -> dict[str, float]:
    event_types = Counter(str(event["event_type"]) for event in events)
    download_bytes = sum(
        int(event.get("bytes_transferred", 0) or 0)
        for event in events
        if event["event_type"] == "FILE_DOWNLOAD"
    )
    resources = {str(event["resource"]) for event in events}
    source_ips = {str(event["source_ip"]) for event in events}

    features = {
        "login_hour": float(window_start.hour),
        "failed_logins": float(event_types["LOGIN_FAILED"]),
        "successful_logins": float(event_types["LOGIN_SUCCESS"]),
        "unique_ips": float(len(source_ips)),
        "new_ip_flag": float(new_ip_flag),
        "file_access_count": float(event_types["FILE_ACCESS"]),
        "files_downloaded": float(event_types["FILE_DOWNLOAD"]),
        "download_mb": round(download_bytes / (1024 * 1024), 2),
        "db_queries": float(event_types["DATABASE_QUERY"]),
        "admin_access_count": float(event_types["ADMIN_ACCESS"]),
        "unique_resources": float(len(resources)),
    }
    return {column: features[column] for column in FEATURE_COLUMNS}


def normalize_event(event: dict[str, object]) -> dict[str, object]:
    normalized = dict(event)
    normalized["timestamp"] = parse_timestamp(normalized["timestamp"]).isoformat()
    normalized["success"] = bool(normalized.get("success"))
    normalized["bytes_transferred"] = int(normalized.get("bytes_transferred", 0) or 0)
    return normalized

