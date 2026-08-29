"""Synthetic security activity generator for the FinSecOps demo."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
import random
from typing import Iterable


EVENT_TYPES = (
    "LOGIN_SUCCESS",
    "LOGIN_FAILED",
    "FILE_ACCESS",
    "FILE_DOWNLOAD",
    "DATABASE_QUERY",
    "ADMIN_ACCESS",
)

COMPANY_USERS: dict[str, str] = {
    "user_01": "admin",
    "user_02": "admin",
    "user_03": "analyst",
    "user_04": "employee",
    "user_05": "employee",
    "user_06": "employee",
    "user_07": "analyst",
    "user_08": "employee",
    "user_09": "employee",
    "user_10": "employee",
    "user_11": "analyst",
    "user_12": "employee",
    "user_13": "employee",
    "user_14": "employee",
    "user_15": "employee",
}

BASELINE_USER_IPS: dict[str, set[str]] = {
    user_id: {f"10.0.0.{10 + index}"}
    for index, user_id in enumerate(COMPANY_USERS, start=1)
}

OFFICE_RESOURCES = (
    "finance_q3.xlsx",
    "vendor_contract.pdf",
    "payroll_summary.csv",
    "customer_export.csv",
    "risk_report.docx",
    "audit_evidence.zip",
    "roadmap.pptx",
    "board_packet.pdf",
)

DATABASE_RESOURCES = (
    "db://ledger.transactions",
    "db://ledger.accounts",
    "db://aml.cases",
    "db://risk.scores",
)


@dataclass(frozen=True)
class SecurityEvent:
    timestamp: datetime
    user_id: str
    role: str
    source_ip: str
    event_type: str
    resource: str
    success: bool
    bytes_transferred: int = 0

    def to_record(self) -> dict[str, object]:
        record = asdict(self)
        record["timestamp"] = self.timestamp.replace(microsecond=0).isoformat()
        return record


class LogGenerator:
    """Creates normal and suspicious activity for the prototype."""

    def __init__(self, seed: int | None = 42) -> None:
        self.random = random.Random(seed)

    def generate_normal_activity(
        self,
        user_ids: Iterable[str] | None = None,
        base_time: datetime | None = None,
    ) -> list[dict[str, object]]:
        day = (base_time or datetime.now()).date()
        selected_users = list(user_ids) if user_ids is not None else list(COMPANY_USERS)
        events: list[SecurityEvent] = []

        for index, user_id in enumerate(selected_users):
            role = COMPANY_USERS[user_id]
            ip = self._baseline_ip(user_id)
            start = datetime.combine(day, datetime.min.time()).replace(
                hour=9 + (index % 7),
                minute=self.random.randint(0, 12),
            )

            events.append(
                self._event(start, user_id, ip, "LOGIN_SUCCESS", "authentication", True)
            )

            if self.random.random() < 0.25:
                events.append(
                    self._event(
                        start + timedelta(minutes=1),
                        user_id,
                        ip,
                        "LOGIN_FAILED",
                        "authentication",
                        False,
                    )
                )

            for offset in range(self.random.randint(4, 9)):
                resource = self.random.choice(OFFICE_RESOURCES)
                events.append(
                    self._event(
                        start + timedelta(minutes=5 + offset * 4),
                        user_id,
                        ip,
                        "FILE_ACCESS",
                        resource,
                        True,
                    )
                )

            for offset in range(self.random.randint(1, 4)):
                resource = self.random.choice(OFFICE_RESOURCES)
                mb = self.random.randint(3, 25)
                events.append(
                    self._event(
                        start + timedelta(minutes=15 + offset * 8),
                        user_id,
                        ip,
                        "FILE_DOWNLOAD",
                        resource,
                        True,
                        mb * 1024 * 1024,
                    )
                )

            if role == "analyst":
                for offset in range(self.random.randint(6, 18)):
                    events.append(
                        self._event(
                            start + timedelta(minutes=8 + offset * 2),
                            user_id,
                            ip,
                            "DATABASE_QUERY",
                            self.random.choice(DATABASE_RESOURCES),
                            True,
                        )
                    )

            if role == "admin":
                for offset in range(self.random.randint(1, 3)):
                    events.append(
                        self._event(
                            start + timedelta(minutes=20 + offset * 10),
                            user_id,
                            ip,
                            "ADMIN_ACCESS",
                            "admin://iam/users",
                            True,
                        )
                    )

        return self._records(events)

    def simulate_brute_force(
        self,
        user_id: str = "user_05",
        source_ip: str = "203.0.113.15",
        attempts: int = 8,
        base_time: datetime | None = None,
    ) -> list[dict[str, object]]:
        start = self._demo_time(base_time, hour=14, minute=5)
        events = [
            self._event(
                start + timedelta(seconds=20 * attempt),
                user_id,
                source_ip,
                "LOGIN_FAILED",
                "authentication",
                False,
            )
            for attempt in range(attempts)
        ]
        return self._records(events)

    def simulate_suspicious_login(
        self,
        user_id: str = "user_06",
        source_ip: str | None = None,
        base_time: datetime | None = None,
    ) -> list[dict[str, object]]:
        start = self._demo_time(base_time, hour=3, minute=12)
        source_ip = source_ip or self._baseline_ip(user_id)
        events = [
            self._event(start, user_id, source_ip, "LOGIN_SUCCESS", "authentication", True),
            self._event(
                start + timedelta(minutes=5),
                user_id,
                source_ip,
                "FILE_ACCESS",
                "risk_report.docx",
                True,
            ),
        ]
        return self._records(events)

    def simulate_privilege_misuse(
        self,
        user_id: str = "user_04",
        base_time: datetime | None = None,
    ) -> list[dict[str, object]]:
        start = self._demo_time(base_time, hour=11, minute=20)
        ip = self._baseline_ip(user_id)
        events = [
            self._event(start, user_id, ip, "LOGIN_SUCCESS", "authentication", True),
            self._event(
                start + timedelta(minutes=3),
                user_id,
                ip,
                "ADMIN_ACCESS",
                "admin://iam/users",
                True,
            ),
        ]
        return self._records(events)

    def simulate_data_exfiltration(
        self,
        user_id: str = "user_08",
        files: int = 150,
        total_mb: int = 3072,
        base_time: datetime | None = None,
    ) -> list[dict[str, object]]:
        start = self._demo_time(base_time, hour=15, minute=0)
        ip = self._baseline_ip(user_id)
        per_file_bytes = int((total_mb * 1024 * 1024) / files)
        events = [
            self._event(
                start + timedelta(seconds=4 * index),
                user_id,
                ip,
                "FILE_DOWNLOAD",
                f"archive/file_{index:03d}.zip",
                True,
                per_file_bytes,
            )
            for index in range(files)
        ]
        return self._records(events)

    def simulate_behavioral_anomaly(
        self,
        user_id: str = "user_09",
        base_time: datetime | None = None,
    ) -> list[dict[str, object]]:
        start = self._demo_time(base_time, hour=3, minute=2)
        role = COMPANY_USERS[user_id]
        source_ips = [f"192.0.2.{20 + index}" for index in range(4)]
        events: list[SecurityEvent] = []

        for index, ip in enumerate(source_ips):
            events.append(
                self._event(
                    start + timedelta(minutes=index),
                    user_id,
                    ip,
                    "LOGIN_FAILED",
                    "authentication",
                    False,
                )
            )

        for index in range(80):
            events.append(
                self._event(
                    start + timedelta(minutes=5, seconds=index * 10),
                    user_id,
                    source_ips[index % len(source_ips)],
                    "FILE_ACCESS",
                    f"shared/high_volume_{index:03d}.dat",
                    True,
                )
            )

        per_file_bytes = int((900 * 1024 * 1024) / 90)
        for index in range(90):
            events.append(
                self._event(
                    start + timedelta(minutes=22, seconds=index * 10),
                    user_id,
                    source_ips[index % len(source_ips)],
                    "FILE_DOWNLOAD",
                    f"shared/export_{index:03d}.dat",
                    True,
                    per_file_bytes,
                )
            )

        for index in range(250):
            events.append(
                self._event(
                    start + timedelta(minutes=38, seconds=index * 4),
                    user_id,
                    source_ips[index % len(source_ips)],
                    "DATABASE_QUERY",
                    DATABASE_RESOURCES[index % len(DATABASE_RESOURCES)],
                    True,
                )
            )

        return self._records(events)

    def simulate_mixed_attack(
        self,
        user_id: str = "user_10",
        source_ip: str = "203.0.113.200",
        base_time: datetime | None = None,
    ) -> list[dict[str, object]]:
        start = self._demo_time(base_time, hour=2, minute=40)
        events: list[SecurityEvent] = []

        for index in range(10):
            events.append(
                self._event(
                    start + timedelta(seconds=18 * index),
                    user_id,
                    source_ip,
                    "LOGIN_FAILED",
                    "authentication",
                    False,
                )
            )

        events.append(
            self._event(
                start + timedelta(minutes=4),
                user_id,
                source_ip,
                "LOGIN_SUCCESS",
                "authentication",
                True,
            )
        )

        for index in range(40):
            events.append(
                self._event(
                    start + timedelta(minutes=6, seconds=index * 10),
                    user_id,
                    source_ip,
                    "DATABASE_QUERY",
                    DATABASE_RESOURCES[index % len(DATABASE_RESOURCES)],
                    True,
                )
            )

        per_file_bytes = int((2048 * 1024 * 1024) / 120)
        for index in range(120):
            events.append(
                self._event(
                    start + timedelta(minutes=12, seconds=index * 4),
                    user_id,
                    source_ip,
                    "FILE_DOWNLOAD",
                    f"bulk/customer_dump_{index:03d}.csv",
                    True,
                    per_file_bytes,
                )
            )

        return self._records(events)

    def generate_scenario(self, scenario: str) -> list[dict[str, object]]:
        scenarios = {
            "normal": self.generate_normal_activity,
            "brute_force": self.simulate_brute_force,
            "suspicious_login": self.simulate_suspicious_login,
            "privilege_misuse": self.simulate_privilege_misuse,
            "data_exfiltration": self.simulate_data_exfiltration,
            "behavioral_anomaly": self.simulate_behavioral_anomaly,
            "mixed_attack": self.simulate_mixed_attack,
        }
        try:
            return scenarios[scenario]()
        except KeyError as exc:
            valid = ", ".join(sorted(scenarios))
            raise ValueError(f"Unknown scenario '{scenario}'. Expected one of: {valid}") from exc

    def _event(
        self,
        timestamp: datetime,
        user_id: str,
        source_ip: str,
        event_type: str,
        resource: str,
        success: bool,
        bytes_transferred: int = 0,
    ) -> SecurityEvent:
        if event_type not in EVENT_TYPES:
            raise ValueError(f"Unsupported event type: {event_type}")
        return SecurityEvent(
            timestamp=timestamp,
            user_id=user_id,
            role=COMPANY_USERS[user_id],
            source_ip=source_ip,
            event_type=event_type,
            resource=resource,
            success=success,
            bytes_transferred=bytes_transferred,
        )

    def _baseline_ip(self, user_id: str) -> str:
        return sorted(BASELINE_USER_IPS[user_id])[0]

    def _demo_time(
        self,
        base_time: datetime | None,
        hour: int,
        minute: int,
    ) -> datetime:
        day = (base_time or datetime.now()).date()
        return datetime.combine(day, datetime.min.time()).replace(hour=hour, minute=minute)

    def _records(self, events: Iterable[SecurityEvent]) -> list[dict[str, object]]:
        return [event.to_record() for event in sorted(events, key=lambda item: item.timestamp)]
