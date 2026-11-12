#!/usr/bin/env python3
"""Fake credential-report data and a fake IAM client for tests and the sample.

Every value here is invented. The account ID 123456789012 is the placeholder
used in AWS documentation. Run `python fixtures.py` to rebuild sample/.
"""
from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from iam_review import ADMIN_POLICY_ARN, ROOT_USER, review, write_outputs

ACCOUNT = "123456789012"
FAKE_NOW = datetime(2026, 6, 30, 12, 0, tzinfo=timezone.utc)
FAKE_REPORT_TIME = FAKE_NOW - timedelta(minutes=95)

REPORT_COLUMNS = [
    "user", "arn", "user_creation_time", "password_enabled", "password_last_used",
    "password_last_changed", "password_next_rotation", "mfa_active",
    "access_key_1_active", "access_key_1_last_rotated", "access_key_1_last_used_date",
    "access_key_1_last_used_region", "access_key_1_last_used_service",
    "access_key_2_active", "access_key_2_last_rotated", "access_key_2_last_used_date",
    "access_key_2_last_used_region", "access_key_2_last_used_service",
    "cert_1_active", "cert_1_last_rotated", "cert_2_active", "cert_2_last_rotated",
]


def ago(days: int) -> str:
    """Credential-report timestamp for FAKE_NOW minus days."""
    return (FAKE_NOW - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def make_row(user: str, **values: str) -> dict[str, str]:
    """Build a full credential-report row with safe defaults (no password, no keys)."""
    row = {col: "N/A" for col in REPORT_COLUMNS}
    row.update({
        "user": user,
        "arn": f"arn:aws:iam::{ACCOUNT}:user/{user}",
        "user_creation_time": ago(365),
        "password_enabled": "false",
        "mfa_active": "false",
        "access_key_1_active": "false",
        "access_key_2_active": "false",
        "cert_1_active": "false",
        "cert_2_active": "false",
    })
    row.update(values)
    return row


FAKE_ROWS: list[dict[str, str]] = [
    make_row("<root_account>", arn=f"arn:aws:iam::{ACCOUNT}:root", password_enabled="not_supported",
             password_last_used=ago(30), password_last_changed="not_supported",
             password_next_rotation="not_supported", mfa_active="true",
             access_key_1_active="true", access_key_1_last_rotated=ago(400),
             access_key_1_last_used_date="N/A"),
    make_row("admin-you", password_enabled="true", password_last_used=ago(1),
             password_last_changed=ago(120), mfa_active="true"),
    make_row("test-nomfa", user_creation_time=ago(60), password_enabled="true",
             password_last_used="no_information", password_last_changed=ago(60)),
    make_row("test-idle", user_creation_time=ago(100), access_key_1_active="true",
             access_key_1_last_rotated=ago(100), access_key_1_last_used_date="N/A"),
    make_row("test-newkey", user_creation_time=ago(3), access_key_1_active="true",
             access_key_1_last_rotated=ago(3), access_key_1_last_used_date="N/A"),
    make_row("test-admin", user_creation_time=ago(20)),
    make_row("iam-auditor", user_creation_time=ago(10), access_key_1_active="true",
             access_key_1_last_rotated=ago(10), access_key_1_last_used_date=ago(0)),
    make_row("test-mfaok", password_enabled="true", password_last_used=ago(5),
             password_last_changed=ago(40), mfa_active="true"),
    make_row("svc-legacy", access_key_1_active="true", access_key_1_last_rotated=ago(200),
             access_key_1_last_used_date=ago(2), access_key_2_active="false",
             access_key_2_last_rotated=ago(500), access_key_2_last_used_date=ago(450)),
]

# Created after the credential report was generated, so ListUsers returns it
# but the report does not.
LATE_USERS: list[dict[str, Any]] = [
    {"UserName": "test-late", "Arn": f"arn:aws:iam::{ACCOUNT}:user/test-late",
     "CreateDate": FAKE_NOW - timedelta(minutes=30)},
]

FAKE_ATTACHED: dict[str, list[str]] = {
    "test-late": [ADMIN_POLICY_ARN],
    "admin-you": [ADMIN_POLICY_ARN],
    "test-admin": [ADMIN_POLICY_ARN],
    "iam-auditor": [f"arn:aws:iam::{ACCOUNT}:policy/MyAdministratorAccess"],
}

FAKE_SERVICES: dict[str, list[dict[str, Any]]] = {
    f"arn:aws:iam::{ACCOUNT}:user/admin-you": [
        {"ServiceNamespace": "iam", "LastAuthenticated": FAKE_NOW - timedelta(days=1)},
        {"ServiceNamespace": "s3", "LastAuthenticated": FAKE_NOW - timedelta(days=90)},
        {"ServiceNamespace": "ec2"},
    ],
}


def report_csv(rows: list[dict[str, str]]) -> bytes:
    """Serialize rows the way GetCredentialReport returns them."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=REPORT_COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue().encode("utf-8")


def users_from_rows(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    """ListUsers entries for every non-root row of a credential report."""
    return [{"UserName": r["user"], "Arn": r["arn"],
             "CreateDate": datetime.fromisoformat(r["user_creation_time"])}
            for r in rows if r["user"] != ROOT_USER]


class _AttachedPaginator:
    """Fake paginator for list_attached_user_policies, one policy per page."""

    def __init__(self, attached: dict[str, list[str]]) -> None:
        self.attached = attached

    def paginate(self, UserName: str) -> list[dict[str, Any]]:  # noqa: N803 (boto3 name)
        arns = self.attached.get(UserName, [])
        return [{"AttachedPolicies": [{"PolicyArn": a, "PolicyName": a.rsplit("/", 1)[-1]}]}
                for a in arns] or [{"AttachedPolicies": []}]


class _UsersPaginator:
    """Fake paginator for list_users, two users per page."""

    def __init__(self, users: list[dict[str, Any]]) -> None:
        self.users = users

    def paginate(self) -> list[dict[str, Any]]:
        return [{"Users": self.users[i:i + 2]} for i in range(0, len(self.users), 2)] \
            or [{"Users": []}]


class FakeIAM:
    """In-memory stand-in for a boto3 IAM client. Records every method called."""

    def __init__(self, rows: list[dict[str, str]] | None = None,
                 attached: dict[str, list[str]] | None = None,
                 services: dict[str, list[dict[str, Any]]] | None = None,
                 late_users: list[dict[str, Any]] | None = None) -> None:
        self.rows = FAKE_ROWS if rows is None else rows
        self.users = users_from_rows(self.rows) + (LATE_USERS if late_users is None else late_users)
        self.attached = FAKE_ATTACHED if attached is None else attached
        self.services = FAKE_SERVICES if services is None else services
        self.calls: list[str] = []
        self._states = iter(["STARTED", "INPROGRESS"])

    def generate_credential_report(self) -> dict[str, str]:
        self.calls.append("generate_credential_report")
        return {"State": next(self._states, "COMPLETE")}

    def get_credential_report(self) -> dict[str, Any]:
        self.calls.append("get_credential_report")
        return {"Content": report_csv(self.rows), "ReportFormat": "text/csv",
                "GeneratedTime": FAKE_REPORT_TIME}

    def get_paginator(self, name: str) -> _AttachedPaginator | _UsersPaginator:
        self.calls.append(f"get_paginator:{name}")
        if name == "list_users":
            return _UsersPaginator(self.users)
        assert name == "list_attached_user_policies"
        return _AttachedPaginator(self.attached)

    def generate_service_last_accessed_details(self, Arn: str) -> dict[str, str]:  # noqa: N803
        self.calls.append("generate_service_last_accessed_details")
        return {"JobId": Arn}

    def get_service_last_accessed_details(self, JobId: str, Marker: str | None = None,  # noqa: N803
                                          ) -> dict[str, Any]:
        self.calls.append("get_service_last_accessed_details")
        services = self.services.get(JobId, [])
        start = int(Marker or 0)
        page = services[start:start + 2]
        truncated = start + 2 < len(services)
        result: dict[str, Any] = {"JobStatus": "COMPLETED", "ServicesLastAccessed": page,
                                  "IsTruncated": truncated}
        if truncated:
            result["Marker"] = str(start + 2)
        return result


def generate_sample(out_dir: Path = Path("sample"), rotation_days: int = 90,
                    unused_days: int = 45) -> tuple[Path, Path]:
    """Run the full review against FakeIAM and write the sample outputs."""
    result = review(FakeIAM(), FAKE_NOW, rotation_days, unused_days, sleep=lambda _s: None)
    return write_outputs(out_dir, result, FAKE_NOW, rotation_days, unused_days)


if __name__ == "__main__":
    csv_path, md_path = generate_sample()
    print(f"Wrote {csv_path} and {md_path} from fake data")
