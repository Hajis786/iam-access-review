#!/usr/bin/env python3
"""Read-only AWS IAM access review.

Checks IAM users and the root user against rules mapped to the
CIS AWS Foundations Benchmark v3.0.0 and NIST CSF 2.0, then writes a CSV of
findings and a one-page Markdown report.

The tool calls only these IAM actions:
GenerateCredentialReport, GetCredentialReport, ListUsers, ListAttachedUserPolicies,
GenerateServiceLastAccessedDetails, GetServiceLastAccessedDetails.
"""
from __future__ import annotations

import argparse
import csv
import io
import logging
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

LOG = logging.getLogger("iam_review")

ROOT_USER = "<root_account>"
ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
NA_VALUES = frozenset({"", "N/A", "no_information", "not_supported"})
SEVERITY_ORDER = {"High": 0, "Medium": 1, "Info": 2}
CSV_FIELDS = ("user", "arn", "finding", "control", "severity")
POLL_SECONDS = 2.0
POLL_TIMEOUT_SECONDS = 300.0

# Control labels. CIS numbers follow CIS AWS Foundations Benchmark v3.0.0.
CTRL_ROOT_KEY = "CIS 1.4 / NIST PR.AA-03"      # No root user access key exists
CTRL_ROOT_MFA = "CIS 1.5 / NIST PR.AA-03"      # MFA enabled for the root user
CTRL_CONSOLE_MFA = "CIS 1.10 / NIST PR.AA-03"  # MFA for all users with a console password
CTRL_UNUSED = "CIS 1.12 / NIST PR.AA-05"       # Credentials unused 45 days are disabled
CTRL_ROTATION = "CIS 1.14 / NIST PR.AA-01"     # Access keys rotated every 90 days or less
CTRL_ADMIN = "CIS 1.16 / NIST PR.AA-05"        # No full "*:*" admin policy attached
# Not a CIS test. CIS 1.16 covers full admin rights, not unused services.
CTRL_UNUSED_SERVICES = "NIST PR.AA-05 (least-privilege check, no direct CIS test)"
# Not a control test. Flags users the credential report has not caught up with.
CTRL_COVERAGE = "Coverage gap (no control test)"

ACTIONS = {
    CTRL_ROOT_KEY: "Delete root access keys. Use IAM roles or users for programmatic access.",
    CTRL_ROOT_MFA: "Enable MFA on the root user, preferably a hardware or passkey device.",
    CTRL_CONSOLE_MFA: "Require MFA for every user with a console password.",
    CTRL_UNUSED: "Disable or remove passwords and access keys that are not in use.",
    CTRL_ROTATION: "Rotate access keys older than the rotation threshold, or replace them with roles.",
    CTRL_ADMIN: "Replace AdministratorAccess on users with scoped policies granted through groups or roles.",
    CTRL_UNUSED_SERVICES: "Remove permissions for services the identity does not use.",
    CTRL_COVERAGE: "Re-run after the credential report refreshes (AWS reuses a report for up to 4 hours).",
}


@dataclass(frozen=True)
class Finding:
    """One rule violation for one identity."""

    user: str
    arn: str
    finding: str
    control: str
    severity: str


# ---------------------------------------------------------------- date helpers

def parse_dt(value: str | None) -> datetime | None:
    """Parse a credential report timestamp. Return None for empty or N/A values."""
    if value is None or value.strip() in NA_VALUES:
        return None
    dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def days_since(dt: datetime | None, now: datetime) -> int | None:
    """Whole days from dt to now, or None when dt is None."""
    return None if dt is None else (now - dt).days


def reference_date(last_used: datetime | None, *created: datetime | None) -> datetime | None:
    """Last-used date if present, otherwise the first available creation date."""
    if last_used is not None:
        return last_used
    return next((dt for dt in created if dt is not None), None)


def is_true(value: str | None) -> bool:
    """True only for the credential report string 'true'."""
    return (value or "").strip().lower() == "true"


# ---------------------------------------------------------------------- rules

def check_root_access_key(row: dict[str, str]) -> list[Finding]:
    """Root has an active access key (CIS 1.4)."""
    if row["user"] != ROOT_USER:
        return []
    if is_true(row.get("access_key_1_active")) or is_true(row.get("access_key_2_active")):
        return [Finding(row["user"], row["arn"], "Root account has an active access key",
                        CTRL_ROOT_KEY, "High")]
    return []


def check_root_mfa(row: dict[str, str]) -> list[Finding]:
    """Root has no MFA (CIS 1.5)."""
    if row["user"] == ROOT_USER and not is_true(row.get("mfa_active")):
        return [Finding(row["user"], row["arn"], "Root account has no MFA", CTRL_ROOT_MFA, "High")]
    return []


def check_console_mfa(row: dict[str, str]) -> list[Finding]:
    """Console user without MFA (CIS 1.10)."""
    if row["user"] == ROOT_USER or not is_true(row.get("password_enabled")):
        return []
    if not is_true(row.get("mfa_active")):
        return [Finding(row["user"], row["arn"], "Console user without MFA", CTRL_CONSOLE_MFA, "High")]
    return []


def check_unused_password(row: dict[str, str], now: datetime, unused_days: int) -> list[Finding]:
    """Console password unused beyond unused_days (CIS 1.12).

    A never-used password is aged from password_last_changed, then user_creation_time.
    """
    if row["user"] == ROOT_USER or not is_true(row.get("password_enabled")):
        return []
    ref = reference_date(parse_dt(row.get("password_last_used")),
                         parse_dt(row.get("password_last_changed")),
                         parse_dt(row.get("user_creation_time")))
    age = days_since(ref, now)
    if age is not None and age > unused_days:
        return [Finding(row["user"], row["arn"], f"Console password unused over {unused_days} days",
                        CTRL_UNUSED, "Medium")]
    return []


def check_unused_keys(row: dict[str, str], now: datetime, unused_days: int) -> list[Finding]:
    """Active access key unused beyond unused_days (CIS 1.12).

    A never-used key is aged from its last-rotated (creation) date.
    """
    if row["user"] == ROOT_USER:
        return []
    findings = []
    for n in ("1", "2"):
        if not is_true(row.get(f"access_key_{n}_active")):
            continue
        ref = reference_date(parse_dt(row.get(f"access_key_{n}_last_used_date")),
                             parse_dt(row.get(f"access_key_{n}_last_rotated")))
        age = days_since(ref, now)
        if age is not None and age > unused_days:
            findings.append(Finding(row["user"], row["arn"],
                                    f"Access key {n} unused over {unused_days} days",
                                    CTRL_UNUSED, "Medium"))
    return findings


def check_key_rotation(row: dict[str, str], now: datetime, rotation_days: int) -> list[Finding]:
    """Active access key older than rotation_days (CIS 1.14)."""
    if row["user"] == ROOT_USER:
        return []
    findings = []
    for n in ("1", "2"):
        if not is_true(row.get(f"access_key_{n}_active")):
            continue
        age = days_since(parse_dt(row.get(f"access_key_{n}_last_rotated")), now)
        if age is not None and age > rotation_days:
            findings.append(Finding(row["user"], row["arn"],
                                    f"Access key {n} older than {rotation_days} days",
                                    CTRL_ROTATION, "Medium"))
    return findings


def check_admin_attached(row: dict[str, str], policy_arns: Iterable[str]) -> list[Finding]:
    """AdministratorAccess attached directly to the user (CIS 1.16)."""
    if row["user"] != ROOT_USER and ADMIN_POLICY_ARN in policy_arns:
        return [Finding(row["user"], row["arn"], "AdministratorAccess attached directly to user",
                        CTRL_ADMIN, "High")]
    return []


def check_unused_services(row: dict[str, str], services: Sequence[dict[str, Any]],
                          now: datetime, unused_days: int) -> list[Finding]:
    """Granted services unused beyond unused_days (NIST PR.AA-05, no direct CIS test).

    A never-used service is aged from user_creation_time.
    """
    created = parse_dt(row.get("user_creation_time"))
    stale = []
    for svc in services:
        age = days_since(reference_date(svc.get("LastAuthenticated"), created), now)
        if age is not None and age > unused_days:
            stale.append(svc["ServiceNamespace"])
    if not stale:
        return []
    shown = ", ".join(sorted(stale)[:5]) + (", ..." if len(stale) > 5 else "")
    return [Finding(row["user"], row["arn"],
                    f"{len(stale)} granted services unused over {unused_days} days: {shown}",
                    CTRL_UNUSED_SERVICES, "Medium")]


def evaluate_row(row: dict[str, str], now: datetime, rotation_days: int,
                 unused_days: int) -> list[Finding]:
    """Apply every credential-report rule to one row."""
    return [
        *check_root_access_key(row),
        *check_root_mfa(row),
        *check_console_mfa(row),
        *check_unused_password(row, now, unused_days),
        *check_key_rotation(row, now, rotation_days),
        *check_unused_keys(row, now, unused_days),
    ]


# ------------------------------------------------------------- AWS (read-only)

def _wait(start: float, timeout: float, what: str) -> None:
    """Raise TimeoutError once timeout seconds have passed since start."""
    if time.monotonic() - start > timeout:
        raise TimeoutError(f"Timed out after {timeout:.0f}s waiting for {what}")


def get_credential_report(iam: Any, sleep: Callable[[float], None] = time.sleep,
                          timeout: float = POLL_TIMEOUT_SECONDS,
                          ) -> tuple[list[dict[str, str]], datetime | None]:
    """Generate the credential report, poll until ready, and return its rows and GeneratedTime."""
    start = time.monotonic()
    while iam.generate_credential_report()["State"] != "COMPLETE":
        _wait(start, timeout, "the credential report")
        sleep(POLL_SECONDS)
    while True:
        try:
            report = iam.get_credential_report()
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "ReportInProgress":
                raise
            _wait(start, timeout, "the credential report")
            sleep(POLL_SECONDS)
    content = report["Content"]
    text = content.decode("utf-8") if isinstance(content, bytes) else content
    return list(csv.DictReader(io.StringIO(text))), report.get("GeneratedTime")


def list_users(iam: Any) -> list[dict[str, Any]]:
    """Return every IAM user (UserName, Arn) from the live ListUsers API."""
    paginator = iam.get_paginator("list_users")
    return [user for page in paginator.paginate() for user in page["Users"]]


def check_missing_from_report(row: dict[str, str]) -> list[Finding]:
    """User exists in IAM but not in the credential report (coverage gap, not a control)."""
    return [Finding(row["user"], row["arn"],
                    "Not in credential report yet. Credential rules skipped until it refreshes",
                    CTRL_COVERAGE, "Info")]


def list_attached_policy_arns(iam: Any, user: str) -> list[str]:
    """Return ARNs of managed policies attached directly to the user."""
    paginator = iam.get_paginator("list_attached_user_policies")
    return [policy["PolicyArn"]
            for page in paginator.paginate(UserName=user)
            for policy in page["AttachedPolicies"]]


def get_services_last_accessed(iam: Any, arn: str, sleep: Callable[[float], None] = time.sleep,
                               timeout: float = POLL_TIMEOUT_SECONDS) -> list[dict[str, Any]] | None:
    """Return service last-accessed entries for an identity, or None if the job failed.

    boto3 has no paginator for this call, so pages are followed with Marker.
    """
    job_id = iam.generate_service_last_accessed_details(Arn=arn)["JobId"]
    start = time.monotonic()
    while True:
        page = iam.get_service_last_accessed_details(JobId=job_id)
        if page["JobStatus"] != "IN_PROGRESS":
            break
        _wait(start, timeout, f"service last-accessed job for {arn}")
        sleep(POLL_SECONDS)
    if page["JobStatus"] == "FAILED":
        LOG.warning("Service last-accessed job failed for %s: %s",
                    arn, page.get("Error", {}).get("Message", "no reason given"))
        return None
    services = list(page.get("ServicesLastAccessed", []))
    while page.get("IsTruncated"):
        page = iam.get_service_last_accessed_details(JobId=job_id, Marker=page["Marker"])
        services.extend(page.get("ServicesLastAccessed", []))
    return services


@dataclass(frozen=True)
class ReviewResult:
    """Findings plus the facts the report header needs."""

    findings: list[Finding]
    identity_count: int
    report_time: datetime | None


def review(iam: Any, now: datetime, rotation_days: int, unused_days: int,
           permissions: bool = False, sleep: Callable[[float], None] = time.sleep,
           ) -> ReviewResult:
    """Run every rule against the account and return sorted findings.

    Users that exist in IAM but not yet in the credential report are flagged as a
    coverage gap and still get the live AdministratorAccess and services checks.
    """
    rows, report_time = get_credential_report(iam, sleep=sleep)
    reported = {row["user"] for row in rows}
    missing = [{"user": u["UserName"], "arn": u["Arn"],
                "user_creation_time": u["CreateDate"].isoformat()}
               for u in list_users(iam) if u["UserName"] not in reported]
    findings: list[Finding] = []
    for row in rows:
        findings += evaluate_row(row, now, rotation_days, unused_days)
    for row in missing:
        findings += check_missing_from_report(row)
    for row in rows + missing:
        if row["user"] == ROOT_USER:
            continue
        findings += check_admin_attached(row, list_attached_policy_arns(iam, row["user"]))
        if permissions:
            services = get_services_last_accessed(iam, row["arn"], sleep=sleep)
            if services is not None:
                findings += check_unused_services(row, services, now, unused_days)
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.user, f.finding))
    return ReviewResult(findings, len(rows) + len(missing), report_time)


# ------------------------------------------------------------------- output

def write_csv(path: Path, findings: Sequence[Finding]) -> None:
    """Write findings to CSV with columns user, arn, finding, control, severity."""
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(asdict(f) for f in findings)


def _md(text: str) -> str:
    """Escape characters that break a Markdown table cell."""
    return text.replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def build_report(findings: Sequence[Finding], identity_count: int, now: datetime,
                 rotation_days: int, unused_days: int, report_time: datetime | None) -> str:
    """Return the one-page Markdown report."""
    counts = {sev: sum(f.severity == sev for f in findings) for sev in SEVERITY_ORDER}
    lines = [
        "# IAM Access Review",
        "",
        f"- Run: {now:%Y-%m-%d %H:%M} UTC",
        "- Credential report generated: "
        + (f"{report_time.astimezone(timezone.utc):%Y-%m-%d %H:%M} UTC "
           f"({max(0, int((now - report_time).total_seconds() // 60))} min before run)"
           if report_time else "unknown"),
        f"- Scope: {identity_count} identities (IAM users and root)",
        f"- Thresholds: access keys older than {rotation_days} days; "
        f"credentials unused over {unused_days} days",
        "- Benchmark: CIS AWS Foundations Benchmark v3.0.0, NIST CSF 2.0",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
        *(f"| {sev} | {n} |" for sev, n in counts.items()),
        f"| **Total** | **{len(findings)}** |",
        "",
        "## Findings",
        "",
    ]
    if findings:
        lines += ["| Severity | Identity | Finding | Control |", "|---|---|---|---|"]
        lines += [f"| {f.severity} | {_md(f.user)} | {_md(f.finding)} | {_md(f.control)} |"
                  for f in findings]
    else:
        lines.append("No findings.")
    lines += ["", "## Recommended actions", ""]
    lines += [f"- {action}" for ctrl, action in ACTIONS.items()
              if any(f.control == ctrl for f in findings)]
    lines.append("- Confirm each finding with the identity owner before changing anything.")
    return "\n".join(lines) + "\n"


def write_outputs(out_dir: Path, result: ReviewResult, now: datetime,
                  rotation_days: int, unused_days: int) -> tuple[Path, Path]:
    """Create out_dir if needed and write iam_review.csv and iam_review.md."""
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path, md_path = out_dir / "iam_review.csv", out_dir / "iam_review.md"
    write_csv(csv_path, result.findings)
    md_path.write_text(build_report(result.findings, result.identity_count, now, rotation_days,
                                    unused_days, result.report_time), encoding="utf-8")
    return csv_path, md_path


# ---------------------------------------------------------------------- CLI

def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    ap = argparse.ArgumentParser(description="Read-only AWS IAM access review")
    ap.add_argument("--profile", help="AWS CLI profile to use, for example iam-audit")
    ap.add_argument("--rotation-days", type=int, default=90,
                    help="flag active access keys older than this many days (default 90)")
    ap.add_argument("--unused-days", type=int, default=45,
                    help="flag credentials unused for more than this many days (default 45)")
    ap.add_argument("--permissions", action="store_true",
                    help="also flag granted services unused for --unused-days (slower)")
    ap.add_argument("--out-dir", type=Path, default=Path("output"),
                    help="folder for iam_review.csv and iam_review.md (default output/)")
    return ap.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point: run the review and write the outputs."""
    import boto3

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = parse_args(argv)
    iam = boto3.Session(profile_name=args.profile).client("iam")
    now = datetime.now(timezone.utc)
    result = review(iam, now, args.rotation_days, args.unused_days, args.permissions)
    csv_path, md_path = write_outputs(args.out_dir, result, now,
                                      args.rotation_days, args.unused_days)
    LOG.info("Checked %d identities. %d findings written to %s and %s",
             result.identity_count, len(result.findings), csv_path, md_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
