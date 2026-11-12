"""Unit tests for iam_review. No test calls AWS."""
from __future__ import annotations

import csv
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

import iam_review as ir
from fixtures import (ACCOUNT, FAKE_NOW, FAKE_REPORT_TIME, FakeIAM, ago, generate_sample,
                      make_row)

NOW = FAKE_NOW
NO_SLEEP = lambda _s: None  # noqa: E731

READ_ONLY_CALLS = {
    "generate_credential_report", "get_credential_report",
    "list_users", "list_attached_user_policies",
    "generate_service_last_accessed_details", "get_service_last_accessed_details",
}


def root_row(**values: str) -> dict[str, str]:
    """Root row with MFA on and no keys unless overridden."""
    base = {"arn": f"arn:aws:iam::{ACCOUNT}:root", "password_enabled": "not_supported",
            "mfa_active": "true"}
    return make_row("<root_account>", **{**base, **values})


# ---------------------------------------------------------------- date helpers

@pytest.mark.parametrize("value", ["", "N/A", "no_information", "not_supported", None, "  N/A "])
def test_parse_dt_returns_none_for_empty_values(value: str | None) -> None:
    assert ir.parse_dt(value) is None


@pytest.mark.parametrize("value", ["2026-06-01T08:30:00+00:00", "2026-06-01T08:30:00Z"])
def test_parse_dt_parses_iso_timestamps(value: str) -> None:
    assert ir.parse_dt(value) == datetime(2026, 6, 1, 8, 30, tzinfo=timezone.utc)


def test_parse_dt_assumes_utc_when_naive() -> None:
    assert ir.parse_dt("2026-06-01T08:30:00").tzinfo == timezone.utc


def test_days_since() -> None:
    assert ir.days_since(NOW - timedelta(days=10, hours=5), NOW) == 10
    assert ir.days_since(None, NOW) is None


def test_reference_date_prefers_last_used_then_first_creation_date() -> None:
    used, changed, created = NOW, NOW - timedelta(days=5), NOW - timedelta(days=9)
    assert ir.reference_date(used, changed, created) == used
    assert ir.reference_date(None, changed, created) == changed
    assert ir.reference_date(None, None, created) == created
    assert ir.reference_date(None, None, None) is None


# --------------------------------------------------------------- root rules

def test_root_active_access_key_flagged() -> None:
    findings = ir.check_root_access_key(root_row(access_key_2_active="true"))
    assert [(f.control, f.severity) for f in findings] == [("CIS 1.4 / NIST PR.AA-03", "High")]


def test_root_without_keys_passes() -> None:
    assert ir.check_root_access_key(root_row()) == []


def test_root_without_mfa_flagged() -> None:
    findings = ir.check_root_mfa(root_row(mfa_active="false"))
    assert [(f.control, f.severity) for f in findings] == [("CIS 1.5 / NIST PR.AA-03", "High")]


def test_root_with_mfa_passes() -> None:
    assert ir.check_root_mfa(root_row()) == []


def test_root_rules_ignore_normal_users() -> None:
    row = make_row("bob", access_key_1_active="true", access_key_1_last_rotated=ago(1))
    assert ir.check_root_access_key(row) == [] and ir.check_root_mfa(row) == []


def test_user_rules_skip_root() -> None:
    row = root_row(mfa_active="false", access_key_1_active="true",
                   access_key_1_last_rotated=ago(400))
    assert ir.check_console_mfa(row) == []
    assert ir.check_key_rotation(row, NOW, 90) == []
    assert ir.check_unused_keys(row, NOW, 45) == []
    assert ir.check_unused_password(row, NOW, 45) == []


# ------------------------------------------------------------- console MFA

def test_console_user_without_mfa_flagged() -> None:
    findings = ir.check_console_mfa(make_row("bob", password_enabled="true"))
    assert [(f.control, f.severity) for f in findings] == [("CIS 1.10 / NIST PR.AA-03", "High")]


def test_console_user_with_mfa_passes() -> None:
    assert ir.check_console_mfa(make_row("bob", password_enabled="true", mfa_active="true")) == []


def test_user_without_password_skips_console_mfa() -> None:
    assert ir.check_console_mfa(make_row("bob")) == []


# --------------------------------------------------------- unused password

def test_password_used_long_ago_flagged() -> None:
    row = make_row("bob", password_enabled="true", password_last_used=ago(46))
    findings = ir.check_unused_password(row, NOW, 45)
    assert [(f.control, f.severity) for f in findings] == [("CIS 1.12 / NIST PR.AA-05", "Medium")]


def test_password_used_recently_passes() -> None:
    row = make_row("bob", password_enabled="true", password_last_used=ago(45))
    assert ir.check_unused_password(row, NOW, 45) == []


def test_never_used_password_uses_creation_date() -> None:
    new = make_row("new", password_enabled="true", password_last_used="no_information",
                   password_last_changed=ago(10), user_creation_time=ago(10))
    old = make_row("old", password_enabled="true", password_last_used="N/A",
                   password_last_changed=ago(60), user_creation_time=ago(60))
    assert ir.check_unused_password(new, NOW, 45) == []
    assert len(ir.check_unused_password(old, NOW, 45)) == 1


def test_never_used_password_falls_back_to_user_creation_time() -> None:
    row = make_row("bob", password_enabled="true", password_last_used="N/A",
                   password_last_changed="N/A", user_creation_time=ago(50))
    assert len(ir.check_unused_password(row, NOW, 45)) == 1


def test_negative_unused_days_flags_new_password() -> None:
    row = make_row("bob", password_enabled="true", password_last_used="N/A",
                   password_last_changed=ago(0), user_creation_time=ago(0))
    assert len(ir.check_unused_password(row, NOW, -1)) == 1


# -------------------------------------------------------------- unused keys

def test_key_used_long_ago_flagged() -> None:
    row = make_row("bob", access_key_1_active="true", access_key_1_last_rotated=ago(100),
                   access_key_1_last_used_date=ago(50))
    findings = ir.check_unused_keys(row, NOW, 45)
    assert [(f.finding, f.control) for f in findings] == [
        ("Access key 1 unused over 45 days", "CIS 1.12 / NIST PR.AA-05")]


def test_never_used_key_uses_creation_date() -> None:
    new = make_row("new", access_key_1_active="true", access_key_1_last_rotated=ago(3),
                   access_key_1_last_used_date="N/A")
    old = make_row("old", access_key_2_active="true", access_key_2_last_rotated=ago(46),
                   access_key_2_last_used_date="N/A")
    assert ir.check_unused_keys(new, NOW, 45) == []
    assert [f.finding for f in ir.check_unused_keys(old, NOW, 45)] == [
        "Access key 2 unused over 45 days"]


def test_inactive_key_ignored() -> None:
    row = make_row("bob", access_key_1_active="false", access_key_1_last_rotated=ago(500),
                   access_key_1_last_used_date=ago(400))
    assert ir.check_unused_keys(row, NOW, 45) == []
    assert ir.check_key_rotation(row, NOW, 90) == []


# ------------------------------------------------------------- key rotation

def test_old_key_flagged_for_rotation() -> None:
    row = make_row("bob", access_key_1_active="true", access_key_1_last_rotated=ago(91),
                   access_key_2_active="true", access_key_2_last_rotated=ago(90))
    findings = ir.check_key_rotation(row, NOW, 90)
    assert [(f.finding, f.control, f.severity) for f in findings] == [
        ("Access key 1 older than 90 days", "CIS 1.14 / NIST PR.AA-01", "Medium")]


def test_key_rotation_handles_missing_date() -> None:
    row = make_row("bob", access_key_1_active="true", access_key_1_last_rotated="N/A")
    assert ir.check_key_rotation(row, NOW, 90) == []


# ------------------------------------------------------------------- admin

def test_admin_policy_attached_flagged() -> None:
    findings = ir.check_admin_attached(make_row("bob"), [ir.ADMIN_POLICY_ARN])
    assert [(f.control, f.severity) for f in findings] == [("CIS 1.16 / NIST PR.AA-05", "High")]


def test_custom_policy_with_similar_name_not_flagged() -> None:
    arn = f"arn:aws:iam::{ACCOUNT}:policy/MyAdministratorAccess"
    assert ir.check_admin_attached(make_row("bob"), [arn]) == []


# --------------------------------------------------------- unused services

def test_unused_services_flagged_with_nist_only_label() -> None:
    row = make_row("bob", user_creation_time=ago(365))
    services = [
        {"ServiceNamespace": "s3", "LastAuthenticated": NOW - timedelta(days=1)},
        {"ServiceNamespace": "ec2", "LastAuthenticated": NOW - timedelta(days=60)},
        {"ServiceNamespace": "lambda"},
    ]
    (finding,) = ir.check_unused_services(row, services, NOW, 45)
    assert finding.control == "NIST PR.AA-05 (least-privilege check, no direct CIS test)"
    assert "CIS" not in finding.control.split("(")[0]
    assert finding.finding == "2 granted services unused over 45 days: ec2, lambda"
    assert finding.severity == "Medium"


def test_never_used_services_on_new_user_not_flagged() -> None:
    row = make_row("bob", user_creation_time=ago(5))
    assert ir.check_unused_services(row, [{"ServiceNamespace": "s3"}], NOW, 45) == []


# --------------------------------------------------------- row-level checks

def test_identity_without_password_or_keys_has_no_findings() -> None:
    assert ir.evaluate_row(make_row("empty"), NOW, 90, 45) == []


def test_na_and_no_information_values_do_not_crash() -> None:
    row = {col: "N/A" for col in make_row("x")} | {"user": "x", "arn": "arn:x",
                                                  "password_enabled": "true",
                                                  "password_last_used": "no_information",
                                                  "access_key_1_active": "true"}
    findings = ir.evaluate_row(row, NOW, 90, 45)
    assert [f.finding for f in findings] == ["Console user without MFA"]


# -------------------------------------------------------- AWS interactions

def test_credential_report_polls_until_complete() -> None:
    iam = MagicMock()
    iam.generate_credential_report.side_effect = [
        {"State": "STARTED"}, {"State": "INPROGRESS"}, {"State": "COMPLETE"}]
    iam.get_credential_report.return_value = {"Content": b"user,arn\nbob,arn:b\n",
                                              "GeneratedTime": FAKE_REPORT_TIME}
    sleeps: list[float] = []
    rows, generated = ir.get_credential_report(iam, sleep=sleeps.append)
    assert rows == [{"user": "bob", "arn": "arn:b"}]
    assert generated == FAKE_REPORT_TIME
    assert len(sleeps) == 2


def test_credential_report_retries_report_in_progress() -> None:
    iam = MagicMock()
    iam.generate_credential_report.return_value = {"State": "COMPLETE"}
    busy = ClientError({"Error": {"Code": "ReportInProgress", "Message": "busy"}},
                       "GetCredentialReport")
    iam.get_credential_report.side_effect = [busy, {"Content": b"user,arn\n"}]
    assert ir.get_credential_report(iam, sleep=NO_SLEEP) == ([], None)


def test_credential_report_reraises_other_errors() -> None:
    iam = MagicMock()
    iam.generate_credential_report.return_value = {"State": "COMPLETE"}
    iam.get_credential_report.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetCredentialReport")
    with pytest.raises(ClientError):
        ir.get_credential_report(iam, sleep=NO_SLEEP)


def test_credential_report_times_out() -> None:
    iam = MagicMock()
    iam.generate_credential_report.return_value = {"State": "INPROGRESS"}
    with pytest.raises(TimeoutError):
        ir.get_credential_report(iam, sleep=NO_SLEEP, timeout=-1)


def test_attached_policies_use_paginator() -> None:
    iam = MagicMock()
    iam.get_paginator.return_value.paginate.return_value = [
        {"AttachedPolicies": [{"PolicyArn": "arn:a"}]},
        {"AttachedPolicies": [{"PolicyArn": ir.ADMIN_POLICY_ARN}]},
    ]
    assert ir.list_attached_policy_arns(iam, "bob") == ["arn:a", ir.ADMIN_POLICY_ARN]
    iam.get_paginator.assert_called_once_with("list_attached_user_policies")
    iam.get_paginator.return_value.paginate.assert_called_once_with(UserName="bob")


def test_service_job_failed_returns_none_and_logs(caplog: pytest.LogCaptureFixture) -> None:
    iam = MagicMock()
    iam.generate_service_last_accessed_details.return_value = {"JobId": "j1"}
    iam.get_service_last_accessed_details.side_effect = [
        {"JobStatus": "IN_PROGRESS"},
        {"JobStatus": "FAILED", "Error": {"Message": "boom"}},
    ]
    with caplog.at_level(logging.WARNING, logger="iam_review"):
        assert ir.get_services_last_accessed(iam, "arn:x", sleep=NO_SLEEP) is None
    assert "boom" in caplog.text


def test_service_details_follow_marker_pages() -> None:
    iam = MagicMock()
    iam.generate_service_last_accessed_details.return_value = {"JobId": "j1"}
    iam.get_service_last_accessed_details.side_effect = [
        {"JobStatus": "COMPLETED", "ServicesLastAccessed": [{"ServiceNamespace": "s3"}],
         "IsTruncated": True, "Marker": "m1"},
        {"JobStatus": "COMPLETED", "ServicesLastAccessed": [{"ServiceNamespace": "ec2"}],
         "IsTruncated": False},
    ]
    services = ir.get_services_last_accessed(iam, "arn:x", sleep=NO_SLEEP)
    assert [s["ServiceNamespace"] for s in services] == ["s3", "ec2"]
    iam.get_service_last_accessed_details.assert_called_with(JobId="j1", Marker="m1")


# ----------------------------------------------------------- end to end

def test_list_users_uses_paginator() -> None:
    iam = MagicMock()
    iam.get_paginator.return_value.paginate.return_value = [
        {"Users": [{"UserName": "a"}]}, {"Users": [{"UserName": "b"}]}]
    assert [u["UserName"] for u in ir.list_users(iam)] == ["a", "b"]
    iam.get_paginator.assert_called_once_with("list_users")


def test_review_end_to_end_with_fake_account() -> None:
    iam = FakeIAM()
    result = ir.review(iam, NOW, 90, 45, sleep=NO_SLEEP)
    findings = result.findings
    got = {(f.user, f.finding) for f in findings}
    assert result.identity_count == 10
    assert result.report_time == FAKE_REPORT_TIME
    assert got == {
        ("test-late", "Not in credential report yet. Credential rules skipped until it refreshes"),
        ("test-late", "AdministratorAccess attached directly to user"),
        ("<root_account>", "Root account has an active access key"),
        ("admin-you", "AdministratorAccess attached directly to user"),
        ("test-admin", "AdministratorAccess attached directly to user"),
        ("test-nomfa", "Console user without MFA"),
        ("test-nomfa", "Console password unused over 45 days"),
        ("test-idle", "Access key 1 older than 90 days"),
        ("test-idle", "Access key 1 unused over 45 days"),
        ("svc-legacy", "Access key 1 older than 90 days"),
    }
    assert [f.severity for f in findings] == sorted(
        (f.severity for f in findings), key=ir.SEVERITY_ORDER.get)


def test_review_with_permissions_adds_unused_services() -> None:
    result = ir.review(FakeIAM(), NOW, 90, 45, permissions=True, sleep=NO_SLEEP)
    unused = [f for f in result.findings if f.control == ir.CTRL_UNUSED_SERVICES]
    assert [(f.user, f.finding) for f in unused] == [
        ("admin-you", "2 granted services unused over 45 days: ec2, s3")]


def test_user_missing_from_report_is_info_coverage_gap() -> None:
    result = ir.review(FakeIAM(rows=[]), NOW, 90, 45, sleep=NO_SLEEP)
    gaps = [f for f in result.findings if f.control == ir.CTRL_COVERAGE]
    assert [(f.user, f.severity) for f in gaps] == [("test-late", "Info")]
    assert result.findings[-1].severity == "Info"


def test_no_coverage_gap_when_report_is_current() -> None:
    result = ir.review(FakeIAM(late_users=[]), NOW, 90, 45, sleep=NO_SLEEP)
    assert all(f.control != ir.CTRL_COVERAGE for f in result.findings)


def test_review_makes_only_read_only_calls() -> None:
    iam = FakeIAM()
    ir.review(iam, NOW, 90, 45, permissions=True, sleep=NO_SLEEP)
    called = {c.split(":")[-1] for c in iam.calls}
    assert called <= READ_ONLY_CALLS


def test_source_calls_only_allowed_iam_actions() -> None:
    source = Path(ir.__file__).read_text(encoding="utf-8")
    methods = set(re.findall(r"\biam\.(\w+)\(", source))
    paginated = set(re.findall(r'get_paginator\("(\w+)"\)', source))
    assert (methods - {"get_paginator"}) | paginated <= READ_ONLY_CALLS


# ------------------------------------------------------------------ output

def test_write_outputs_creates_folder_csv_and_report(tmp_path: Path) -> None:
    result = ir.review(FakeIAM(), NOW, 90, 45, sleep=NO_SLEEP)
    csv_path, md_path = ir.write_outputs(tmp_path / "output", result, NOW, 90, 45)
    with csv_path.open(newline="") as fh:
        reader = csv.DictReader(fh)
        assert tuple(reader.fieldnames) == ir.CSV_FIELDS
        assert len(list(reader)) == len(result.findings)
    report = md_path.read_text()
    for heading in ("## Summary", "## Findings", "## Recommended actions"):
        assert heading in report
    assert "| High | 5 |" in report and "| Medium | 4 |" in report and "| Info | 1 |" in report
    assert "- Credential report generated: 2026-06-30 10:25 UTC (95 min before run)" in report
    assert "&lt;root_account&gt;" in report
    assert "CIS AWS Foundations Benchmark v3.0.0" in report


def test_report_with_no_findings() -> None:
    report = ir.build_report([], 1, NOW, 90, 45, None)
    assert "No findings." in report and "| **Total** | **0** |" in report
    assert "- Credential report generated: unknown" in report


def test_sample_generator_writes_files(tmp_path: Path) -> None:
    csv_path, md_path = generate_sample(tmp_path)
    assert csv_path.exists() and md_path.exists()


def test_parse_args_defaults() -> None:
    args = ir.parse_args([])
    assert (args.rotation_days, args.unused_days, args.permissions) == (90, 45, False)
    assert args.out_dir == Path("output")


def test_parse_args_accepts_negative_demo_thresholds() -> None:
    args = ir.parse_args(["--unused-days", "-1", "--rotation-days", "-1"])
    assert (args.rotation_days, args.unused_days) == (-1, -1)
