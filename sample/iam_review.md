# IAM Access Review

- Run: 2026-06-30 12:00 UTC
- Credential report generated: 2026-06-30 10:25 UTC (95 min before run)
- Scope: 10 identities (IAM users and root)
- Thresholds: access keys older than 90 days; credentials unused over 45 days
- Benchmark: CIS AWS Foundations Benchmark v3.0.0, NIST CSF 2.0

## Summary

| Severity | Count |
|---|---|
| High | 5 |
| Medium | 4 |
| Info | 1 |
| **Total** | **10** |

## Findings

| Severity | Identity | Finding | Control |
|---|---|---|---|
| High | &lt;root_account&gt; | Root account has an active access key | CIS 1.4 / NIST PR.AA-03 |
| High | admin-you | AdministratorAccess attached directly to user | CIS 1.16 / NIST PR.AA-05 |
| High | test-admin | AdministratorAccess attached directly to user | CIS 1.16 / NIST PR.AA-05 |
| High | test-late | AdministratorAccess attached directly to user | CIS 1.16 / NIST PR.AA-05 |
| High | test-nomfa | Console user without MFA | CIS 1.10 / NIST PR.AA-03 |
| Medium | svc-legacy | Access key 1 older than 90 days | CIS 1.14 / NIST PR.AA-01 |
| Medium | test-idle | Access key 1 older than 90 days | CIS 1.14 / NIST PR.AA-01 |
| Medium | test-idle | Access key 1 unused over 45 days | CIS 1.12 / NIST PR.AA-05 |
| Medium | test-nomfa | Console password unused over 45 days | CIS 1.12 / NIST PR.AA-05 |
| Info | test-late | Not in credential report yet. Credential rules skipped until it refreshes | Coverage gap (no control test) |

## Recommended actions

- Delete root access keys. Use IAM roles or users for programmatic access.
- Require MFA for every user with a console password.
- Disable or remove passwords and access keys that are not in use.
- Rotate access keys older than the rotation threshold, or replace them with roles.
- Replace AdministratorAccess on users with scoped policies granted through groups or roles.
- Re-run after the credential report refreshes (AWS reuses a report for up to 4 hours).
- Confirm each finding with the identity owner before changing anything.
