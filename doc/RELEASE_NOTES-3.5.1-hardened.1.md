# Release Notes: xxl-job-hardened 3.5.1-hardened.1

| | |
|---|---|
| Version | `3.5.1-hardened.1` |
| Status | **Release candidate**: approved for staging. Production release after the staging pentest (see "Release status"). |
| Base | Upstream XXL-JOB `3.5.1-SNAPSHOT` (commit `693d2764`) |
| Requirements | JDK 17, MySQL 8.x, Spring Boot 4 (admin) |
| Artifacts | `com.xuxueli:xxl-job-core:3.5.1-hardened.1`, `xxl-job-admin-3.5.1-hardened.1.jar`, images `xxl-job-admin:3.5.1-hardened.1`, `xxl-job-executor-sample-springboot:3.5.1-hardened.1` |
| Documents | [HARDENING.md](HARDENING.md) (configuration, events, detection), [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md) (replacing existing XXL-JOB), [CHANGELOG.md](../CHANGELOG.md) |

## Why this release

XXL-JOB executes code on executors by design: GLUE jobs ship Shell, Python, Groovy and other scripts from the admin to every executor. A compromised admin account or a leaked executor token is therefore remote code execution on every executor, which usually holds database, cache, internal API and cloud credentials. That makes XXL-JOB a frequent target in enterprise intrusions.

This release removes that execution path, closes the token and registration weaknesses that make it reachable, and adds the visibility needed to detect attempts and investigate past compromise. Changes are minimal: no UI and no database schema changes, and normal BEAN jobs work as before.

## Highlights

**Remote code execution path removed**
- GLUE is rejected on both the admin and the executor, through every API, including GLUE jobs already in the database.
- Executors run only BEAN handlers, optionally limited by an allowlist. The dangerous sample handlers `commandJobHandler` and `httpJobHandler` are denied by default.

**Token and access hardening**
- Fixed a token disclosure: any logged-in user could read every executor group's token through `/jobgroup/loadById`.
- Weak and default tokens (`default_token`, or anything under 32 chars) are rejected everywhere.
- The executor token can no longer create or modify jobs through the OpenAPI (disabled by default).
- Executors can only register into their own group, from allowed networks.
- Manual triggers can no longer be pointed at arbitrary hosts (token theft and SSRF).
- The default admin password `123456` blocks startup until reset; brute-force lockout per username + source IP and per source IP, which cannot be released by flooding the lockout table.

**Detection and visibility**
- Security event log with severity, a tamper-evident hash chain, and webhook alerting.
- Inspection of job payloads with your SOC's rules, with evidence capture: rejected GLUE payloads show what an attacker tried to run and are a sign of compromise elsewhere.
- Canary tokens, exploit and scanner fingerprints, brute-force detection, audit of user and executor-group changes, and an inventory of GLUE jobs at startup.
- Admin posture endpoint and Prometheus metrics.

**Deployment**
- Non-root images, a hardened reference compose deployment, and Kubernetes reference NetworkPolicy and pod security settings.

## Breaking changes

All hardening fails closed. Plan for the following before upgrading:

| Change | Impact | Action |
|---|---|---|
| GLUE disabled | GLUE jobs stop running; their trigger fails with an error in the job log. | Rewrite them as reviewed BEAN handlers before the upgrade. |
| Weak tokens rejected | Executors with `default_token` or short tokens will not start; groups with weak tokens cannot trigger. | Rotate every group token to a 32+ char value and deploy it to the executors. |
| Default admin password | Admin will not start while `admin/123456` is in use. | Start once with `XXL_JOB_SECURITY_INIT_ADMIN_PASSWORD`, then remove it. |
| OpenAPI job management off | External systems calling `addJob` / `updateJob` / `removeJob` / `startJob` / `stopJob` / `triggerJob` get an error. | Move those integrations to the admin UI, or explicitly set `xxl.job.openapi.job-manage.enabled=true` (alerts as risky config). |
| Sample handlers denied | `commandJobHandler` and `httpJobHandler` jobs fail. | Replace with purpose-built handlers, or allowlist explicitly (not recommended). |
| Executor-side protection lives in the core library | Upgrading only the admin leaves old executors accepting GLUE. | Rebuild every executor application against `xxl-job-core:3.5.1-hardened.1`. |
| HTTP probes on the executor port | Raise `EXECUTOR_SCAN` (HIGH) alerts. | Use TCP probes on the executor port. |

## Compatibility

- **Database**: schema identical to upstream 3.5.x. No migration script for this release (older upstream versions: see the migration guide).
- **Protocol**: identical to upstream 3.5.x; hardened admin and executors must both be 3.5.x, and both should be the hardened build.
- **Executor API**: `@XxlJob` handlers and `XxlJobSpringExecutor` / `XxlJobSimpleExecutor` setup are unchanged. `setGlueEnabled(...)` is still accepted but ignored; `setHandlerAllowlist(...)` is new.

## Release status and verification

| Verification | Result |
|---|---|
| Build (JDK 17, all modules) | Pass |
| Unit tests (`SecurityToolTest`, `ThreatDetectorTest`, `LoginAttemptGuardTest`) | 18 / 18 pass |
| Deployment and functional test in Docker (`docker/e2e/run_deploy_test.sh`): startup guards, token handling, registration, BEAN job round trip, posture / metrics, alerting, container hardening, log integrity | 47 / 47 pass |
| Attack-path validation (pentest in staging) | **Pending; required before the production release** |

Production release criteria:
1. Staging pentest completed with no open blocking findings, including proof on the executor host that rejected payloads never execute.
2. Every executor application rebuilt against the hardened core.
3. Network restriction (only admin can reach the executor port) applied and verified with a real connection test.

## Known limitations

- Login lockout and brute-force state are in memory per admin instance.
- Unsalted SHA-256 password hashing, no SSO/MFA, upstream admin/user role model.
- One token per executor group shared for executor auth, registry and OpenAPI; no rotation overlap window; no mTLS between admin and executor.
- Network and runtime hardening must be enforced by your infrastructure.
- The payload rules file ships empty: detection quality depends on the SOC's rules.

## Upgrade

Follow [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md). In short: preserve evidence, port GLUE jobs, rotate tokens, rebuild executors, deploy admin and executors in the same window, apply the network policy, switch on SOC alerting.
