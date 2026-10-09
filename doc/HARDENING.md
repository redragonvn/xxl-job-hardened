# XXL-JOB Hardened Build

Minimal-change fork of XXL-JOB 3.5.1-SNAPSHOT. No UI or database schema changes. All hardening is enforced on the backend and **fails closed**.

## 1. What changed

| Area | Change | Where |
|---|---|---|
| GLUE (Executor) | Every non-BEAN trigger is rejected. `glueEnabled=true` is ignored. The Groovy loader and the script handler throw if they are ever reached. | `ExecutorBizImpl`, `XxlJobExecutor`, `GlueFactory`, `ScriptJobHandler` |
| GLUE (Admin) | Creating a non-BEAN job is rejected for both the web UI and the OpenAPI. `/jobcode/save` is disabled. GLUE jobs already in the database are never dispatched; their job log shows a failure. | `XxlJobServiceImpl.add`, `JobCodeController.save`, `JobTrigger` |
| Handler allowlist | `xxl.job.executor.handlerallowlist` sets which BEAN handlers may run. The sample handlers `commandJobHandler` (OS command) and `httpJobHandler` (SSRF) are always denied unless explicitly allowlisted. | `XxlJobExecutor.isHandlerAllowed` |
| Token strength | Tokens that are blank, `default_token`, a known default, or shorter than 32 chars are rejected: the executor refuses to start, and the admin refuses to trigger, accept OpenAPI calls, or save the group. | `SecurityTool.isWeakToken` |
| Token compare | Constant-time comparison (`MessageDigest.isEqual`). | `EmbedServer`, `OpenApiController`, `LoginController` |
| Token exposure | `/jobgroup/loadById` now checks group permission and never returns `accessToken`. `XxlJobGroup.toString()` masks the token. | `JobGroupController`, `XxlJobGroup` |
| OpenAPI job management | `addJob / updateJob / removeJob / startJob / stopJob / triggerJob` are **disabled by default**, because they authenticate with the executor token that every executor host holds. | `OpenApiController`, `xxl.job.openapi.job-manage.enabled` |
| Executor registry | An executor can only register into **its own** group (`registryKey` == authenticated appname). The address must be http(s), and its host must match `xxl.job.registry.allowed-cidrs` if that is set. | `OpenApiController.validRegistry` |
| Manual trigger address | The `addressList` override must be a registered node of the group. Before, it could send the group token to any host (token theft and SSRF). | `XxlJobServiceImpl.trigger`, `JobTrigger` |
| Default admin | The admin refuses to start while user `admin` still has the default password `123456`, unless `xxl.job.security.init-admin-password` is provided to reset it. | `SecurityStartupCheck` |
| Login | Locks the account for 15 minutes after 5 failures. Success and failure are audited. | `LoginController` |
| Visibility | Security events go to the `xxl-job-security` logger and operation audit to the `xxl-job-audit` logger. The admin writes both to `xxl-job-admin-security.log`. Every event has a severity, a counter and a hash-chain field. | `SecurityTool`, `SecuritySeverity`, `logback.xml` |
| Detection | Payload inspection with SOC rules, evidence capture, canary tokens, exploit fingerprints, brute-force and scan detection, privileged-change audit, GLUE inventory at startup. See section 5. | `ThreatDetector`, `SecurityAuditFilter`, `SecurityStartupCheck` |
| Alerting / posture | Webhook alerts, an admin-only posture endpoint, and a Prometheus metrics endpoint. | `SecurityAlerter`, `SecurityController` |

## 2. Configuration

Admin (`application.properties`, or command-line arguments / env vars):

```properties
# one-time reset of default admin password; prefer env XXL_JOB_SECURITY_INIT_ADMIN_PASSWORD, remove after first start
xxl.job.security.init-admin-password=
# keep false unless an external system really needs job management via openapi
xxl.job.openapi.job-manage.enabled=false
# executor registry source allowlist (pod / node CIDR)
xxl.job.registry.allowed-cidrs=10.0.0.0/8
# alert webhook (POST json) for events >= min-severity
xxl.job.security.alert.webhook-url=https://soar.example.internal/hooks/xxl-job
xxl.job.security.alert.min-severity=HIGH
# SOC-maintained payload rules file (hot reload every 30s)
xxl.job.security.payload-rules=/etc/xxl-job/payload-rules.txt
# canary (honey) tokens, comma-separated
xxl.job.security.canary-tokens=
# bearer token (min 32 chars) for /security/metrics; blank disables the endpoint
xxl.job.security.metrics-token=
```

Executor (env vars, read directly by `xxl-job-core`, no code change needed in the executor app):

```properties
xxl.job.executor.accessToken=${XXL_JOB_ACCESS_TOKEN:}
xxl.job.executor.handlerallowlist=demoJobHandler,shardingJobHandler
```

| Env var | Purpose |
|---|---|
| `XXL_JOB_ACCESS_TOKEN` | Executor token (sample apps). |
| `XXL_JOB_SECURITY_ALERT_WEBHOOK` | Alert webhook URL. |
| `XXL_JOB_SECURITY_ALERT_MIN_SEVERITY` | Minimum alert severity, default `HIGH`. |
| `XXL_JOB_SECURITY_PAYLOAD_RULES` | Path to the payload rules file. |
| `XXL_JOB_SECURITY_CANARY_TOKENS` | Canary tokens, comma-separated. |

Log files (under `LOG_HOME`, default `/data/applogs`):

| File | Content | Access |
|---|---|---|
| `xxl-job/xxl-job-admin-security.log` | Admin security events and audit, with `remote` and `ua` | SIEM |
| `xxl-job/xxl-job-admin-evidence.log` | Full captured payloads (admin) | **IR team only** |
| `xxl-job/xxl-job-executor-security.log` | Executor security events (sample springboot logback) | SIEM |
| `xxl-job/xxl-job-executor-evidence.log` | Full captured payloads (executor) | **IR team only** |

Executor apps not based on the samples should add the `xxl-job-security` and `xxl-job-evidence` loggers to their own logback configuration (copy from `xxl-job-executor-sample-springboot/src/main/resources/logback.xml`).

## 3. Migration checklist

1. **Inventory GLUE jobs** before upgrading. They stop running after the upgrade. The hardened admin also reports them at startup (`ADMIN_GLUE_JOB_PRESENT`).
   ```sql
   SELECT id, job_group, name, author, glue_type, glue_updatetime, trigger_status FROM xxl_job_info WHERE glue_type <> 'BEAN';
   ```
   Rewrite each one as a reviewed BEAN handler. During IR, also review `xxl_job_logglue` (see section 5.4).
2. **Rotate every executor group token** to a random value of at least 32 chars, e.g. `echo t$(openssl rand -hex 24)` (49 chars). The UI only accepts `[a-z][a-z0-9_]*` up to 50 chars, so the token must start with a letter. Set it in Admin → Executor Management, and inject the same value into the executor through a Secret (`XXL_JOB_ACCESS_TOKEN`).
3. **Reset the default admin password**: start once with `XXL_JOB_SECURITY_INIT_ADMIN_PASSWORD`, then remove the variable.
4. Set `xxl.job.registry.allowed-cidrs` to the executor network.
5. Set `xxl.job.executor.handlerallowlist` on each executor.
6. Ship the security logs to the SIEM, restrict the evidence logs to the IR team, and configure the alert webhook.
7. Deploy the payload rules file from the SOC's detection content, and plant canary tokens (section 5.2).

## 4. Security events (SIEM)

Format (one line, logger `xxl-job-security`, level WARN):

```
severity=<LEVEL> event=<TYPE> key="value" ... seq=<n> chain=<16 hex>
```

| Event | Severity | Meaning / suggested response |
|---|---|---|
| `CANARY_TOKEN_USED` | CRITICAL | A decoy token was presented. The place it was planted has leaked: confirmed compromise. |
| `EXPLOIT_DEFAULT_TOKEN` | CRITICAL | `default_token` (or another known default) was presented. A public exploit or scanner. |
| `EXECUTOR_EXPLOIT_PROBE` | CRITICAL | The legacy `/run` executor API was called (targeted by unauthenticated GLUE exploits). |
| `EXECUTOR_GLUE_REJECTED` | CRITICAL | GLUE code was sent to an executor **with a valid token**: the token or the admin is compromised. |
| `OPENAPI_JOB_MANAGE_REJECTED` | CRITICAL | An executor token was used to manage jobs: the executor host is likely compromised. |
| `PAYLOAD_RULE_MATCH` | rule severity (≥ HIGH) | A SOC rule matched `glueSource` / `executorParam`. |
| `PAYLOAD_CAPTURED` | HIGH | A GLUE or rejected payload was captured as evidence; no rule matched. |
| `PAYLOAD_SUSPICIOUS` | MEDIUM | Only generic signals (encoded blob, high entropy, large param, shell metachar). |
| `EXECUTOR_HANDLER_REJECTED` | HIGH | A handler outside the allowlist (or `commandJobHandler` / `httpJobHandler`) was requested. |
| `EXECUTOR_SCAN` | HIGH | A non-POST request or unknown path hit the executor port. |
| `ADMIN_GLUE_REJECTED` | HIGH | Attempt to create or edit GLUE, or a legacy GLUE job was triggered. |
| `ADMIN_GLUE_JOB_PRESENT` | HIGH | A GLUE job still exists in the database (startup inventory). |
| `ADMIN_TRIGGER_ADDRESS_REJECTED` | HIGH | A manual trigger aimed at an unregistered host (token theft / SSRF attempt). |
| `OPENAPI_REGISTRY_REJECTED` | HIGH | Cross-group or off-network executor registration. |
| `BRUTE_FORCE_DETECTED` | HIGH | 10+ failures from one source within 60s (`kind`: admin-login, openapi-auth, executor-auth, executor-scan). |
| `EXPLOIT_DEFAULT_CREDENTIAL` | HIGH | A login was attempted with password `123456`. |
| `ADMIN_LOGIN_LOCKED` | HIGH | An account was locked after 5 failures. |
| `ADMIN_PRIVILEGED_CHANGE` | HIGH | A user or executor group was created, updated or deleted (typical persistence step). |
| `ADMIN_DEFAULT_PASSWORD` / `ADMIN_RISKY_CONFIG` | HIGH | Default admin password blocked the startup / OpenAPI job management is enabled. |
| `EXECUTOR_AUTH_FAIL` / `OPENAPI_AUTH_FAIL` / `ADMIN_LOGIN_FAIL` | MEDIUM | Authentication failure; alert on repetition (see `BRUTE_FORCE_DETECTED`). |
| `REGISTRY_NEW_ADDRESS` | MEDIUM | First-seen executor address registered into a group. Verify it is a known pod/host. |
| `ADMIN_WEAK_TOKEN` / `ADMIN_DEFAULT_PASSWORD_RESET` | MEDIUM | Configuration finding / default password reset. |
| `SECURITY_LOG_CHAIN_START` | INFO | Genesis of the hash chain (one per process start). |

Operation audit (`xxl-job-audit`): `jobinfo-save / update / remove / start / stop / trigger`, `jobcode-update`, `login-success`, and user / executor-group changes (`/user/*`, `/jobgroup/*`).

## 5. Detection

### 5.1 Job payload inspection (sign of compromise elsewhere)

A GLUE payload is rejected and never runs, but its content shows what the attacker wanted to execute, and that they already had a token, an admin account, or a foothold that can reach the executor. Inspection points:

| Where | Field | Captured when |
|---|---|---|
| Executor `/trigger` (authenticated) | `glueSource` | Always (GLUE is rejected) |
| Executor `/trigger` (authenticated, BEAN) | `executorParam` | A rule or generic signal matches |
| Executor, rejected handler | `executorParam` | Always |
| Executor `/trigger` unauthenticated, `/run` probe | `glueSource`, `executorParam` or raw body | Always |
| Admin job add (UI / OpenAPI) | `glueSource` (always), `executorParam` (on match) | |
| Admin job update, manual trigger | `executorParam` | On match |
| Admin `/jobcode/save` | `glueSource` | Always |
| Admin OpenAPI job calls (rejected) | `glueSource`, `executorParam` | Always |
| Admin startup inventory | GLUE jobs and `xxl_job_logglue` history | Always |

**Rules file**: the build ships **no built-in attack signatures**. The SOC maintains the rules, one per line, `#` for comments:

```
rule_id | SEVERITY | java-regex
```

Invalid lines and regexes are skipped with a warning. The file is reloaded within 30 seconds of a change. `docker/e2e/payload-rules.txt` contains only a harmless test marker.

**Generic signals** (no signatures): an encoded blob (200+ base64/hex-like chars), high entropy (> 5.2 bits/char), and for `executorParam` a size over 2 KB or shell metacharacters.

**Evidence**: each finding logs `payloadSha256`, `payloadLength`, and a sample capped at 200 chars in the security event. The full payload (max 64 KB, escaped) goes to `xxl-job-evidence`, keyed by the same SHA-256. Use the hash to correlate across hosts and with threat-intel feeds.

### 5.2 Canary (honey) tokens

Generate decoy tokens (`echo t$(openssl rand -hex 24)`), set them in `xxl.job.security.canary-tokens` / `XXL_JOB_SECURITY_CANARY_TOKENS`, and plant each one in a different place an attacker would look: a fake `application.properties` in a repo, a wiki page, a ConfigMap, a CI variable, a backup. When any of them is presented to the executor or the OpenAPI, `CANARY_TOKEN_USED` fires. The event carries a 12-char hash prefix of the token, so keep a table of which prefix was planted where; that tells you which location leaked.

### 5.3 Other signals

- **Exploit fingerprints**: `default_token` presented, the legacy `/run` endpoint, non-POST requests or unknown paths on the executor port (scanners), and logins with `123456`.
- **Brute force**: a sliding 60-second window per source and kind; raised once per window.
- **Persistence**: `ADMIN_PRIVILEGED_CHANGE` for user and group changes (new admin users, token changes, manual executor address lists), and `REGISTRY_NEW_ADDRESS` for first-seen executors.
- **Tamper evidence**: verify the security logs with `python3 doc/detection/verify_chain.py <security.log...>`. It exits with 1 when a line was edited, deleted or reordered, and passes multiple process restarts (one genesis line per start). Ship logs off-host promptly; the chain proves integrity but does not prevent deletion of the whole file.

### 5.4 Hunting in existing data (IR)

Run the same rules against historical data. Planted code often survives in the GLUE history even after the job was reverted:

```sql
-- GLUE code history (attacker may have edited then reverted a job)
SELECT id, job_id, glue_type, glue_remark, add_time, glue_source FROM xxl_job_logglue ORDER BY add_time;
-- executor params and target addresses used in past triggers
SELECT id, job_id, trigger_time, executor_address, executor_handler, executor_param FROM xxl_job_log
 WHERE executor_handler IN ('commandJobHandler', 'httpJobHandler') OR executor_param <> '' ORDER BY trigger_time;
-- registered executor addresses: compare with the known pod / host inventory
SELECT registry_key, registry_value, update_time FROM xxl_job_registry ORDER BY registry_key;
-- users: look for unknown or recently added admins (role = 1)
SELECT id, username, role, permission FROM xxl_job_user;
```

### 5.5 Posture and metrics

- `GET /security/posture` (admin session) returns JSON: whether the default password is still in use, weak-token groups, GLUE job IDs, OpenAPI job management state, registry CIDRs, alert / rules / canary configuration, chain sequence and event counters.
- `GET /security/metrics` with `Authorization: Bearer <xxl.job.security.metrics-token>` returns the Prometheus text format: `xxljob_security_events_total{event=...}` plus posture gauges. Without a valid token it returns 404. Counters reset when the process restarts.

## 6. Test status

- The full build compiles with JDK 17 (`maven:3.9-eclipse-temurin-17` in Docker). Run with `-Dgpg.skip`. To run tests, add `-Dmaven.test.skip=false -Djunit-jupiter.version=6.0.3` (the upstream JUnit versions are misaligned).
- Unit tests: `SecurityToolTest` and `ThreatDetectorTest`, 11 of 11 pass.
- **Not yet done: end-to-end testing against running services.** `docker/e2e/` provides the environment (MySQL, admin, executor, a webhook receiver and a marker rules file); the `tester` service expects a test driver at `docker/e2e/e2e_test.py`, which is not included. Validate with your own test plan or a pentest of the hardened build. In particular, prove on the executor host that rejected GLUE payloads and rejected handlers never execute (e.g. a file the payload would create never appears), in addition to the log events.

## 7. Not covered by this build (needs infrastructure or bigger changes)

- NetworkPolicy/firewall so that only the Admin can reach the executor port. **Still P0**: do it at the infrastructure layer.
- Executor running as non-root, read-only filesystem, no privileged ServiceAccount.
- Separate tokens for OpenAPI, registry and executor; token rotation with an overlap window; mTLS.
- RBAC beyond admin/user, SSO/MFA, password hashing stronger than unsalted SHA-256.
- Per-handler `executorParam` validation and approval workflow.
- Login lockout and brute-force state are in memory, per admin instance; they reset on restart and are not shared across a cluster.
