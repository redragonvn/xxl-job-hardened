# Migration Guide: replacing XXL-JOB with xxl-job-hardened 3.5.1-hardened.1

Audience: platform / DevOps teams, executor application owners, SOC / IR.
Configuration and event details are in [HARDENING.md](HARDENING.md); what changed is in the [release notes](RELEASE_NOTES-3.5.1-hardened.1.md).

The replacement has two halves that **must both happen**:

- **Admin (scheduling center)**: replace the deployment with the hardened admin.
- **Every executor application**: rebuild against the hardened `xxl-job-core`. The executor-side protections (GLUE rejection, handler allowlist, token checks, detection) live in that library. Upgrading only the admin leaves old executors executing GLUE for anyone holding a leaked token.

---

## 1. Find your starting point

| Current version | Path |
|---|---|
| **3.5.x** | Same schema and protocol. No database migration. Go to section 2. |
| **3.0.x – 3.4.x** | Apply the upstream database upgrade scripts for every version between yours and 3.5.0 (upstream doc `doc/XXL-JOB官方文档.md`, section 7, "数据库升级脚本"), in order. The 3.5.0 protocol change (token per executor group) means **admin and all executors must move in the same window**. |
| **2.x and older** | Everything above, plus: 3.x requires **JDK 17** (2.x ran on JDK 8) and Spring Boot 3+ (`jakarta.*`). Executor applications on JDK 8 must be upgraded first; this is usually the longest part of the project. |

Upstream changes that affect the migration:

| Upstream version | Change | Consequence |
|---|---|---|
| 3.0.0 | JDK 17, Spring Boot 3 | Executor apps must run JDK 17. |
| 3.2.0 | Password hash MD5 → SHA-256; `xxl_job_user.password` widened, `token` column added | Existing passwords stop working; users need new passwords (section 6.3). |
| 3.5.0 | Global `xxl.job.accessToken` replaced by a token **per executor group** (`xxl_job_group.access_token`); `title` → `name`, `job_desc` → `name`; protocol change | DB script required; admin and executors upgrade together. |

---

## 2. Phase 0: preserve evidence (before touching anything)

XXL-JOB is commonly targeted. Treat the current installation as possibly compromised and keep evidence **before** the upgrade changes job state:

1. Take a full database backup (`mysqldump --single-transaction xxl_job`), and store it read-only.
2. Run the hunting queries in [HARDENING.md section 5.4](HARDENING.md#54-hunting-in-existing-data-ir) and section 3 (GLUE inventory). Keep the output.
3. Copy the admin and executor logs (application logs and `jobhandler` execution logs).
4. List the executor hosts that currently register (`xxl_job_registry`) and compare them with your inventory. Unknown addresses are a finding.
5. Hand anything suspicious (unknown GLUE code, unexpected `commandJobHandler` / `httpJobHandler` use, unknown admin users, unknown executors) to IR before continuing.

---

## 3. Phase 1: inventory

Fill in one row per executor application and per admin deployment.

| Item | Why it matters |
|---|---|
| Admin deployments (URL, version, who has accounts) | All are replaced. |
| Executor applications: repo, owner, current `xxl-job-core` version, JDK, AppName | Each must be rebuilt (section 5). |
| GLUE jobs per group (`glue_type <> 'BEAN'`) | They stop running; each needs a BEAN replacement. |
| BEAN handlers each job uses | Becomes the executor's `handlerallowlist`. |
| Jobs using `commandJobHandler` / `httpJobHandler` | Denied by default; need purpose-built handlers. |
| External systems calling the admin OpenAPI (`/api/addJob`, `/api/triggerJob`, ...) | Job-management OpenAPI is off by default. |
| How executors and admin reach each other (network, proxy, ingress) | Needed for the CIDR allowlist, NetworkPolicy and proxy settings. |
| Health probes on executor ports | HTTP probes raise `EXECUTOR_SCAN` alerts; switch to TCP. |

Useful queries:

```sql
-- groups, tokens state (do not export the tokens themselves)
SELECT id, app_name, name, address_type, access_token IS NULL OR access_token = 'default_token' OR LENGTH(access_token) < 32 AS weak_token FROM xxl_job_group;
-- handlers per group (=> allowlists)
SELECT job_group, executor_handler, COUNT(*) FROM xxl_job_info WHERE glue_type = 'BEAN' GROUP BY job_group, executor_handler;
-- GLUE and dangerous sample handlers
SELECT id, job_group, name, glue_type, executor_handler, trigger_status FROM xxl_job_info
 WHERE glue_type <> 'BEAN' OR executor_handler IN ('commandJobHandler', 'httpJobHandler');
```

---

## 4. Phase 2: prepare

### 4.1 Port GLUE jobs to BEAN handlers

For each GLUE job, implement the same logic as a reviewed handler in the executor application (code review, tests, normal release process), then point the job at it.

```java
@Component
public class ReportJobs {

    @XxlJob("dailyReportJobHandler")
    public void dailyReport() {
        String param = XxlJobHelper.getJobParam();     // validate: this is data, never a command
        XxlJobHelper.log("daily report start, param={}", param);
        // ... business logic that used to be in the GLUE script ...
        XxlJobHelper.handleSuccess();
    }
}
```

Rules for handlers:
- The job parameter is **data**: validate it (format, length, allowed values); never pass it to a shell, `ProcessBuilder`, script engine, SQL string or URL without strict validation.
- Do not write generic "run this command" / "call this URL" handlers; that recreates GLUE.

After the upgrade, change each job to `BEAN` + the new handler. GLUE type cannot be changed in the UI, so either recreate the job as BEAN, or update it in the database during the window:

```sql
UPDATE xxl_job_info SET glue_type = 'BEAN', glue_source = '', executor_handler = 'dailyReportJobHandler' WHERE id = <jobId>;
```

### 4.2 Generate secrets

```bash
echo t$(openssl rand -hex 24)
```

The token must be at least 32 chars and start with a letter (the admin UI only accepts `[a-z][a-z0-9_]*`, max 50 chars). Generate:

| Secret | Count |
|---|---|
| Executor group token | One per executor group (AppName) |
| Admin init password | One (min 12 chars), used once |
| Metrics bearer token | One, if Prometheus scrapes the admin |
| Canary tokens | Several; record where each will be planted |
| DB password for a dedicated `xxl_job` user | One (the admin should not use `root`) |

Store them in your secret manager. Never in Git, images or ConfigMaps.

### 4.3 Prepare SOC content

- Payload rules file (`rule_id | SEVERITY | java-regex`) from your detection content; review the regexes for performance.
- SIEM parsing for the `severity=... event=... key="value" ... seq=... chain=...` format, and alerts for CRITICAL / HIGH events ([HARDENING.md section 4](HARDENING.md#4-security-events-siem)).
- Webhook receiver for alerts (internal endpoint; alerts include a 200-char payload sample).
- Restricted storage for the evidence logs.

---

## 5. Phase 3: build and publish

### 5.1 Build the hardened artifacts

```bash
mvn clean install
```

Publish to your **internal** repository only. The `release` profile (Maven Central) is opt-in; never pass `-Prelease`:

```bash
mvn deploy -DaltDeploymentRepository=internal::https://repo.example.internal/repository/maven-releases/
```

Build and push the images (`xxl-job-admin/Dockerfile`, executor Dockerfiles) to your internal registry with tag `3.5.1-hardened.1`.

### 5.2 Rebuild each executor application

1. Dependency:
   ```xml
   <dependency>
       <groupId>com.xuxueli</groupId>
       <artifactId>xxl-job-core</artifactId>
       <version>3.5.1-hardened.1</version>
   </dependency>
   ```
   Confirm no other version comes in transitively: `mvn dependency:tree -Dincludes=com.xuxueli:xxl-job-core`.

2. Configuration (application `XxlJobConfig` / properties):

   | Old | New |
   |---|---|
   | `xxl.job.accessToken=default_token` (≤ 3.4, global) or `xxl.job.executor.accessToken=...` (3.5) | `xxl.job.executor.accessToken=${XXL_JOB_ACCESS_TOKEN:}`, value from a Secret, equal to the group token in the admin |
   | `xxl.job.executor.glueenabled=true` | Remove. GLUE is always disabled; `setGlueEnabled` is ignored. |
   | n/a | `xxl.job.executor.handlerallowlist=handlerA,handlerB` → `xxlJobSpringExecutor.setHandlerAllowlist(...)` |

   Example `XxlJobConfig` change:
   ```java
   @Value("${xxl.job.executor.handlerallowlist:}")
   private String handlerAllowlist;
   // ...
   xxlJobSpringExecutor.setAccessToken(accessToken);
   xxlJobSpringExecutor.setHandlerAllowlist(handlerAllowlist);
   ```

3. Environment variables (read by the core library, no code needed): `XXL_JOB_SECURITY_ALERT_WEBHOOK`, `XXL_JOB_SECURITY_ALERT_MIN_SEVERITY`, `XXL_JOB_SECURITY_PAYLOAD_RULES`, `XXL_JOB_SECURITY_CANARY_TOKENS`.

4. Logging: add the `xxl-job-security` and `xxl-job-evidence` loggers (copy from `xxl-job-executor-samples/xxl-job-executor-sample-springboot/src/main/resources/logback.xml`). Without them, security events only reach the application's normal log.

5. Runtime: non-root user, read-only root filesystem with a writable log dir and `/tmp`, no Docker socket, no privileged ServiceAccount (`docker/k8s/executor-pod-security.yaml`). TCP probes on the executor port.

6. Remove any copied sample handlers (`commandJobHandler`, `httpJobHandler`) from the application code.

---

## 6. Phase 4: staging

Run the whole cutover (section 7) in staging first, with a copy of the production database.

1. Deploy, then run `docker/e2e/run_deploy_test.sh` (reference deployment) or the equivalent checks in your platform.
2. **Pentest** the hardened build: GLUE through every admin and executor API, token misuse, cross-group registration, trigger address override, rejected handlers, payload rules. Prove on the executor host that rejected payloads never execute.
3. Leave it running for a few days and tune noisy alerts (generic `executorParam` signals, `REGISTRY_NEW_ADDRESS` on pod restarts).
4. Run every production job type at least once on staging executors.

---

## 7. Phase 5: production cutover

Schedule a maintenance window: jobs do not run while admin and executors are being replaced.

### 7.1 Before the window
- Phase 0 evidence collected; staging sign-off; executor applications built and ready to deploy.
- NetworkPolicy / firewall rules prepared (only admin → executor port; executor egress limited).

### 7.2 In the window

1. **Stop the old admin** (all instances). Scheduling pauses.
2. **Back up the database** again.
3. **Database changes** (only if coming from < 3.5.0): apply the upstream upgrade scripts in order. For the 3.5.0 script, set each group token to its **generated** value, never `default_token`:
   ```sql
   UPDATE xxl_job_group SET access_token = '<generated token>' WHERE app_name = '<AppName>';
   ```
   Coming from 3.5.x, set the tokens the same way or through the admin UI after step 4.
4. **Start the hardened admin** with `XXL_JOB_SECURITY_INIT_ADMIN_PASSWORD` set (required if `admin` still has `123456`; coming from < 3.2.0 the upstream script also resets passwords to `123456`). The admin logs `ADMIN_WEAK_TOKEN` for every group whose token is not rotated yet, and `ADMIN_GLUE_JOB_PRESENT` for every remaining GLUE job.
5. **Rotate any remaining group tokens** (Admin → Executor Management) and convert GLUE jobs to BEAN (section 4.1).
6. **Deploy all executor applications** with the hardened core and the new token.
7. **Verify** (section 7.3).
8. **Apply the network restriction** and verify it with a real connection attempt from a non-admin host / pod.
9. **Restart the admin without** `XXL_JOB_SECURITY_INIT_ADMIN_PASSWORD`, and remove it from the secret store.
10. Re-enable job schedules.

### 7.3 Verification

| Check | How |
|---|---|
| Admin hardened version | UI footer shows `3.5.1-hardened.1`. |
| No GLUE, no weak tokens, defaults gone | `GET /security/posture` (admin session): `defaultAdminPassword=false`, `weakTokenGroups=[]`, `glueJobIds=[]`. |
| All executors registered | Executor Management shows every expected node; no unknown addresses. |
| Every executor runs the hardened core | Executor startup log contains `xxl-job hardened executor, glue disabled`. |
| Jobs run | Trigger one job per executor group; job log shows trigger 200 and handle 200. |
| Network restriction | From a non-admin pod/host, a TCP connection to the executor port fails. |
| Alerting | A HIGH event reaches the SOC (e.g. the `ADMIN_PRIVILEGED_CHANGE` from rotating a token). |
| Log integrity | `python3 doc/detection/verify_chain.py <security.log>` returns `OK`. |
| Metrics (if used) | Prometheus scrape of `/security/metrics` succeeds with the bearer token. |

---

## 8. Rollback

- The hardened build does not change the database schema, so the upstream 3.5.x admin and executors can run against the same database.
- **Rolling back re-enables GLUE execution.** Only roll back with the network restriction in place, never restore GLUE jobs, and keep the rotated tokens (do not go back to `default_token`).
- Rolling back across the 3.5.0 protocol change (to < 3.5.0) also requires restoring the pre-upgrade database backup.
- Record the rollback as a security exception and plan the re-upgrade.

---

## 9. Operating the hardened build

**Token rotation** (one token per group, no overlap window):
1. Update the group token in Admin → Executor Management (or SQL).
2. Redeploy the group's executors with the new `XXL_JOB_ACCESS_TOKEN`.
Triggers to that group fail between steps 1 and 2; do it in a short window. Rotate immediately on any `CANARY_TOKEN_USED`, `EXECUTOR_GLUE_REJECTED` or `OPENAPI_JOB_MANAGE_REJECTED` alert for that group.

**Onboarding a new executor application**: hardened core dependency, group token from the secret manager, `handlerallowlist`, security loggers, non-root runtime, TCP probes, NetworkPolicy label, CIDR within `xxl.job.registry.allowed-cidrs`.

**Routine**: review the posture endpoint weekly; verify security-log chains daily (or on every log shipment); review canary placements and rules quarterly.

---

## 10. Troubleshooting

| Symptom / log message | Cause | Fix |
|---|---|---|
| Admin exits: `user 'admin' still uses the default password` | `admin/123456` in the database | Start once with `XXL_JOB_SECURITY_INIT_ADMIN_PASSWORD` (min 12 chars). |
| Executor exits: `accessToken is weak` | Token blank, default or < 32 chars | Set a generated token in `XXL_JOB_ACCESS_TOKEN` and in the group. |
| Executor never appears in Executor Management | Token mismatch, or address outside `xxl.job.registry.allowed-cidrs` | Check `OPENAPI_AUTH_FAIL` / `OPENAPI_REGISTRY_REJECTED` in the admin security log. |
| Job log: `executor group accessToken is weak` | Group token not rotated | Rotate the group token. |
| Job log: `GLUE job is disabled in hardened build` | GLUE job still in the database | Port to BEAN (section 4.1). |
| Job fails: `job handler [...] is not in executor handler allowlist` | Handler missing from `handlerallowlist`, or a denied sample handler | Add the handler to the allowlist (not for sample command/HTTP handlers). |
| OpenAPI returns `openapi job management is disabled` | Job-management OpenAPI off by default | Use the admin UI, or enable explicitly and accept the risk. |
| Manual trigger: `address [...] is not a registered node` | Address override not in the group's registry | Use one of the registered addresses (exact match). |
| Many `EXECUTOR_SCAN` alerts | HTTP health probe on the executor port | Switch to a TCP probe. |
| All logins / alerts show the same IP, or every user is locked out at once | Admin behind a proxy: all requests look like the proxy IP, so the per-IP login limit applies to everyone | Configure `server.forward-headers-strategy=native` with `server.tomcat.remoteip.internal-proxies`. |
| A user cannot log in for 15 minutes after a few attempts | Username + IP lock (5 failures) or IP lock (20 failures, e.g. shared NAT with someone guessing) | Wait for the lock to expire; check `ADMIN_LOGIN_LOCKED` (`scope`) in the security log. |
| `verify_chain.py` reports `BROKEN` | Security log edited or lines deleted | Treat as a security incident; compare with the SIEM copy. |
