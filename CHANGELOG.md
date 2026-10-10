# Changelog: xxl-job-hardened

All notable changes of the hardened fork. Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Upstream changes are tracked in `doc/XXL-JOB官方文档.md` (section 7, Release Notes).

Base: upstream XXL-JOB `3.5.1-SNAPSHOT` (commit `693d2764`).

## [3.5.1-hardened.1] - release candidate

Status: **release candidate**. Deployment and functional tests pass; attack-path (pentest) validation in staging is pending. See [doc/RELEASE_NOTES-3.5.1-hardened.1.md](doc/RELEASE_NOTES-3.5.1-hardened.1.md).

### Security (breaking: fail-closed)

- **GLUE execution removed.** The executor rejects every non-BEAN trigger (`GLUE(Java)`, Shell, Python, Node.js, PowerShell, PHP); `xxl.job.executor.glueenabled=true` is ignored; the Groovy loader and script handler refuse to run.
- **GLUE blocked on the admin side.** Non-BEAN job creation is rejected for the web UI and the OpenAPI; `/jobcode/save` is disabled; GLUE jobs already in the database are never dispatched (the job log records the failure).
- **BEAN handler allowlist** on the executor (`xxl.job.executor.handlerallowlist`). The sample handlers `commandJobHandler` (OS command) and `httpJobHandler` (arbitrary HTTP) are denied unless explicitly allowlisted.
- **Weak tokens rejected.** Blank, `default_token` or other known defaults, or tokens shorter than 32 chars: the executor refuses to start; the admin refuses to save the group, trigger its jobs, or accept its OpenAPI calls.
- **Token exposure fixed.** `/jobgroup/loadById` now checks group permission and never returns `accessToken` (previously any logged-in user could read every group's token). `XxlJobGroup.toString()` masks the token.
- **Constant-time comparison** for executor tokens, OpenAPI tokens and password hashes.
- **OpenAPI job management disabled by default** (`addJob`, `updateJob`, `removeJob`, `startJob`, `stopJob`, `triggerJob`): these authenticate with the executor token that every executor host holds. Opt in with `xxl.job.openapi.job-manage.enabled=true`.
- **Executor registration restricted.** An executor can only register into its own group; the address must be http(s), and its host must match `xxl.job.registry.allowed-cidrs` when set.
- **Manual trigger address override** limited to registered nodes of the group (previously it could send the group token to any host).
- **Default admin password blocks startup.** The admin refuses to start while `admin/123456` is in use, unless `xxl.job.security.init-admin-password` is provided for a one-time reset.
- **Login lockout**: 5 failures lock the username for the failing source IP for 15 minutes.

### Added: visibility and detection

- Security event log (`xxl-job-security`) with severity, per-event counters and a tamper-evident hash chain; operation audit log (`xxl-job-audit`); admin requests tagged with source IP and user-agent.
- Webhook alerting for events at or above a configurable severity (`HIGH` by default), async and bounded, tagged with source (admin or executor appname).
- Payload inspection of `glueSource` / `executorParam` at every admin and executor entry point, using a SOC-maintained rules file (hot reload, no built-in signatures) plus generic signals; payload evidence capture (hash, sample, full payload in `xxl-job-evidence`).
- Canary (honey) tokens; exploit fingerprints (`default_token`, legacy `/run` endpoint, non-POST and unknown paths on the executor port, logins with `123456`); brute-force and scan detection per source; privileged-change audit (users, executor groups); first-seen executor address; startup inventory of GLUE jobs and their code history.
- `GET /security/posture` (admin only) and `GET /security/metrics` (Prometheus, bearer token).
- `doc/detection/verify_chain.py`: security-log integrity checker.

### Added: deployment

- Non-root (uid 10001) Docker images copying one exact jar, `exec java` for clean SIGTERM handling.
- `docker/docker-compose.yml`: hardened reference deployment (read-only rootfs, all capabilities dropped, no-new-privileges, only admin published on 127.0.0.1, dedicated DB user, required secrets) with `docker/.env.example`.
- `docker/k8s/`: reference executor NetworkPolicy and pod security settings.
- `docker/e2e/run_deploy_test.sh`: build + deploy + functional test (47 checks).

### Changed

- Version `3.5.1-hardened.1` for all Maven modules, Docker image tags and the admin UI.
- Sample executors read the token from `XXL_JOB_ACCESS_TOKEN`; `glueenabled` replaced by `handlerallowlist` in sample configs.
- `server.forward-headers-strategy=none` set explicitly (configure a trusted proxy when behind an ingress).
- Upstream operation-log lines routed to the `xxl-job-audit` logger.
- Upstream `release` profile (GPG signing + Maven Central publishing) is now opt-in (`-Prelease`). Upstream had it active by default, so `mvn deploy` would target Maven Central; plain `mvn clean install` now works without `-Dgpg.skip`. The compiler configuration (`-parameters`, required by Spring MVC parameter binding) moved from that profile into the main build.

### Removed

- Tracked `docker/.env` containing upstream default passwords (replaced by `docker/.env.example`, `.env` git-ignored).

### Fixed

- Upstream Dockerfiles failed to build (`target/*.jar` glob matched the `-sources` / `-javadoc` jars).
- Upstream test setup failed to start (JUnit engine/API version mismatch); fixed by importing `junit-bom`.

### Known limitations

- Login lockout and brute-force state are in memory per admin instance (reset on restart, not shared across a cluster).
- Password hashing remains upstream's unsalted SHA-256; no SSO/MFA; RBAC is upstream's admin/user model.
- A single executor-group token is still shared for executor auth, registry and OpenAPI (no rotation overlap window, no mTLS).
- The network restriction and runtime hardening must be enforced by the infrastructure (`docker/k8s/` are references).
