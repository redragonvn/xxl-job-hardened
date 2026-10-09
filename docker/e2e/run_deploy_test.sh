#!/usr/bin/env bash
# xxl-job hardened build: deployment + functional test on docker.
# Builds the images, deploys ../docker-compose.yml with a test override, and checks
# startup guards, registration, a BEAN job round trip, posture / metrics, container hardening and log integrity.
#
# usage: docker/e2e/run_deploy_test.sh     (from repo root, after: mvn clean install -Dgpg.skip)
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DOCKER_DIR="$(cd "$HERE/.." && pwd)"
OUT="$HERE/out"
PROJECT=xxljob-test
RESULTS=()
FAILED=0

pass() { RESULTS+=("PASS $1"); echo "PASS $1"; }
fail() { RESULTS+=("FAIL $1 -> $2"); echo "FAIL $1 -> $2"; FAILED=1; }
check() { if eval "$2"; then pass "$1"; else fail "$1" "${3:-condition false}"; fi; }

secret() { echo "t$(openssl rand -hex 24)"; }

rm -rf "$OUT" && mkdir -p "$OUT" && chmod 777 "$OUT"
ENV_FILE="$OUT/test.env"
ADMIN_PW="Adm1n-$(openssl rand -hex 8)"
EXECUTOR_TOKEN="$(secret)"
METRICS_TOKEN="$(secret)"
CANARY_TOKEN="$(secret)"
cat > "$ENV_FILE" <<EOF
MYSQL_ROOT_PASSWORD=$(secret)
MYSQL_USER=xxl_job
MYSQL_PASSWORD=$(secret)
XXL_JOB_ADMIN_BIND=127.0.0.1
XXL_JOB_ADMIN_PORT=18080
XXL_JOB_INIT_ADMIN_PASSWORD=
XXL_JOB_EXECUTOR_TOKEN=$EXECUTOR_TOKEN
XXL_JOB_HANDLER_ALLOWLIST=demoJobHandler,shardingJobHandler
XXL_JOB_SUBNET=172.31.250.0/24
XXL_JOB_REGISTRY_ALLOWED_CIDRS=172.31.250.0/24
XXL_JOB_ALERT_WEBHOOK=http://webhook:8000/alert
XXL_JOB_ALERT_MIN_SEVERITY=HIGH
XXL_JOB_CANARY_TOKENS=$CANARY_TOKEN
XXL_JOB_METRICS_TOKEN=$METRICS_TOKEN
XXL_JOB_PAYLOAD_RULES_FILE=./e2e/payload-rules.txt
EOF

dc() { docker compose -p "$PROJECT" --env-file "$ENV_FILE" -f "$DOCKER_DIR/docker-compose.yml" -f "$HERE/docker-compose.test.yml" "$@"; }
set_env() { sed -i.bak "s#^$1=.*#$1=$2#" "$ENV_FILE" && rm -f "$ENV_FILE.bak"; }
ADMIN_URL="http://127.0.0.1:18080"
JAR="$OUT/cookies.txt"
login() { curl -s -c "$JAR" -b "$JAR" -X POST "$ADMIN_URL/auth/doLogin" --data-urlencode "userName=$1" --data-urlencode "password=$2" -d ifRemember=on; }
api() { local path=$1; shift; curl -s -b "$JAR" -X POST "$ADMIN_URL$path" "$@"; }
admin_log() { dc exec -T xxl-job-admin cat /data/applogs/xxl-job/xxl-job-admin-security.log 2>/dev/null; }
executor_log() { dc exec -T xxl-job-executor-sample-springboot cat /data/applogs/xxl-job/xxl-job-executor-security.log 2>/dev/null; }
mysql_healthy() { dc ps mysql --format '{{.Health}}' | grep -q healthy; }
# note: never "producer | grep -q" under pipefail (grep exits early -> SIGPIPE -> pipeline fails); use grep -c
log_has() { dc logs "$1" 2>&1 | grep -c -- "$2" >/dev/null; }
executor_registered() { api /jobgroup/loadById -d id=1 | grep -c '"registryList":\["http' >/dev/null; }
job1_succeeded() { api /joblog/pageList -d offset=0 -d pagesize=1 -d jobGroup=1 -d jobId=1 -d logStatus=-1 -d filterTime= | grep -c '"handleCode":200' >/dev/null; }
published_ports() { dc ps --format '{{.Service}} {{.Ports}}' | grep "^$1 " | grep -c -- '->' ; }
admin_up() { curl -sf -o /dev/null "$ADMIN_URL/auth/login"; }
wait_for() { # $1 seconds  $2 command
  local deadline=$((SECONDS + $1))
  while (( SECONDS < deadline )); do eval "$2" >/dev/null 2>&1 && return 0; sleep 2; done
  return 1
}

cleanup() { dc down -v --remove-orphans >/dev/null 2>&1; }
trap cleanup EXIT
cleanup

echo "== build images"
dc build --quiet xxl-job-admin xxl-job-executor-sample-springboot >"$OUT/build.log" 2>&1
BUILD_RC=$?
check "images build (non-root Dockerfiles, exact jar)" "[ $BUILD_RC -eq 0 ]" "see $OUT/build.log"
[ $BUILD_RC -eq 0 ] || exit 1

echo "== start mysql + webhook"
dc up -d mysql webhook >/dev/null 2>&1
check "mysql healthy" "wait_for 180 mysql_healthy"

echo "== T1 admin refuses to start with default admin password"
dc up -d --no-deps xxl-job-admin >/dev/null 2>&1
check "admin startup blocked while admin/123456 in use" "wait_for 120 'log_has xxl-job-admin \"still uses the default password\"'"
check "admin port not serving while blocked" "! admin_up"
check "alert webhook received ADMIN_DEFAULT_PASSWORD" "wait_for 30 'grep -q ADMIN_DEFAULT_PASSWORD $OUT/alerts.jsonl'"

echo "== T2 admin starts after one-time password reset"
set_env XXL_JOB_INIT_ADMIN_PASSWORD "$ADMIN_PW"
dc up -d --no-deps --force-recreate xxl-job-admin >/dev/null 2>&1
check "admin up" "wait_for 180 admin_up"
check "login with reset password" "login admin '$ADMIN_PW' | grep -q '\"code\":200'"
check "UI shows hardened version" "curl -s -b $JAR $ADMIN_URL/ | grep -c '3.5.1-hardened.1' >/dev/null"

echo "== T3 restart without init password (password no longer default)"
set_env XXL_JOB_INIT_ADMIN_PASSWORD ""
dc up -d --no-deps --force-recreate xxl-job-admin >/dev/null 2>&1
check "admin restarts cleanly without init password" "wait_for 180 admin_up"
login admin "$ADMIN_PW" >/dev/null

echo "== T4 executor group token rotation"
RESP=$(api /jobgroup/update -d id=1 -d appname=xxl-job-executor-sample --data-urlencode "name=Sample Executor" -d addressType=0 -d addressList= -d accessToken=default_token)
check "weak group token rejected by admin" "echo '$RESP' | grep -q 'weak'" "$RESP"
RESP=$(api /jobgroup/update -d id=1 -d appname=xxl-job-executor-sample --data-urlencode "name=Sample Executor" -d addressType=0 -d addressList= -d "accessToken=$EXECUTOR_TOKEN")
check "strong group token accepted" "echo '$RESP' | grep -q '\"code\":200'" "$RESP"

echo "== T5 executor refuses weak token"
set_env XXL_JOB_EXECUTOR_TOKEN default_token
dc up -d --no-deps xxl-job-executor-sample-springboot >/dev/null 2>&1
check "executor startup blocked with default_token" "wait_for 120 'log_has xxl-job-executor-sample-springboot \"accessToken is weak\"'"
set_env XXL_JOB_EXECUTOR_TOKEN "$EXECUTOR_TOKEN"

echo "== T6 executor starts and registers"
dc up -d --no-deps --force-recreate xxl-job-executor-sample-springboot >/dev/null 2>&1
check "executor registered in group 1" "wait_for 120 executor_registered"
GROUP_JSON=$(api /jobgroup/loadById -d id=1)
check "loadById does not return accessToken" "! echo '$GROUP_JSON' | grep -q '$EXECUTOR_TOKEN'" "$GROUP_JSON"
check "REGISTRY_NEW_ADDRESS raised for first registration" "wait_for 20 'admin_log | grep -c REGISTRY_NEW_ADDRESS >/dev/null'"

echo "== T6b executor security log pipeline (HTTP GET on executor port, as a misconfigured http health probe would do)"
EXECUTOR_ADDR=$(api /jobgroup/loadById -d id=1 | sed -n 's/.*"registryList":\["\([^"]*\)".*/\1/p')
dc exec -T webhook python -c "import urllib.request,sys
try: urllib.request.urlopen(sys.argv[1], timeout=5).read()
except Exception: pass" "$EXECUTOR_ADDR" >/dev/null 2>&1
check "executor logs EXECUTOR_SCAN to its security log" "wait_for 20 'executor_log | grep -c EXECUTOR_SCAN >/dev/null'"
check "EXECUTOR_SCAN (HIGH) alert delivered to webhook, tagged with executor appname" "wait_for 20 'grep EXECUTOR_SCAN $OUT/alerts.jsonl | grep -c xxl-job-executor:xxl-job-executor-sample >/dev/null'"

echo "== T7 BEAN job round trip (job 1, demoJobHandler)"
RESP=$(api /jobinfo/trigger -d id=1 -d executorParam= -d addressList=)
check "manual trigger accepted" "echo '$RESP' | grep -q '\"code\":200'" "$RESP"
check "job log: trigger 200 and handle 200" "wait_for 60 job1_succeeded"

echo "== T8 posture endpoint"
POSTURE=$(api /security/posture)
echo "$POSTURE" > "$OUT/posture.json"
check "posture: default password cleared" "echo '$POSTURE' | grep -q '\"defaultAdminPassword\":false'"
check "posture: no GLUE jobs" "echo '$POSTURE' | grep -q '\"glueJobIds\":\[\]'"
check "posture: remaining weak group listed" "echo '$POSTURE' | grep -q 'xxl-job-executor-sample-ai'"
check "posture: alert webhook configured" "echo '$POSTURE' | grep -q '\"alertWebhookConfigured\":true'"
check "posture: payload rules loaded" "echo '$POSTURE' | grep -q '\"payloadRuleCount\":1'"
check "posture: canary token configured" "echo '$POSTURE' | grep -q '\"canaryTokenCount\":1'"
check "posture denied without session" "! curl -s -X POST $ADMIN_URL/security/posture | grep -q defaultAdminPassword"

echo "== T9 metrics endpoint"
check "metrics 404 without token" "[ \"\$(curl -s -o /dev/null -w '%{http_code}' $ADMIN_URL/security/metrics)\" = 404 ]"
check "metrics 404 with wrong token" "[ \"\$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer wrongwrongwrongwrongwrongwrongwrong' $ADMIN_URL/security/metrics)\" = 404 ]"
METRICS=$(curl -s -H "Authorization: Bearer $METRICS_TOKEN" "$ADMIN_URL/security/metrics")
echo "$METRICS" > "$OUT/metrics.txt"
check "metrics served with token" "echo \"\$METRICS\" | grep -q '^xxljob_security_events_total{event=\"REGISTRY_NEW_ADDRESS\"}'"
check "metrics gauge glue_jobs = 0" "echo \"\$METRICS\" | grep -q '^xxljob_security_glue_jobs 0'"

echo "== T10 container hardening"
for svc in xxl-job-admin xxl-job-executor-sample-springboot; do
  check "$svc runs as uid 10001" "[ \"\$(dc exec -T $svc id -u)\" = 10001 ]"
  check "$svc root filesystem read-only" "! dc exec -T $svc sh -c 'touch /app.jar.test' 2>/dev/null"
  check "$svc no capabilities" "dc exec -T $svc grep -q 'CapEff:\s*0000000000000000' /proc/1/status"
done
check "executor port 9999 not published on host" "[ \"\$(published_ports xxl-job-executor-sample-springboot)\" = 0 ]"
check "mysql port not published on host" "[ \"\$(published_ports mysql)\" = 0 ]"
check "admin bound to 127.0.0.1 only" "dc ps --format '{{.Service}} {{.Ports}}' | grep '^xxl-job-admin ' | grep -c '127.0.0.1:18080->8080' >/dev/null"

echo "== T11 secrets never logged"
admin_log > "$OUT/admin-security.log"; executor_log > "$OUT/executor-security.log"
dc logs --no-color > "$OUT/all-containers.log" 2>&1
for name in EXECUTOR_TOKEN METRICS_TOKEN CANARY_TOKEN ADMIN_PW; do
  check "$name absent from all logs" "! grep -q -- \"\${!name}\" $OUT/all-containers.log $OUT/admin-security.log $OUT/executor-security.log"
done

echo "== T12 security log hash chain"
VERIFY() { docker run --rm -v "$OUT:/o:ro" -v "$DOCKER_DIR/../doc/detection:/d:ro" python:3.12-alpine python /d/verify_chain.py "$@"; }
VERIFY /o/admin-security.log > "$OUT/verify-admin.txt"
VERIFY /o/executor-security.log > "$OUT/verify-executor.txt"
check "admin security log chain intact" "grep -q '^OK' $OUT/verify-admin.txt" "$(cat "$OUT/verify-admin.txt")"
check "executor security log chain intact" "grep -q '^OK' $OUT/verify-executor.txt" "$(cat "$OUT/verify-executor.txt")"
# tamper a copy: drop the 2nd event line
awk '/xxl-job-security/ && /seq=/ && !/seq=0 /{n++; if(n==2) next} {print}' "$OUT/admin-security.log" > "$OUT/admin-security.tampered.log"
VERIFY /o/admin-security.tampered.log > "$OUT/verify-tampered.txt"
check "tampered copy detected as BROKEN" "grep -q '^BROKEN' $OUT/verify-tampered.txt" "$(cat "$OUT/verify-tampered.txt")"

echo "== T13 graceful stop (exec java gets SIGTERM)"
START=$SECONDS
dc stop -t 30 xxl-job-executor-sample-springboot >/dev/null 2>&1
check "executor stops within grace period" "(( SECONDS - START < 30 ))"

echo
echo "================ SUMMARY ================"
printf '%s\n' "${RESULTS[@]}" | tee "$OUT/results.txt"
echo "passed: $(grep -c '^PASS' "$OUT/results.txt")  failed: $(grep -c '^FAIL' "$OUT/results.txt")"
exit $FAILED
