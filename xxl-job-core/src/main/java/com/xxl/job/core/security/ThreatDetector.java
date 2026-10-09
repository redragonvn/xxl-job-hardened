package com.xxl.job.core.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * hardened build: detection helpers for xxl-job.
 *
 * 1、payload inspection: SOC-maintained rules file (no built-in signature) + generic signals (encoded blob / entropy / size / metachar);
 * 2、evidence capture: payload sha256 + capped sample in security event, full payload in "xxl-job-evidence" logger;
 * 3、canary (honey) tokens: decoy accessToken planted in fake config, any use is a confirmed leak;
 * 4、exploit fingerprint: well-known default token presented while configured token is strong;
 * 5、brute force / scan: sliding window failure counter per source.
 *
 * rules file (env XXL_JOB_SECURITY_PAYLOAD_RULES / -Dxxl.job.security.payload-rules), one rule per line, '#' for comment:
 *      rule_id | SEVERITY | java-regex
 */
public class ThreatDetector {
    private static final Logger logger = LoggerFactory.getLogger(ThreatDetector.class);

    /**
     * full payload evidence, keep in a restricted file (IR team only)
     */
    public static final Logger EVIDENCE_LOGGER = LoggerFactory.getLogger("xxl-job-evidence");

    private static final int EVIDENCE_MAX_LENGTH = 64 * 1024;
    private static final int SAMPLE_MAX_LENGTH = 200;


    // ---------------------- rules file ----------------------

    public static class PayloadRule {
        final String id;
        final SecuritySeverity severity;
        final Pattern pattern;
        PayloadRule(String id, SecuritySeverity severity, Pattern pattern) {
            this.id = id;
            this.severity = severity;
            this.pattern = pattern;
        }
    }

    private static volatile String rulesPath = firstNonBlank(System.getenv("XXL_JOB_SECURITY_PAYLOAD_RULES"), System.getProperty("xxl.job.security.payload-rules"));
    private static volatile List<PayloadRule> rules = Collections.emptyList();
    private static volatile long rulesLastModified = -1;
    private static volatile long rulesLastCheck = 0;
    private static final long RULES_RELOAD_INTERVAL = 30 * 1000L;

    public static void configureRulesPath(String path) {
        if (path != null && !path.trim().isEmpty()) {
            rulesPath = path.trim();
            rulesLastModified = -1;
            rulesLastCheck = 0;
        }
    }

    public static int ruleCount() {
        reloadRulesIfChanged();
        return rules.size();
    }

    private static void reloadRulesIfChanged() {
        String path = rulesPath;
        long now = System.currentTimeMillis();
        if (path == null || now - rulesLastCheck < RULES_RELOAD_INTERVAL && rulesLastModified != -1) {
            return;
        }
        rulesLastCheck = now;
        File file = new File(path);
        if (!file.isFile()) {
            if (rulesLastModified != 0) {
                logger.warn(">>>>>>>>>>> xxl-job security payload rules file not found: {}", path);
                rulesLastModified = 0;
                rules = Collections.emptyList();
            }
            return;
        }
        if (file.lastModified() == rulesLastModified) {
            return;
        }
        rules = parseRules(file);
        rulesLastModified = file.lastModified();
        logger.info(">>>>>>>>>>> xxl-job security payload rules loaded, path:{}, count:{}", path, rules.size());
    }

    static List<PayloadRule> parseRules(File file) {
        List<PayloadRule> result = new ArrayList<>();
        try {
            int lineNum = 0;
            for (String line : Files.readAllLines(file.toPath(), StandardCharsets.UTF_8)) {
                lineNum++;
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                String[] parts = line.split("\\s*\\|\\s*", 3);
                if (parts.length != 3 || parts[0].isEmpty() || parts[2].isEmpty()) {
                    logger.warn(">>>>>>>>>>> xxl-job security payload rule invalid, line:{}", lineNum);
                    continue;
                }
                try {
                    result.add(new PayloadRule(parts[0], SecuritySeverity.match(parts[1], SecuritySeverity.HIGH), Pattern.compile(parts[2])));
                } catch (Exception e) {
                    logger.warn(">>>>>>>>>>> xxl-job security payload rule regex invalid, line:{}, error:{}", lineNum, e.getMessage());
                }
            }
        } catch (Exception e) {
            logger.warn(">>>>>>>>>>> xxl-job security payload rules load error:{}", e.getMessage());
        }
        return Collections.unmodifiableList(result);
    }


    // ---------------------- payload inspection ----------------------

    private static final Pattern ENCODED_BLOB = Pattern.compile("[A-Za-z0-9+/=_-]{200,}");
    private static final Pattern SHELL_METACHAR = Pattern.compile("[;&|`$<>]|\\$\\(");
    private static final int LARGE_PARAM_LENGTH = 2048;

    /**
     * inspect payload, return matched rule ids and generic signals; empty list if nothing found
     *
     * @param payload       glueSource / executorParam
     * @param isParam       true for BEAN executorParam (enable param-specific generic signals)
     */
    public static List<String> inspect(String payload, boolean isParam) {
        if (payload == null || payload.isEmpty()) {
            return Collections.emptyList();
        }
        reloadRulesIfChanged();
        List<String> findings = new ArrayList<>();
        for (PayloadRule rule : rules) {
            if (rule.pattern.matcher(payload).find()) {
                findings.add("rule:" + rule.id + ":" + rule.severity.name());
            }
        }
        Matcher blob = ENCODED_BLOB.matcher(payload);
        if (blob.find()) {
            findings.add("generic:encoded_blob");
        }
        if (payload.length() >= 64 && shannonEntropy(payload) > 5.2) {
            findings.add("generic:high_entropy");
        }
        if (isParam) {
            if (payload.length() > LARGE_PARAM_LENGTH) {
                findings.add("generic:large_param");
            }
            if (SHELL_METACHAR.matcher(payload).find()) {
                findings.add("generic:shell_metachar");
            }
        }
        return findings;
    }

    /**
     * highest severity among findings: rule severity, generic signals are MEDIUM
     */
    public static SecuritySeverity maxSeverity(List<String> findings) {
        SecuritySeverity max = SecuritySeverity.INFO;
        for (String item : findings) {
            SecuritySeverity severity = item.startsWith("rule:")
                    ? SecuritySeverity.match(item.substring(item.lastIndexOf(':') + 1), SecuritySeverity.HIGH)
                    : SecuritySeverity.MEDIUM;
            if (severity.ordinal() > max.ordinal()) {
                max = severity;
            }
        }
        return max;
    }

    static double shannonEntropy(String text) {
        int[] counts = new int[256];
        int total = 0;
        for (char c : text.toCharArray()) {
            counts[c & 0xFF]++;
            total++;
        }
        double entropy = 0;
        for (int count : counts) {
            if (count > 0) {
                double p = (double) count / total;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return entropy;
    }

    /**
     * capture payload as evidence and raise event:
     *      - PAYLOAD_RULE_MATCH (severity of rule) when SOC rule matched;
     *      - PAYLOAD_SUSPICIOUS when only generic signal found;
     *      - PAYLOAD_CAPTURED when forceCapture (e.g. any GLUE attempt) and nothing matched.
     *
     * @param where         capture point, such as "executor-trigger" / "admin-jobinfo-add"
     * @param field         glueSource / executorParam
     * @param payload       content
     * @param forceCapture  capture even if nothing matched
     * @param context       extra key, value pairs
     * @return findings
     */
    public static List<String> inspectAndCapture(String where, String field, String payload, boolean forceCapture, Object... context) {
        List<String> findings = inspect(payload, "executorParam".equals(field));
        if (findings.isEmpty() && !forceCapture) {
            return findings;
        }
        if (payload == null) {
            return findings;
        }
        String sha256 = SecurityTool.sha256Hex(payload);
        boolean ruleMatched = false;
        for (String item : findings) {
            if (item.startsWith("rule:")) {
                ruleMatched = true;
                break;
            }
        }
        String event = ruleMatched ? "PAYLOAD_RULE_MATCH" : (findings.isEmpty() ? "PAYLOAD_CAPTURED" : "PAYLOAD_SUSPICIOUS");

        List<Object> kvs = new ArrayList<>(Arrays.asList(
                "where", where, "field", field,
                "findings", String.join(",", findings),
                "maxSeverity", maxSeverity(findings).name(),
                "payloadSha256", sha256, "payloadLength", payload.length(),
                "sample", payload.length() > SAMPLE_MAX_LENGTH ? payload.substring(0, SAMPLE_MAX_LENGTH) : payload));
        kvs.addAll(Arrays.asList(context));
        SecurityTool.eventAt(ruleMatched ? maxSeverity(findings) : null, event, kvs.toArray());

        // full evidence, escaped single line
        String evidence = payload.length() > EVIDENCE_MAX_LENGTH ? payload.substring(0, EVIDENCE_MAX_LENGTH) : payload;
        EVIDENCE_LOGGER.warn("payloadSha256={} where={} field={} truncated={} payload=\"{}\"",
                sha256, where, field, payload.length() > EVIDENCE_MAX_LENGTH,
                evidence.replace("\\", "\\\\").replace("\"", "\\\"").replace("\r", "\\r").replace("\n", "\\n"));
        return findings;
    }


    // ---------------------- canary / fingerprint ----------------------

    private static volatile Set<String> canaryTokens = parseCsv(firstNonBlank(System.getenv("XXL_JOB_SECURITY_CANARY_TOKENS"), System.getProperty("xxl.job.security.canary-tokens")));

    public static void configureCanaryTokens(String csv) {
        if (csv != null && !csv.trim().isEmpty()) {
            canaryTokens = parseCsv(csv);
        }
    }

    public static int canaryTokenCount() {
        return canaryTokens.size();
    }

    /**
     * inspect presented token on auth failure path: canary / known default token fingerprint
     *
     * @return true if a detection event was raised
     */
    public static boolean inspectPresentedToken(String presentedToken, String where, Object... context) {
        if (presentedToken == null || presentedToken.isEmpty()) {
            return false;
        }
        for (String canary : canaryTokens) {
            if (SecurityTool.safeEquals(presentedToken, canary)) {
                List<Object> kvs = new ArrayList<>(Arrays.asList("where", where, "canary", SecurityTool.sha256Hex(canary).substring(0, 12)));
                kvs.addAll(Arrays.asList(context));
                SecurityTool.event("CANARY_TOKEN_USED", kvs.toArray());
                return true;
            }
        }
        if (SecurityTool.isKnownDefaultToken(presentedToken)) {
            List<Object> kvs = new ArrayList<>(Arrays.asList("where", where, "presented", presentedToken));
            kvs.addAll(Arrays.asList(context));
            SecurityTool.event("EXPLOIT_DEFAULT_TOKEN", kvs.toArray());
            return true;
        }
        return false;
    }


    // ---------------------- brute force / scan ----------------------

    private static final int BRUTE_FORCE_THRESHOLD = 10;
    private static final long BRUTE_FORCE_WINDOW = 60 * 1000L;
    private static final int TRACKER_MAX_SIZE = 10000;
    private static final ConcurrentMap<String, long[]> FAILURE_TRACKER = new ConcurrentHashMap<>();   // key -> [windowStart, count, alerted]

    /**
     * count a failure for (kind, source); raise BRUTE_FORCE_DETECTED once per window when threshold reached
     */
    public static void trackFailure(String kind, String source) {
        if (source == null) {
            return;
        }
        if (FAILURE_TRACKER.size() > TRACKER_MAX_SIZE) {
            FAILURE_TRACKER.clear();
        }
        String key = kind + "|" + stripPort(source);
        long now = System.currentTimeMillis();
        long[] state = FAILURE_TRACKER.compute(key, (k, v) -> {
            if (v == null || now - v[0] > BRUTE_FORCE_WINDOW) {
                v = new long[]{now, 0, 0};
            }
            v[1]++;
            return v;
        });
        boolean raise = false;
        synchronized (state) {
            if (state[1] >= BRUTE_FORCE_THRESHOLD && state[2] == 0) {
                state[2] = 1;
                raise = true;
            }
        }
        if (raise) {
            SecurityTool.event("BRUTE_FORCE_DETECTED", "kind", kind, "source", stripPort(source),
                    "failures", state[1], "windowSeconds", BRUTE_FORCE_WINDOW / 1000);
        }
    }

    /**
     * "/10.0.0.1:53422" -> "10.0.0.1"
     */
    public static String stripPort(String address) {
        if (address == null) {
            return null;
        }
        String result = address.startsWith("/") ? address.substring(1) : address;
        int bracket = result.indexOf(']');
        if (result.startsWith("[") && bracket > 0) {
            return result.substring(1, bracket);
        }
        int colon = result.lastIndexOf(':');
        if (colon > 0 && result.indexOf(':') == colon) {
            result = result.substring(0, colon);
        }
        return result;
    }


    // ---------------------- util ----------------------

    private static Set<String> parseCsv(String csv) {
        Set<String> result = new HashSet<>();
        if (csv != null) {
            for (String item : csv.split(",")) {
                if (!item.trim().isEmpty()) {
                    result.add(item.trim());
                }
            }
        }
        return Collections.unmodifiableSet(result);
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.trim().isEmpty()) {
                return value.trim();
            }
        }
        return null;
    }

}
