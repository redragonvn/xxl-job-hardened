package com.xxl.job.core.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * hardened build: shared security helpers (token checks, security event log, cidr match)
 */
public class SecurityTool {

    /**
     * dedicated logger for security events, route to SIEM via logback appender "xxl-job-security"
     */
    public static final Logger SECURITY_LOGGER = LoggerFactory.getLogger("xxl-job-security");

    /**
     * dedicated logger for operation audit (who changed / triggered what), logback appender "xxl-job-audit"
     */
    public static final Logger AUDIT_LOGGER = LoggerFactory.getLogger("xxl-job-audit");

    public static final int TOKEN_MIN_LENGTH = 32;

    private static final Set<String> WEAK_TOKENS = new HashSet<>(Arrays.asList(
            "default_token", "xxl-job", "xxl_job", "xxljob", "token", "accesstoken", "access_token", "changeme", "change_me"
    ));


    /**
     * constant-time string compare
     */
    public static boolean safeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * token blank, too short, or known default
     */
    public static boolean isWeakToken(String token) {
        if (token == null || token.trim().length() < TOKEN_MIN_LENGTH) {
            return true;
        }
        return WEAK_TOKENS.contains(token.trim().toLowerCase());
    }

    /**
     * well-known default token, used by public exploits / scanners
     */
    public static boolean isKnownDefaultToken(String token) {
        return token != null && WEAK_TOKENS.contains(token.trim().toLowerCase());
    }

    public static String weakTokenMsg() {
        return "accessToken is weak (blank, default value, or shorter than " + TOKEN_MIN_LENGTH + " chars), rejected by hardened build.";
    }

    /**
     * mask secret for logging
     */
    public static String mask(String secret) {
        if (secret == null || secret.isEmpty()) {
            return "<empty>";
        }
        return "****(len=" + secret.length() + ")";
    }

    // ---------------------- security event ----------------------

    /**
     * per event-type counter, exposed by posture / metrics endpoint
     */
    private static final ConcurrentMap<String, AtomicLong> EVENT_COUNTERS = new ConcurrentHashMap<>();

    /**
     * tamper-evident hash chain: chain_n = sha256(chain_{n-1} + "|" + payload_n); deleting / editing a line breaks the chain
     */
    private static final Object CHAIN_LOCK = new Object();
    private static long chainSeq = 0;
    private static String chainHead = null;

    /**
     * write one security event, single line "severity=xx event=xx k=v ... seq=n chain=hex" for easy SIEM parsing
     *
     * @param event     event type, such as GLUE_REJECTED / AUTH_FAIL, severity mapped by {@link SecuritySeverity#of(String)}
     * @param kvs       key, value, key, value ...
     */
    public static void event(String event, Object... kvs) {
        eventAt(null, event, kvs);
    }

    /**
     * @param minSeverity   raise severity to at least this level (e.g. matched rule severity), null to use event default
     */
    public static void eventAt(SecuritySeverity minSeverity, String event, Object... kvs) {
        SecuritySeverity severity = SecuritySeverity.of(event);
        if (minSeverity != null && minSeverity.ordinal() > severity.ordinal()) {
            severity = minSeverity;
        }
        Map<String, String> fields = new LinkedHashMap<>();
        StringBuilder sb = new StringBuilder("severity=").append(severity.name()).append(" event=").append(event);
        for (int i = 0; i + 1 < kvs.length; i += 2) {
            String value = quote(kvs[i + 1]);
            sb.append(' ').append(kvs[i]).append('=').append(value);
            fields.put(String.valueOf(kvs[i]), value.substring(1, value.length() - 1));
        }
        EVENT_COUNTERS.computeIfAbsent(event, k -> new AtomicLong()).incrementAndGet();

        String line;
        synchronized (CHAIN_LOCK) {
            if (chainHead == null) {
                // chain genesis, random per process start
                chainHead = sha256Hex("xxl-job-security-genesis|" + UUID.randomUUID());
                String genesis = "severity=INFO event=SECURITY_LOG_CHAIN_START seq=0 genesis=\"" + chainHead + "\"";
                SECURITY_LOGGER.warn(genesis);
            }
            chainSeq++;
            sb.append(" seq=").append(chainSeq);
            String payload = sb.toString();
            chainHead = sha256Hex(chainHead + "|" + payload);
            line = payload + " chain=" + chainHead.substring(0, 16);
            SECURITY_LOGGER.warn(line);
        }

        SecurityAlerter.dispatch(severity, event, fields);
    }

    public static Map<String, Long> eventCounters() {
        Map<String, Long> result = new java.util.TreeMap<>();
        for (Map.Entry<String, AtomicLong> item : EVENT_COUNTERS.entrySet()) {
            result.put(item.getKey(), item.getValue().get());
        }
        return result;
    }

    public static long chainSeq() {
        synchronized (CHAIN_LOCK) {
            return chainSeq;
        }
    }

    public static String sha256Hex(String text) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String quote(Object value) {
        String str = String.valueOf(value);
        str = str.replace("\\", "\\\\").replace("\"", "\\\"").replace("\r", "\\r").replace("\n", "\\n");
        if (str.length() > 512) {
            str = str.substring(0, 512) + "...";
        }
        return "\"" + str + "\"";
    }


    // ---------------------- cidr ----------------------

    /**
     * match host against comma-separated cidr / ip list; blank list means allow all
     */
    public static boolean matchCidrList(String host, String cidrList) {
        if (cidrList == null || cidrList.trim().isEmpty()) {
            return true;
        }
        if (host == null || host.trim().isEmpty()) {
            return false;
        }
        byte[] hostBytes = toLiteralIp(host.trim());
        if (hostBytes == null) {
            return false;
        }
        for (String item : cidrList.split(",")) {
            item = item.trim();
            if (item.isEmpty()) {
                continue;
            }
            String[] parts = item.split("/");
            byte[] netBytes = toLiteralIp(parts[0].trim());
            if (netBytes == null || netBytes.length != hostBytes.length) {
                continue;
            }
            int prefix = netBytes.length * 8;
            if (parts.length == 2) {
                try {
                    prefix = Integer.parseInt(parts[1].trim());
                } catch (NumberFormatException e) {
                    continue;
                }
            }
            if (prefixMatch(hostBytes, netBytes, prefix)) {
                return true;
            }
        }
        return false;
    }

    private static boolean prefixMatch(byte[] a, byte[] b, int prefix) {
        if (prefix < 0 || prefix > a.length * 8) {
            return false;
        }
        int fullBytes = prefix / 8;
        for (int i = 0; i < fullBytes; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        int remainBits = prefix % 8;
        if (remainBits == 0) {
            return true;
        }
        int mask = (0xFF << (8 - remainBits)) & 0xFF;
        return (a[fullBytes] & mask) == (b[fullBytes] & mask);
    }

    /**
     * parse ip literal only, never do dns lookup
     */
    private static byte[] toLiteralIp(String ip) {
        if (ip.startsWith("[") && ip.endsWith("]")) {
            ip = ip.substring(1, ip.length() - 1);
        }
        boolean ipv4 = ip.matches("^\\d{1,3}(\\.\\d{1,3}){3}$");
        boolean ipv6 = ip.contains(":") && ip.matches("^[0-9a-fA-F:.]+$");
        if (!ipv4 && !ipv6) {
            return null;
        }
        if (ipv4) {
            for (String octet : ip.split("\\.")) {
                if (Integer.parseInt(octet) > 255) {
                    return null;
                }
            }
        }
        try {
            return InetAddress.getByName(ip).getAddress();
        } catch (Exception e) {
            return null;
        }
    }

}
