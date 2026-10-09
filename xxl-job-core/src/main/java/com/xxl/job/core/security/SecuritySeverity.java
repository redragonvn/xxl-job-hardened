package com.xxl.job.core.security;

import java.util.HashMap;
import java.util.Map;

/**
 * hardened build: security event severity
 */
public enum SecuritySeverity {

    INFO, LOW, MEDIUM, HIGH, CRITICAL;

    private static final Map<String, SecuritySeverity> EVENT_SEVERITY = new HashMap<>();
    static {
        // CRITICAL: near-certain attack / compromise
        put(CRITICAL, "CANARY_TOKEN_USED", "EXPLOIT_DEFAULT_TOKEN", "EXECUTOR_EXPLOIT_PROBE", "EXECUTOR_GLUE_REJECTED",
                "OPENAPI_JOB_MANAGE_REJECTED");
        // HIGH: likely attack or dangerous change
        put(HIGH, "EXECUTOR_HANDLER_REJECTED", "ADMIN_GLUE_REJECTED", "ADMIN_TRIGGER_ADDRESS_REJECTED", "OPENAPI_REGISTRY_REJECTED",
                "BRUTE_FORCE_DETECTED", "EXPLOIT_DEFAULT_CREDENTIAL", "ADMIN_LOGIN_LOCKED", "ADMIN_PRIVILEGED_CHANGE",
                "ADMIN_GLUE_JOB_PRESENT", "ADMIN_DEFAULT_PASSWORD", "ADMIN_RISKY_CONFIG", "EXECUTOR_SCAN",
                "PAYLOAD_RULE_MATCH", "PAYLOAD_CAPTURED");
        // MEDIUM: needs review
        put(MEDIUM, "EXECUTOR_AUTH_FAIL", "OPENAPI_AUTH_FAIL", "ADMIN_LOGIN_FAIL", "ADMIN_WEAK_TOKEN", "REGISTRY_NEW_ADDRESS",
                "ADMIN_DEFAULT_PASSWORD_RESET", "PAYLOAD_SUSPICIOUS");
        // LOW
        put(LOW, "ADMIN_LOGIN_SUCCESS");
    }

    private static void put(SecuritySeverity severity, String... events) {
        for (String event : events) {
            EVENT_SEVERITY.put(event, severity);
        }
    }

    public static SecuritySeverity of(String event) {
        SecuritySeverity severity = EVENT_SEVERITY.get(event);
        return severity != null ? severity : MEDIUM;
    }

    public static SecuritySeverity match(String name, SecuritySeverity defaultSeverity) {
        if (name != null) {
            for (SecuritySeverity item : values()) {
                if (item.name().equalsIgnoreCase(name.trim())) {
                    return item;
                }
            }
        }
        return defaultSeverity;
    }

}
