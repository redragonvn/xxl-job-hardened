package com.xxl.job.core.security;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class ThreatDetectorTest {

    @Test
    public void rulesFile() throws Exception {
        File file = File.createTempFile("payload-rules", ".txt");
        file.deleteOnExit();
        Files.write(file.toPath(), (
                "# comment\n" +
                "test_marker | CRITICAL | XXLJOB-TEST-MARKER-[0-9]+\n" +
                "bad_line_without_regex\n" +
                "bad_regex | HIGH | ([\n").getBytes(StandardCharsets.UTF_8));

        List<ThreatDetector.PayloadRule> rules = ThreatDetector.parseRules(file);
        assertEquals(1, rules.size());

        ThreatDetector.configureRulesPath(file.getAbsolutePath());
        assertEquals(1, ThreatDetector.ruleCount());

        List<String> findings = ThreatDetector.inspect("echo XXLJOB-TEST-MARKER-42", false);
        assertTrue(findings.contains("rule:test_marker:CRITICAL"));
        assertEquals(SecuritySeverity.CRITICAL, ThreatDetector.maxSeverity(findings));

        assertTrue(ThreatDetector.inspect("hello world", false).isEmpty());
    }

    @Test
    public void genericSignals() {
        StringBuilder blob = new StringBuilder();
        for (int i = 0; i < 300; i++) {
            blob.append((char) ('A' + (i * 7) % 26));
        }
        assertTrue(ThreatDetector.inspect(blob.toString(), false).contains("generic:encoded_blob"));

        assertTrue(ThreatDetector.inspect("a=1; b=2", true).contains("generic:shell_metachar"));
        assertFalse(ThreatDetector.inspect("a=1; b=2", false).contains("generic:shell_metachar"));
        assertTrue(ThreatDetector.inspect("x".repeat(3000), true).contains("generic:large_param"));
        assertTrue(ThreatDetector.inspect("plain-param-value", true).isEmpty());
    }

    @Test
    public void canaryAndDefaultToken() {
        ThreatDetector.configureCanaryTokens("canary_token_value_planted_in_fake_config_01");
        assertTrue(ThreatDetector.inspectPresentedToken("canary_token_value_planted_in_fake_config_01", "test"));
        assertTrue(ThreatDetector.inspectPresentedToken("default_token", "test"));
        assertFalse(ThreatDetector.inspectPresentedToken("some_wrong_but_random_token_value_123456", "test"));
        assertFalse(ThreatDetector.inspectPresentedToken(null, "test"));
        assertTrue(SecurityTool.eventCounters().get("CANARY_TOKEN_USED") >= 1);
        assertTrue(SecurityTool.eventCounters().get("EXPLOIT_DEFAULT_TOKEN") >= 1);
    }

    private static long bruteForceEvents() {
        return SecurityTool.eventCounters().getOrDefault("BRUTE_FORCE_DETECTED", 0L);
    }

    @Test
    public void bruteForce() {
        long before = bruteForceEvents();
        String source = "/10.9.8.7:51234";
        for (int i = 0; i < 25; i++) {
            ThreatDetector.trackFailure("unit-test", source);
        }
        // raised once per window
        assertEquals(before + 1, bruteForceEvents());
    }

    /**
     * a flood of other sources must not reset an attacker's in-progress counter (tracker is never cleared)
     */
    @Test
    public void bruteForceSurvivesFlood() {
        String attacker = "/10.66.66.66:40000";
        for (int i = 0; i < 9; i++) {
            ThreatDetector.trackFailure("unit-flood", attacker);
        }
        for (int i = 0; i < 60_000; i++) {
            ThreatDetector.trackFailure("unit-flood", "/100." + (i / 65536) + "." + ((i / 256) % 256) + "." + (i % 256) + ":1");
        }
        long before = bruteForceEvents();
        ThreatDetector.trackFailure("unit-flood", attacker);
        assertEquals(before + 1, bruteForceEvents());
    }

    @Test
    public void stripPort() {
        assertEquals("10.0.0.1", ThreatDetector.stripPort("/10.0.0.1:53422"));
        assertEquals("10.0.0.1", ThreatDetector.stripPort("10.0.0.1"));
        assertEquals("fd00::1", ThreatDetector.stripPort("[fd00::1]:9999"));
        assertEquals("fd00::1", ThreatDetector.stripPort("fd00::1"));
    }

    @Test
    public void captureAndChain() {
        long before = SecurityTool.chainSeq();
        List<String> findings = ThreatDetector.inspectAndCapture("unit-test", "glueSource", "echo hello", true, "jobId", 1);
        assertTrue(findings.isEmpty());
        assertEquals(before + 1, SecurityTool.chainSeq());
        assertTrue(SecurityTool.eventCounters().get("PAYLOAD_CAPTURED") >= 1);

        // nothing found & not forced: no event
        ThreatDetector.inspectAndCapture("unit-test", "executorParam", "plain", false);
        assertEquals(before + 1, SecurityTool.chainSeq());
    }

}
