package com.xxl.job.core.security;

import com.xxl.job.core.executor.XxlJobExecutor;
import com.xxl.job.core.glue.GlueFactory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class SecurityToolTest {

    @Test
    public void weakToken() {
        assertTrue(SecurityTool.isWeakToken(null));
        assertTrue(SecurityTool.isWeakToken(""));
        assertTrue(SecurityTool.isWeakToken("default_token"));
        assertTrue(SecurityTool.isWeakToken("short_token_1234"));
        assertFalse(SecurityTool.isWeakToken("a8f3c2e9d1b7465f9e0c3a2b1d4e5f60"));
    }

    @Test
    public void safeEquals() {
        assertTrue(SecurityTool.safeEquals("abc", "abc"));
        assertFalse(SecurityTool.safeEquals("abc", "abd"));
        assertFalse(SecurityTool.safeEquals("abc", null));
        assertFalse(SecurityTool.safeEquals(null, null));
    }

    @Test
    public void matchCidrList() {
        assertTrue(SecurityTool.matchCidrList("10.1.2.3", ""));
        assertTrue(SecurityTool.matchCidrList("10.1.2.3", "10.0.0.0/8"));
        assertTrue(SecurityTool.matchCidrList("192.168.1.10", "10.0.0.0/8, 192.168.1.10"));
        assertTrue(SecurityTool.matchCidrList("172.16.5.1", "172.16.0.0/12"));
        assertFalse(SecurityTool.matchCidrList("172.32.0.1", "172.16.0.0/12"));
        assertFalse(SecurityTool.matchCidrList("11.0.0.1", "10.0.0.0/8"));
        assertFalse(SecurityTool.matchCidrList("999.0.0.1", "0.0.0.0/0"));
        // hostname never resolved, rejected when allowlist set
        assertFalse(SecurityTool.matchCidrList("evil.example.com", "0.0.0.0/0"));
        assertTrue(SecurityTool.matchCidrList("fd00::1", "fd00::/8"));
    }

    @Test
    public void glueDisabled() {
        XxlJobExecutor executor = new XxlJobExecutor();
        executor.setGlueEnabled(true);
        assertFalse(executor.getGlueEnabled());

        assertThrows(UnsupportedOperationException.class,
                () -> GlueFactory.getInstance().loadNewInstance("class A {}"));
    }

    @Test
    public void handlerAllowlist() {
        XxlJobExecutor executor = new XxlJobExecutor();
        // blank / not configured = fail closed: nothing is allowed
        assertFalse(executor.isHandlerAllowed("anyHandler"));
        assertFalse(executor.isHandlerAllowed("demoJobHandler"));

        // "*" = allow every business handler, but dangerous samples stay denied
        executor.setHandlerAllowlist("*");
        assertTrue(executor.isHandlerAllowed("anyHandler"));
        assertFalse(executor.isHandlerAllowed("commandJobHandler"));
        assertFalse(executor.isHandlerAllowed("httpJobHandler"));
        assertFalse(executor.isHandlerAllowed(null));

        // explicit list = only those names
        executor.setHandlerAllowlist("demoJobHandler, shardingJobHandler");
        assertTrue(executor.isHandlerAllowed("demoJobHandler"));
        assertTrue(executor.isHandlerAllowed("shardingJobHandler"));
        assertFalse(executor.isHandlerAllowed("anyHandler"));
        assertFalse(executor.isHandlerAllowed("commandJobHandler"));
        assertFalse(executor.isHandlerAllowed(null));

        // a dangerous handler runs only when named explicitly
        executor.setHandlerAllowlist("commandJobHandler");
        assertTrue(executor.isHandlerAllowed("commandJobHandler"));

        // blank again resets to fail-closed
        executor.setHandlerAllowlist("");
        assertFalse(executor.isHandlerAllowed("demoJobHandler"));
    }

}
