package com.xxl.job.admin.framework.web;

import org.junit.jupiter.api.Test;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

public class LoginAttemptGuardTest {

    private final AtomicLong now = new AtomicLong(1_000_000L);

    /**
     * same order as LoginController: locked -> reject without recording; otherwise record the failure
     */
    private void failedLogin(LoginAttemptGuard guard, String user, String ip) {
        if (!guard.isLocked(user, ip)) {
            guard.recordFailure(user, ip);
        }
        now.addAndGet(2);   // 2ms per attempt
    }

    private static String randomUser() {
        return "u" + UUID.randomUUID().toString().replace("-", "");
    }

    @Test
    public void userIpLock() {
        LoginAttemptGuard guard = new LoginAttemptGuard(now::get);
        for (int i = 0; i < LoginAttemptGuard.USER_IP_MAX_FAIL; i++) {
            assertFalse(guard.isLocked("admin", "10.0.0.1"));
            failedLogin(guard, "admin", "10.0.0.1");
        }
        assertTrue(guard.isLocked("admin", "10.0.0.1"));
        // other source not affected: no remote lockout of a legit admin
        assertFalse(guard.isLocked("admin", "10.0.0.2"));

        now.addAndGet(LoginAttemptGuard.LOCK_MILLIS + 1);
        assertFalse(guard.isLocked("admin", "10.0.0.1"));
    }

    @Test
    public void ipLockStopsRandomUsernames() {
        LoginAttemptGuard guard = new LoginAttemptGuard(now::get);
        for (int i = 0; i < LoginAttemptGuard.IP_MAX_FAIL; i++) {
            failedLogin(guard, randomUser(), "10.0.0.9");
        }
        assertTrue(guard.isLocked(randomUser(), "10.0.0.9"));
        assertTrue(guard.isLocked("admin", "10.0.0.9"));
    }

    /**
     * auditor finding: flood with random usernames to overflow the table and reset the lock on "admin"
     */
    @Test
    public void floodFromSameIpCannotResetLock() {
        LoginAttemptGuard guard = new LoginAttemptGuard(now::get);
        for (int i = 0; i < LoginAttemptGuard.USER_IP_MAX_FAIL; i++) {
            failedLogin(guard, "admin", "10.0.0.1");
        }
        assertTrue(guard.isLocked("admin", "10.0.0.1"));

        for (int i = 0; i < 100_000; i++) {
            failedLogin(guard, randomUser(), "10.0.0.1");
        }
        assertTrue(guard.isLocked("admin", "10.0.0.1"));
        // memory bounded: the ip locks after IP_MAX_FAIL failures, nothing is recorded while locked
        assertTrue(guard.userIpEntries() <= LoginAttemptGuard.IP_MAX_FAIL, "entries: " + guard.userIpEntries());
        assertEquals(1, guard.ipEntries());
    }

    @Test
    public void floodFromManyIpsCannotResetLock() {
        LoginAttemptGuard guard = new LoginAttemptGuard(now::get);
        for (int i = 0; i < LoginAttemptGuard.USER_IP_MAX_FAIL; i++) {
            failedLogin(guard, "admin", "10.0.0.1");
        }

        // > MAX_ENTRIES distinct (username, ip) pairs from 4000 sources
        int sources = 4000;
        for (int s = 0; s < sources; s++) {
            String ip = "172.16." + (s / 250) + "." + (s % 250);
            for (int i = 0; i < LoginAttemptGuard.IP_MAX_FAIL; i++) {
                failedLogin(guard, randomUser(), ip);
            }
        }
        assertTrue(guard.isLocked("admin", "10.0.0.1"), "locked entry must survive eviction");
        // every flooding source is itself locked
        assertTrue(guard.isLocked(randomUser(), "172.16.0.0"));
        assertTrue(guard.isLocked(randomUser(), "172.16.15.249"));
    }

    @Test
    public void successResetsOnlyUserIpPair() {
        LoginAttemptGuard guard = new LoginAttemptGuard(now::get);
        for (int i = 0; i < LoginAttemptGuard.IP_MAX_FAIL - 1; i++) {
            failedLogin(guard, randomUser(), "10.0.0.5");
        }
        // a valid login with another account must not reset the ip counter
        guard.recordSuccess("validuser", "10.0.0.5");
        failedLogin(guard, randomUser(), "10.0.0.5");
        assertTrue(guard.isLocked(randomUser(), "10.0.0.5"));
    }

    @Test
    public void windowExpiryResetsCounter() {
        LoginAttemptGuard guard = new LoginAttemptGuard(now::get);
        for (int i = 0; i < LoginAttemptGuard.USER_IP_MAX_FAIL - 1; i++) {
            failedLogin(guard, "admin", "10.0.0.7");
        }
        now.addAndGet(LoginAttemptGuard.WINDOW_MILLIS + 1);
        failedLogin(guard, "admin", "10.0.0.7");
        assertFalse(guard.isLocked("admin", "10.0.0.7"));
    }

}
