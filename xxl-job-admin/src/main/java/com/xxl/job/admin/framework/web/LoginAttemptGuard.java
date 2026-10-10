package com.xxl.job.admin.framework.web;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

/**
 * hardened build: login brute-force lockout, in-memory.
 *
 * Two independent limits, both must pass:
 * 1、username + source ip: {@link #USER_IP_MAX_FAIL} failures within {@link #WINDOW_MILLIS} lock that pair
 *    (a remote attacker can not lock out a legit admin from another ip);
 * 2、source ip: {@link #IP_MAX_FAIL} failures (any username, existing or not) within the window lock the ip,
 *    which stops random-username guessing / flooding from one source.
 *
 * Bounded memory without a lockout bypass: tables are never cleared; on overflow only expired, then unlocked
 * entries are evicted, locked entries are always kept. While an ip is locked no new entry is recorded for it,
 * so one source adds at most {@link #IP_MAX_FAIL} username entries per window.
 */
public class LoginAttemptGuard {

    public static final int USER_IP_MAX_FAIL = 5;
    public static final int IP_MAX_FAIL = 20;
    public static final long WINDOW_MILLIS = 15 * 60 * 1000L;
    public static final long LOCK_MILLIS = 15 * 60 * 1000L;
    static final int MAX_ENTRIES = 50000;
    private static final long EVICT_INTERVAL_MILLIS = 1000L;

    /**
     * lock state transition returned by {@link #recordFailure}
     */
    public enum LockResult { NONE, USER_IP_LOCKED, IP_LOCKED }

    private static final class Attempt {
        final int count;
        final long windowStart;
        final long lockUntil;
        Attempt(int count, long windowStart, long lockUntil) {
            this.count = count;
            this.windowStart = windowStart;
            this.lockUntil = lockUntil;
        }
    }

    private final ConcurrentMap<String, Attempt> byUserIp = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Attempt> byIp = new ConcurrentHashMap<>();
    private final AtomicLong lastEvict = new AtomicLong(0);
    private final LongSupplier clock;

    public LoginAttemptGuard() {
        this(System::currentTimeMillis);
    }

    LoginAttemptGuard(LongSupplier clock) {
        this.clock = clock;
    }

    private static String userIpKey(String userName, String ip) {
        return userName + "|" + ip;
    }

    public boolean isLocked(String userName, String ip) {
        long now = clock.getAsLong();
        return isLocked(byIp.get(ip), now) || isLocked(byUserIp.get(userIpKey(userName, ip)), now);
    }

    private static boolean isLocked(Attempt attempt, long now) {
        return attempt != null && attempt.lockUntil > now;
    }

    /**
     * record one failed login (call only when not locked)
     */
    public LockResult recordFailure(String userName, String ip) {
        long now = clock.getAsLong();
        evictIfNeeded(now);
        boolean userIpLocked = increment(byUserIp, userIpKey(userName, ip), USER_IP_MAX_FAIL, now);
        boolean ipLocked = increment(byIp, ip, IP_MAX_FAIL, now);
        if (ipLocked) {
            return LockResult.IP_LOCKED;
        }
        return userIpLocked ? LockResult.USER_IP_LOCKED : LockResult.NONE;
    }

    /**
     * successful login: reset the username + ip pair only; the ip counter is kept, so a valid account
     * can not be used to reset the ip limit while guessing other usernames
     */
    public void recordSuccess(String userName, String ip) {
        byUserIp.remove(userIpKey(userName, ip));
    }

    /**
     * @return true if this failure just reached the limit and locked the key
     */
    private static boolean increment(ConcurrentMap<String, Attempt> table, String key, int maxFail, long now) {
        boolean[] lockedNow = {false};
        table.compute(key, (k, v) -> {
            if (v == null || (v.lockUntil == 0 && now - v.windowStart > WINDOW_MILLIS) || (v.lockUntil > 0 && v.lockUntil <= now)) {
                v = new Attempt(0, now, 0);
            }
            int count = v.count + 1;
            long lockUntil = v.lockUntil;
            if (count >= maxFail && lockUntil == 0) {
                lockUntil = now + LOCK_MILLIS;
                lockedNow[0] = true;
            }
            return new Attempt(count, v.windowStart, lockUntil);
        });
        return lockedNow[0];
    }

    private void evictIfNeeded(long now) {
        if (byUserIp.size() < MAX_ENTRIES && byIp.size() < MAX_ENTRIES) {
            return;
        }
        long last = lastEvict.get();
        if (now - last < EVICT_INTERVAL_MILLIS || !lastEvict.compareAndSet(last, now)) {
            return;
        }
        evict(byUserIp, now);
        evict(byIp, now);
    }

    private static void evict(ConcurrentMap<String, Attempt> table, long now) {
        if (table.size() < MAX_ENTRIES) {
            return;
        }
        // 1、expired: lock over, or unlocked and window over
        table.entrySet().removeIf(e -> expired(e.getValue(), now));
        if (table.size() < MAX_ENTRIES) {
            return;
        }
        // 2、still full: drop unlocked counters, never a locked entry
        table.entrySet().removeIf(e -> e.getValue().lockUntil <= now);
    }

    private static boolean expired(Attempt attempt, long now) {
        if (attempt.lockUntil > 0) {
            return attempt.lockUntil <= now;
        }
        return now - attempt.windowStart > WINDOW_MILLIS;
    }

    int userIpEntries() {
        return byUserIp.size();
    }

    int ipEntries() {
        return byIp.size();
    }

}
