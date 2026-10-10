package com.xxl.job.admin.business.scheduler.openapi;

import com.xxl.job.core.constant.RegistTypeEnum;
import com.xxl.job.core.openapi.admin.dto.RegistryRequest;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;

/**
 * hardened build: test the executor registry whitelist — the gate that controls which hosts may
 * register (and therefore become a node the admin RPC-connects to and dispatches jobs to).
 *
 * Invokes the real {@code OpenApiController.validRegistry} (private) so the production decision is
 * exercised directly, including {@code xxl.job.registry.allowed-cidrs} enforcement and the
 * cross-group / scheme / DNS-rebinding guards. No Spring context or DB is needed: validRegistry only
 * reads the controller's own cidr field and uses RegistTypeEnum / URI / SecurityTool.
 */
public class RegistryWhitelistTest {

    private final Method validRegistry;
    private final Field cidrField;

    public RegistryWhitelistTest() throws Exception {
        validRegistry = OpenApiController.class.getDeclaredMethod("validRegistry", RegistryRequest.class, String.class);
        validRegistry.setAccessible(true);
        cidrField = OpenApiController.class.getDeclaredField("registryAllowedCidrs");
        cidrField.setAccessible(true);
    }

    /** @return null when the registration is accepted, otherwise the rejection reason */
    private String check(String allowedCidrs, String registryGroup, String registryKey, String registryValue, String appname) throws Exception {
        OpenApiController controller = new OpenApiController();
        cidrField.set(controller, allowedCidrs);
        RegistryRequest req = null;
        if (registryGroup != null || registryKey != null || registryValue != null) {
            req = new RegistryRequest();
            req.setRegistryGroup(registryGroup);
            req.setRegistryKey(registryKey);
            req.setRegistryValue(registryValue);
        }
        return (String) validRegistry.invoke(controller, req, appname);
    }

    private static final String EXEC = RegistTypeEnum.EXECUTOR.name();

    // ---------------- whitelist (allowed-cidrs) ----------------

    @Test
    void inRangeExecutorRegisteringItselfIsAccepted() throws Exception {
        assertNull(check("10.0.0.0/8", EXEC, "my-app", "http://10.1.2.3:9999/", "my-app"),
                "an executor in the allowed CIDR registering its own appname must be accepted");
    }

    @Test
    void outOfRangeHostIsRejected() throws Exception {
        assertEquals("registryValue host not in allowed cidrs.",
                check("10.0.0.0/8", EXEC, "my-app", "http://192.168.5.5:9999/", "my-app"),
                "a host outside the allowed CIDR must be rejected (off-network executor)");
    }

    @Test
    void blankWhitelistAllowsAnyIp() throws Exception {
        assertNull(check("", EXEC, "my-app", "http://203.0.113.9:9999/", "my-app"),
                "a blank allowlist means allow-all (documented default)");
        assertNull(check(null, EXEC, "my-app", "http://203.0.113.9:9999/", "my-app"));
    }

    @Test
    void hostnameIsRejectedWhenWhitelistSet_noDnsRebinding() throws Exception {
        // matchCidrList never resolves DNS, so a hostname cannot slip past an IP allowlist
        assertEquals("registryValue host not in allowed cidrs.",
                check("0.0.0.0/0", EXEC, "my-app", "http://evil.example.com:9999/", "my-app"),
                "a hostname must not be resolved to pass the IP whitelist");
    }

    @Test
    void multipleCidrsAndExactIpAreHonoured() throws Exception {
        assertNull(check("10.0.0.0/8, 192.168.1.10", EXEC, "my-app", "http://192.168.1.10:9999/", "my-app"));
        assertEquals("registryValue host not in allowed cidrs.",
                check("10.0.0.0/8, 192.168.1.10", EXEC, "my-app", "http://192.168.1.11:9999/", "my-app"));
    }

    // ---------------- cross-group / spoofing guards ----------------

    @Test
    void crossGroupRegistrationIsRejected() throws Exception {
        assertEquals("registryKey must equal authenticated appname.",
                check("0.0.0.0/0", EXEC, "other-group", "http://10.1.2.3:9999/", "my-app"),
                "an executor must not register into a group it did not authenticate as");
    }

    @Test
    void nonExecutorRegistryGroupIsRejected() throws Exception {
        assertEquals("registryGroup invalid.",
                check("0.0.0.0/0", "ADMIN", "my-app", "http://10.1.2.3:9999/", "my-app"));
    }

    @Test
    void nonHttpSchemeIsRejected() throws Exception {
        assertEquals("registryValue must be http(s) address.",
                check("0.0.0.0/0", EXEC, "my-app", "file:///etc/passwd", "my-app"),
                "a non-http(s) registry value must be rejected");
    }

    @Test
    void nullAndMalformedParamsAreRejected() throws Exception {
        assertEquals("registry param empty.", check("0.0.0.0/0", null, null, null, "my-app"));
        assertEquals("registryValue invalid.",
                check("0.0.0.0/0", EXEC, "my-app", "ht tp://bad uri", "my-app"));
    }
}
