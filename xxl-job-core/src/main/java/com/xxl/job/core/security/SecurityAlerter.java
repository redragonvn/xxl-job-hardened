package com.xxl.job.core.security;

import com.xxl.tool.json.GsonTool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * hardened build: push security events (>= min severity) to a webhook (SIEM / SOAR / chat-ops), async and bounded.
 *
 * config by env / system property:
 *      XXL_JOB_SECURITY_ALERT_WEBHOOK      (-Dxxl.job.security.alert.webhook-url)
 *      XXL_JOB_SECURITY_ALERT_MIN_SEVERITY (-Dxxl.job.security.alert.min-severity), default HIGH
 */
public class SecurityAlerter {
    private static final Logger logger = LoggerFactory.getLogger(SecurityAlerter.class);

    private static volatile String webhookUrl = firstNonBlank(System.getenv("XXL_JOB_SECURITY_ALERT_WEBHOOK"), System.getProperty("xxl.job.security.alert.webhook-url"));
    private static volatile SecuritySeverity minSeverity = SecuritySeverity.match(
            firstNonBlank(System.getenv("XXL_JOB_SECURITY_ALERT_MIN_SEVERITY"), System.getProperty("xxl.job.security.alert.min-severity")),
            SecuritySeverity.HIGH);
    private static volatile String source = "xxl-job";

    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
    private static final ThreadPoolExecutor ALERT_POOL = new ThreadPoolExecutor(1, 1, 60L, TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(1000),
            r -> {
                Thread thread = new Thread(r, "xxl-job, SecurityAlerter");
                thread.setDaemon(true);
                return thread;
            },
            new ThreadPoolExecutor.DiscardPolicy());

    /**
     * override config (blank value keeps env / system property config)
     */
    public static void configure(String url, String severity, String sourceName) {
        if (url != null && !url.trim().isEmpty()) {
            webhookUrl = url.trim();
        }
        if (severity != null && !severity.trim().isEmpty()) {
            minSeverity = SecuritySeverity.match(severity, minSeverity);
        }
        if (sourceName != null && !sourceName.trim().isEmpty()) {
            source = sourceName.trim();
        }
    }

    public static boolean isConfigured() {
        return webhookUrl != null;
    }

    static void dispatch(SecuritySeverity severity, String event, Map<String, String> fields) {
        final String url = webhookUrl;
        if (url == null || severity.ordinal() < minSeverity.ordinal()) {
            return;
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("source", source);
        body.put("host", hostname());
        body.put("time", OffsetDateTime.now().toString());
        body.put("severity", severity.name());
        body.put("event", event);
        body.put("fields", fields);
        final String json = GsonTool.toJson(body);

        if (ALERT_POOL.getQueue().remainingCapacity() == 0) {
            logger.warn(">>>>>>>>>>> xxl-job security alert queue full, alert dropped, event:{}", event);
            return;
        }
        ALERT_POOL.execute(() -> {
            try {
                HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                        .timeout(Duration.ofSeconds(5))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(json))
                        .build();
                HttpResponse<Void> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.discarding());
                if (response.statusCode() >= 300) {
                    logger.warn(">>>>>>>>>>> xxl-job security alert webhook response code:{}", response.statusCode());
                }
            } catch (Throwable e) {
                logger.warn(">>>>>>>>>>> xxl-job security alert webhook error:{}", e.getMessage());
            }
        });
    }

    private static volatile String hostname;
    private static String hostname() {
        if (hostname == null) {
            try {
                hostname = InetAddress.getLocalHost().getHostName();
            } catch (Exception e) {
                hostname = "unknown";
            }
        }
        return hostname;
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
