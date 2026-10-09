package com.xxl.job.admin.framework.controller;

import com.xxl.job.admin.framework.constant.Consts;
import com.xxl.job.admin.framework.web.SecurityStartupCheck;
import com.xxl.job.core.security.SecurityTool;
import com.xxl.sso.core.annotation.XxlSso;
import com.xxl.tool.response.Response;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;
import java.util.Map;

/**
 * hardened build: security posture (admin only) and prometheus metrics (bearer token)
 */
@Controller
@RequestMapping("/security")
public class SecurityController {

    @Resource
    private SecurityStartupCheck securityStartupCheck;

    @RequestMapping("/posture")
    @ResponseBody
    @XxlSso(role = Consts.ADMIN_ROLE)
    public Response<Map<String, Object>> posture() {
        return Response.ofSuccess(securityStartupCheck.posture());
    }

    /**
     * prometheus text format; disabled unless "xxl.job.security.metrics-token" (min 32 chars) is set,
     * scrape with header "Authorization: Bearer {token}"
     */
    @RequestMapping(value = "/metrics", produces = "text/plain; version=0.0.4; charset=utf-8")
    @ResponseBody
    @XxlSso(login = false)
    public String metrics(HttpServletRequest request, HttpServletResponse response) {
        String authorization = request.getHeader("Authorization");
        String presented = authorization != null && authorization.startsWith("Bearer ") ? authorization.substring(7).trim() : null;
        if (!securityStartupCheck.isMetricsTokenValid(presented)) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            return "";
        }

        Map<String, Object> posture = securityStartupCheck.posture();
        StringBuilder sb = new StringBuilder();
        sb.append("# HELP xxljob_security_events_total Security events by type since process start.\n");
        sb.append("# TYPE xxljob_security_events_total counter\n");
        for (Map.Entry<String, Long> item : SecurityTool.eventCounters().entrySet()) {
            sb.append("xxljob_security_events_total{event=\"").append(item.getKey()).append("\"} ").append(item.getValue()).append('\n');
        }
        gauge(sb, "xxljob_security_default_admin_password", "1 if admin still uses default password.", Boolean.TRUE.equals(posture.get("defaultAdminPassword")) ? 1 : 0);
        gauge(sb, "xxljob_security_weak_token_groups", "Executor groups with weak accessToken.", ((List<?>) posture.get("weakTokenGroups")).size());
        gauge(sb, "xxljob_security_glue_jobs", "GLUE jobs still present in db.", ((List<?>) posture.get("glueJobIds")).size());
        gauge(sb, "xxljob_security_openapi_job_manage_enabled", "1 if openapi job management enabled.", Boolean.TRUE.equals(posture.get("openapiJobManageEnabled")) ? 1 : 0);
        gauge(sb, "xxljob_security_payload_rules", "Loaded payload rules.", ((Number) posture.get("payloadRuleCount")).longValue());
        gauge(sb, "xxljob_security_log_chain_seq", "Security log hash chain sequence.", SecurityTool.chainSeq());
        return sb.toString();
    }

    private static void gauge(StringBuilder sb, String name, String help, long value) {
        sb.append("# HELP ").append(name).append(' ').append(help).append('\n');
        sb.append("# TYPE ").append(name).append(" gauge\n");
        sb.append(name).append(' ').append(value).append('\n');
    }

}
