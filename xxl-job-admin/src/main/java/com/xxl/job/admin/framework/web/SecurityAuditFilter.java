package com.xxl.job.admin.framework.web;

import com.xxl.job.core.security.SecurityTool;
import com.xxl.sso.core.helper.XxlSsoHelper;
import com.xxl.sso.core.model.LoginInfo;
import com.xxl.tool.response.Response;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * hardened build: request context for security / audit log (MDC: remote, ua), and audit of privileged admin changes
 * (user / executor group), which are typical persistence steps after an admin account takeover.
 */
@Component
public class SecurityAuditFilter implements Filter {

    private static final Set<String> PRIVILEGED_PATHS = Set.of(
            "/user/insert", "/user/update", "/user/delete",
            "/jobgroup/insert", "/jobgroup/update", "/jobgroup/delete");

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        MDC.put("remote", request.getRemoteAddr());
        MDC.put("ua", truncate(request.getHeader("User-Agent"), 200));
        try {
            chain.doFilter(servletRequest, servletResponse);
        } finally {
            try {
                String path = request.getServletPath();
                if (PRIVILEGED_PATHS.contains(path)) {
                    Response<LoginInfo> loginInfoResponse = XxlSsoHelper.loginCheckWithAttr(request);
                    String operator = loginInfoResponse!=null && loginInfoResponse.getData()!=null ? loginInfoResponse.getData().getUserName() : null;
                    String params = maskedParams(request);
                    SecurityTool.event("ADMIN_PRIVILEGED_CHANGE", "operator", operator, "path", path,
                            "status", response.getStatus(), "remote", request.getRemoteAddr(), "params", params);
                    SecurityTool.AUDIT_LOGGER.info(">>>>>>>>>>> xxl-job operation log: operator = {}, type = {}, content = {}",
                            operator, path, params);
                }
            } finally {
                MDC.remove("remote");
                MDC.remove("ua");
            }
        }
    }

    private static String maskedParams(HttpServletRequest request) {
        Map<String, String> result = new TreeMap<>();
        for (Map.Entry<String, String[]> item : request.getParameterMap().entrySet()) {
            String key = item.getKey();
            String lowerKey = key.toLowerCase();
            String value = String.join(",", item.getValue());
            if (lowerKey.contains("password") || lowerKey.contains("token")) {
                value = SecurityTool.mask(value);
            }
            result.put(key, value);
        }
        return result.toString();
    }

    private static String truncate(String value, int max) {
        if (value == null) {
            return "";
        }
        return value.length() > max ? value.substring(0, max) : value;
    }

}
