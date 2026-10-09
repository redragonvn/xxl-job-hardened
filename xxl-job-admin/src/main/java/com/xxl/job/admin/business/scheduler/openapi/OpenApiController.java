package com.xxl.job.admin.business.scheduler.openapi;

import com.xxl.job.admin.business.model.XxlJobGroup;
import com.xxl.job.admin.business.scheduler.config.XxlJobAdminBootstrap;
import com.xxl.job.core.constant.Const;
import com.xxl.job.core.constant.RegistTypeEnum;
import com.xxl.job.core.openapi.admin.AdminBiz;
import com.xxl.job.core.openapi.admin.AdminJobBiz;
import com.xxl.job.core.openapi.admin.dto.CallbackRequest;
import com.xxl.job.core.openapi.admin.dto.JobAddRequest;
import com.xxl.job.core.openapi.admin.dto.JobOperateRequest;
import com.xxl.job.core.openapi.admin.dto.JobTriggerRequest;
import com.xxl.job.core.openapi.admin.dto.JobUpdateRequest;
import com.xxl.job.core.openapi.admin.dto.RegistryRequest;
import com.xxl.job.core.security.SecurityTool;
import com.xxl.job.core.security.ThreatDetector;
import com.xxl.sso.core.annotation.XxlSso;
import com.xxl.tool.core.StringTool;
import com.xxl.tool.json.GsonTool;
import com.xxl.tool.response.Response;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Created by xuxueli on 17/5/10.
 */
@Controller
public class OpenApiController {

    @Resource
    private AdminBiz adminBiz;

    @Resource
    private AdminJobBiz adminJobBiz;

    /**
     * hardened build: job management api (addJob/updateJob/removeJob/startJob/stopJob/triggerJob) shares the executor accessToken,
     * any executor host holding the token could manage jobs of its group; disabled by default.
     */
    @Value("${xxl.job.openapi.job-manage.enabled:false}")
    private boolean jobManageEnabled;

    /**
     * hardened build: allowed executor registry ip / cidr list, comma-separated; blank means allow all.
     */
    @Value("${xxl.job.registry.allowed-cidrs:}")
    private String registryAllowedCidrs;

    private static final Set<String> JOB_MANAGE_URIS = new HashSet<>(Arrays.asList(
            "addJob", "updateJob", "removeJob", "startJob", "stopJob", "triggerJob"));

    /**
     * api
     */
    @RequestMapping("/api/{uri}")
    @ResponseBody
    @XxlSso(login = false)
    public Object api(HttpServletRequest request,
                      @PathVariable("uri") String uri,
                      @RequestHeader(value = Const.XXL_JOB_ACCESS_TOKEN, required = false) String accessToken,
                      @RequestHeader(value = Const.XXL_JOB_APPNAME, required = false) String appname,
                      @RequestBody(required = false) String requestBody) {

        // valid
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            return Response.ofFail("invalid request, HttpMethod not support.");
        }
        if (StringTool.isBlank(uri)) {
            return Response.ofFail("invalid request, uri-mapping empty.");
        }
        if (StringTool.isBlank(requestBody)) {
            return Response.ofFail("invalid request, requestBody empty.");
        }

        // valid: appname + accessToken
        String remote = request.getRemoteAddr();
        if (StringTool.isBlank(accessToken) || StringTool.isBlank(appname)) {
            SecurityTool.event("OPENAPI_AUTH_FAIL", "reason", "token or appname empty", "remote", remote, "uri", uri);
            ThreatDetector.trackFailure("openapi-auth", remote);
            return Response.ofFail("invalid request, accessToken or appname is empty.");
        }
        XxlJobGroup xxlJobGroup = XxlJobAdminBootstrap.getInstance().getJobRegistryHelper().loadByAppName(appname);
        if (!(xxlJobGroup!=null && SecurityTool.safeEquals(accessToken, xxlJobGroup.getAccessToken()))) {
            SecurityTool.event("OPENAPI_AUTH_FAIL", "reason", xxlJobGroup==null?"appname not found":"token invalid",
                    "remote", remote, "uri", uri, "appname", appname);
            ThreatDetector.trackFailure("openapi-auth", remote);
            ThreatDetector.inspectPresentedToken(accessToken, "admin-openapi", "remote", remote, "uri", uri, "appname", appname);
            captureJobPayload("admin-openapi-unauth", uri, requestBody, "remote", remote, "appname", appname);
            return Response.ofFail("invalid request, accessToken or appname invalid.");
        }
        // hardened build: weak group token is never accepted
        if (SecurityTool.isWeakToken(xxlJobGroup.getAccessToken())) {
            SecurityTool.event("ADMIN_WEAK_TOKEN", "action", "openapi", "remote", remote, "uri", uri, "appname", appname);
            ThreatDetector.inspectPresentedToken(accessToken, "admin-openapi", "remote", remote, "uri", uri, "appname", appname);
            return Response.ofFail("invalid request, executor group " + SecurityTool.weakTokenMsg());
        }
        // hardened build: job management api disabled by default
        if (JOB_MANAGE_URIS.contains(uri) && !jobManageEnabled) {
            SecurityTool.event("OPENAPI_JOB_MANAGE_REJECTED", "remote", remote, "uri", uri, "appname", appname);
            // executor token used to manage jobs: token holder (executor host) likely compromised, keep payload as evidence
            captureJobPayload("admin-openapi-job-manage", uri, requestBody, "remote", remote, "appname", appname);
            return Response.ofFail("invalid request, openapi job management is disabled in hardened build.");
        }

        // dispatch request
        try {
            switch (uri) {
                case "callback": {
                    CallbackRequest callbackParam = GsonTool.fromJson(requestBody, CallbackRequest.class);
                    return adminBiz.callback(callbackParam);
                }
                case "registry": {
                    RegistryRequest registryParam = GsonTool.fromJson(requestBody, RegistryRequest.class);
                    String registryInvalid = validRegistry(registryParam, appname);
                    if (registryInvalid != null) {
                        SecurityTool.event("OPENAPI_REGISTRY_REJECTED", "reason", registryInvalid, "remote", remote, "appname", appname,
                                "registryKey", registryParam==null?null:registryParam.getRegistryKey(),
                                "registryValue", registryParam==null?null:registryParam.getRegistryValue());
                        return Response.ofFail("invalid request, " + registryInvalid);
                    }
                    // hardened build: first-seen executor address
                    List<String> registryList = xxlJobGroup.getRegistryList();
                    if (registryList == null || !registryList.contains(registryParam.getRegistryValue())) {
                        SecurityTool.event("REGISTRY_NEW_ADDRESS", "remote", remote, "appname", appname,
                                "registryValue", registryParam.getRegistryValue(), "knownAddresses", registryList==null?0:registryList.size());
                    }
                    return adminBiz.registry(registryParam);
                }
                case "registryRemove": {
                    RegistryRequest registryParam = GsonTool.fromJson(requestBody, RegistryRequest.class);
                    String registryInvalid = validRegistry(registryParam, appname);
                    if (registryInvalid != null) {
                        SecurityTool.event("OPENAPI_REGISTRY_REJECTED", "reason", registryInvalid, "remote", remote, "appname", appname,
                                "registryKey", registryParam==null?null:registryParam.getRegistryKey(),
                                "registryValue", registryParam==null?null:registryParam.getRegistryValue());
                        return Response.ofFail("invalid request, " + registryInvalid);
                    }
                    return adminBiz.registryRemove(registryParam);
                    }
                case "addJob": {
                    JobAddRequest jobParam = GsonTool.fromJson(requestBody, JobAddRequest.class);
                    return adminJobBiz.addJob(jobParam);
                }
                case "updateJob": {
                    JobUpdateRequest jobParam = GsonTool.fromJson(requestBody, JobUpdateRequest.class);
                    return adminJobBiz.updateJob(jobParam);
                }
                case "removeJob": {
                    JobOperateRequest jobParam = GsonTool.fromJson(requestBody, JobOperateRequest.class);
                    return adminJobBiz.removeJob(jobParam);
                }
                case "startJob": {
                    JobOperateRequest jobParam = GsonTool.fromJson(requestBody, JobOperateRequest.class);
                    return adminJobBiz.startJob(jobParam);
                }
                case "stopJob": {
                    JobOperateRequest jobParam = GsonTool.fromJson(requestBody, JobOperateRequest.class);
                    return adminJobBiz.stopJob(jobParam);
                }
                case "triggerJob": {
                    JobTriggerRequest jobParam = GsonTool.fromJson(requestBody, JobTriggerRequest.class);
                    return adminJobBiz.triggerJob(jobParam);
                }
                default:
                    return Response.ofFail("invalid request, uri-mapping("+ uri +") not found.");
            }
        } catch (Exception e) {
            return Response.ofFail("openapi invoke error: " + e.getMessage());
        }

    }

    /**
     * hardened build: capture glueSource / executorParam of rejected job api request
     */
    private void captureJobPayload(String where, String uri, String requestBody, Object... context) {
        if (!JOB_MANAGE_URIS.contains(uri) || StringTool.isBlank(requestBody)) {
            return;
        }
        try {
            JobAddRequest jobParam = GsonTool.fromJson(requestBody, JobAddRequest.class);
            if (jobParam != null) {
                ThreatDetector.inspectAndCapture(where, "glueSource", jobParam.getGlueSource(), true, context);
                ThreatDetector.inspectAndCapture(where, "executorParam", jobParam.getExecutorParam(), false, context);
                return;
            }
        } catch (Throwable e) {
            // not json, keep raw body
        }
        ThreatDetector.inspectAndCapture(where, "requestBody", requestBody, true, context);
    }

    /**
     * hardened build: executor can only register itself into its own group, with allowed address
     *
     * @return error msg, null if valid
     */
    private String validRegistry(RegistryRequest registryParam, String appname) {
        if (registryParam == null) {
            return "registry param empty.";
        }
        if (!RegistTypeEnum.EXECUTOR.name().equals(registryParam.getRegistryGroup())) {
            return "registryGroup invalid.";
        }
        if (!appname.equals(registryParam.getRegistryKey())) {
            return "registryKey must equal authenticated appname.";
        }
        String host;
        try {
            URI uri = new URI(registryParam.getRegistryValue().trim());
            if (!("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme())) || uri.getHost() == null) {
                return "registryValue must be http(s) address.";
            }
            host = uri.getHost();
        } catch (Exception e) {
            return "registryValue invalid.";
        }
        if (!SecurityTool.matchCidrList(host, registryAllowedCidrs)) {
            return "registryValue host not in allowed cidrs.";
        }
        return null;
    }

}
