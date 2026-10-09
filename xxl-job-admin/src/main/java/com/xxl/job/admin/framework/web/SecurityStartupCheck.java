package com.xxl.job.admin.framework.web;

import com.xxl.job.admin.business.mapper.XxlJobGroupMapper;
import com.xxl.job.admin.business.mapper.XxlJobInfoMapper;
import com.xxl.job.admin.business.mapper.XxlJobLogGlueMapper;
import com.xxl.job.admin.business.model.XxlJobGroup;
import com.xxl.job.admin.business.model.XxlJobInfo;
import com.xxl.job.admin.business.model.XxlJobLogGlue;
import com.xxl.job.admin.framework.mapper.XxlJobUserMapper;
import com.xxl.job.admin.framework.model.XxlJobUser;
import com.xxl.job.core.glue.GlueTypeEnum;
import com.xxl.job.core.security.SecurityAlerter;
import com.xxl.job.core.security.SecurityTool;
import com.xxl.job.core.security.ThreatDetector;
import com.xxl.tool.core.StringTool;
import com.xxl.tool.crypto.Sha256Tool;
import jakarta.annotation.Resource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * hardened build: fail-closed startup check + security posture
 *
 * 1、refuse to start while default admin password (123456) is in use, unless "xxl.job.security.init-admin-password" is provided to reset it;
 * 2、report executor groups with weak accessToken (trigger / openapi for these groups are rejected);
 * 3、inventory existing GLUE jobs and their code history, inspect them with payload rules (IR: planted code);
 * 4、configure alert webhook / payload rules / canary tokens;
 * 5、warn on risky switches.
 */
@Component
public class SecurityStartupCheck implements InitializingBean {
    private static final Logger logger = LoggerFactory.getLogger(SecurityStartupCheck.class);

    private static final String DEFAULT_ADMIN_USERNAME = "admin";
    private static final String DEFAULT_ADMIN_PASSWORD_HASH = Sha256Tool.sha256("123456");
    private static final int ADMIN_PASSWORD_MIN_LENGTH = 12;

    @Resource
    private XxlJobUserMapper xxlJobUserMapper;
    @Resource
    private XxlJobGroupMapper xxlJobGroupMapper;
    @Resource
    private XxlJobInfoMapper xxlJobInfoMapper;
    @Resource
    private XxlJobLogGlueMapper xxlJobLogGlueMapper;

    @Value("${xxl.job.security.init-admin-password:}")
    private String initAdminPassword;

    @Value("${xxl.job.openapi.job-manage.enabled:false}")
    private boolean jobManageEnabled;

    @Value("${xxl.job.registry.allowed-cidrs:}")
    private String registryAllowedCidrs;

    @Value("${xxl.job.security.alert.webhook-url:}")
    private String alertWebhookUrl;
    @Value("${xxl.job.security.alert.min-severity:}")
    private String alertMinSeverity;
    @Value("${xxl.job.security.payload-rules:}")
    private String payloadRules;
    @Value("${xxl.job.security.canary-tokens:}")
    private String canaryTokens;
    @Value("${xxl.job.security.metrics-token:}")
    private String metricsToken;

    @Override
    public void afterPropertiesSet() throws Exception {
        SecurityAlerter.configure(alertWebhookUrl, alertMinSeverity, "xxl-job-admin");
        ThreatDetector.configureRulesPath(payloadRules);
        ThreatDetector.configureCanaryTokens(canaryTokens);

        checkDefaultAdminPassword();
        checkGroupAccessToken();
        inventoryGlueJobs();

        if (jobManageEnabled) {
            SecurityTool.event("ADMIN_RISKY_CONFIG", "config", "xxl.job.openapi.job-manage.enabled", "value", true);
        }
        if (StringTool.isBlank(registryAllowedCidrs)) {
            logger.warn(">>>>>>>>>>> xxl-job hardened, 'xxl.job.registry.allowed-cidrs' is blank, executor registry from any address is accepted.");
        }
        logger.info(">>>>>>>>>>> xxl-job hardened admin, GLUE disabled, openapi job-manage:{}, alert webhook:{}, payload rules:{}, canary tokens:{}",
                jobManageEnabled, SecurityAlerter.isConfigured(), ThreatDetector.ruleCount(), ThreatDetector.canaryTokenCount());
    }

    private void checkDefaultAdminPassword() {
        XxlJobUser admin = xxlJobUserMapper.loadByUserName(DEFAULT_ADMIN_USERNAME);
        if (admin == null || !DEFAULT_ADMIN_PASSWORD_HASH.equals(admin.getPassword())) {
            return;
        }

        // default password in use, reset with provided init password
        if (StringTool.isNotBlank(initAdminPassword)) {
            if (initAdminPassword.length() < ADMIN_PASSWORD_MIN_LENGTH || "123456".equals(initAdminPassword)) {
                throw new IllegalStateException("xxl-job hardened, 'xxl.job.security.init-admin-password' must be at least "
                        + ADMIN_PASSWORD_MIN_LENGTH + " chars.");
            }
            admin.setPassword(Sha256Tool.sha256(initAdminPassword));
            xxlJobUserMapper.update(admin);
            SecurityTool.event("ADMIN_DEFAULT_PASSWORD_RESET", "username", DEFAULT_ADMIN_USERNAME);
            return;
        }

        SecurityTool.event("ADMIN_DEFAULT_PASSWORD", "username", DEFAULT_ADMIN_USERNAME, "action", "refuse-start");
        throw new IllegalStateException("xxl-job hardened, user 'admin' still uses the default password. "
                + "Set env XXL_JOB_SECURITY_INIT_ADMIN_PASSWORD (or property 'xxl.job.security.init-admin-password', min "
                + ADMIN_PASSWORD_MIN_LENGTH + " chars) to reset it on startup, then remove it.");
    }

    private void checkGroupAccessToken() {
        for (String appname : weakTokenGroups()) {
            SecurityTool.event("ADMIN_WEAK_TOKEN", "action", "startup-check", "appname", appname);
            logger.error(">>>>>>>>>>> xxl-job hardened, executor group [{}] {} Trigger and openapi of this group are rejected until the token is rotated.",
                    appname, SecurityTool.weakTokenMsg());
        }
    }

    /**
     * IR: every GLUE job left in db (and its code history) is reported, and inspected with payload rules
     */
    private void inventoryGlueJobs() {
        for (XxlJobInfo jobInfo : glueJobs()) {
            SecurityTool.event("ADMIN_GLUE_JOB_PRESENT", "jobId", jobInfo.getId(), "jobGroup", jobInfo.getJobGroup(),
                    "glueType", jobInfo.getGlueType(), "name", jobInfo.getName(), "author", jobInfo.getAuthor(),
                    "glueUpdatetime", jobInfo.getGlueUpdatetime(), "triggerStatus", jobInfo.getTriggerStatus());
            ThreatDetector.inspectAndCapture("startup-inventory-job", "glueSource", jobInfo.getGlueSource(), true,
                    "jobId", jobInfo.getId(), "glueType", jobInfo.getGlueType());

            List<XxlJobLogGlue> history = xxlJobLogGlueMapper.findByJobId(jobInfo.getId());
            if (history != null) {
                for (XxlJobLogGlue item : history) {
                    ThreatDetector.inspectAndCapture("startup-inventory-history", "glueSource", item.getGlueSource(), true,
                            "jobId", jobInfo.getId(), "historyId", item.getId(), "glueType", item.getGlueType(),
                            "remark", item.getGlueRemark(), "addTime", item.getAddTime());
                }
            }
        }
    }


    // ---------------------- posture ----------------------

    private List<String> weakTokenGroups() {
        List<String> result = new ArrayList<>();
        List<XxlJobGroup> groupList = xxlJobGroupMapper.findAll();
        if (groupList != null) {
            for (XxlJobGroup group : groupList) {
                if (SecurityTool.isWeakToken(group.getAccessToken())) {
                    result.add(group.getAppname());
                }
            }
        }
        return result;
    }

    private List<XxlJobInfo> glueJobs() {
        List<XxlJobInfo> result = new ArrayList<>();
        List<XxlJobGroup> groupList = xxlJobGroupMapper.findAll();
        if (groupList != null) {
            for (XxlJobGroup group : groupList) {
                List<XxlJobInfo> jobList = xxlJobInfoMapper.getJobsByGroup(group.getId());
                if (jobList == null) {
                    continue;
                }
                for (XxlJobInfo jobInfo : jobList) {
                    if (GlueTypeEnum.BEAN != GlueTypeEnum.match(jobInfo.getGlueType())) {
                        result.add(jobInfo);
                    }
                }
            }
        }
        return result;
    }

    public boolean isMetricsTokenValid(String presented) {
        return !SecurityTool.isWeakToken(metricsToken) && SecurityTool.safeEquals(presented, metricsToken);
    }

    public Map<String, Object> posture() {
        XxlJobUser admin = xxlJobUserMapper.loadByUserName(DEFAULT_ADMIN_USERNAME);
        List<XxlJobInfo> glueJobs = glueJobs();
        List<Integer> glueJobIds = new ArrayList<>();
        for (XxlJobInfo item : glueJobs) {
            glueJobIds.add(item.getId());
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("defaultAdminPassword", admin != null && DEFAULT_ADMIN_PASSWORD_HASH.equals(admin.getPassword()));
        result.put("weakTokenGroups", weakTokenGroups());
        result.put("glueJobIds", glueJobIds);
        result.put("openapiJobManageEnabled", jobManageEnabled);
        result.put("registryAllowedCidrs", StringTool.isBlank(registryAllowedCidrs) ? null : registryAllowedCidrs);
        result.put("alertWebhookConfigured", SecurityAlerter.isConfigured());
        result.put("payloadRuleCount", ThreatDetector.ruleCount());
        result.put("canaryTokenCount", ThreatDetector.canaryTokenCount());
        result.put("metricsEndpointEnabled", !SecurityTool.isWeakToken(metricsToken));
        result.put("securityLogChainSeq", SecurityTool.chainSeq());
        result.put("eventCounters", SecurityTool.eventCounters());
        return result;
    }

}
