package com.xxl.job.core.openapi.executor.impl;

import com.xxl.job.core.constant.ExecutorBlockStrategyEnum;
import com.xxl.job.core.context.XxlJobContext;
import com.xxl.job.core.executor.XxlJobExecutor;
import com.xxl.job.core.glue.GlueFactory;
import com.xxl.job.core.glue.GlueTypeEnum;
import com.xxl.job.core.handler.IJobHandler;
import com.xxl.job.core.handler.impl.GlueJobHandler;
import com.xxl.job.core.handler.impl.ScriptJobHandler;
import com.xxl.job.core.log.XxlJobFileAppender;
import com.xxl.job.core.openapi.executor.ExecutorBiz;
import com.xxl.job.core.openapi.executor.dto.*;
import com.xxl.job.core.security.SecurityTool;
import com.xxl.job.core.security.ThreatDetector;
import com.xxl.job.core.thread.JobThread;
import com.xxl.tool.response.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;

/**
 * Created by xuxueli on 17/3/1.
 */
public class ExecutorBizImpl implements ExecutorBiz {
    private static final Logger logger = LoggerFactory.getLogger(ExecutorBizImpl.class);

    @Override
    public Response<String> beat() {
        return Response.ofSuccess();
    }

    @Override
    public Response<String> idleBeat(IdleBeatRequest idleBeatRequest) {

        // isRunningOrHasQueue
        boolean isRunningOrHasQueue = false;
        JobThread jobThread = XxlJobExecutor.getInstance().loadJobThread(idleBeatRequest.getJobId());
        if (jobThread != null && jobThread.isRunningOrHasQueue()) {
            isRunningOrHasQueue = true;
        }

        if (isRunningOrHasQueue) {
            return Response.ofFail("job thread is running or has trigger queue.");
        }
        return Response.ofSuccess();
    }

    @Override
    public Response<String> trigger(TriggerRequest triggerRequest) {

        // load job info：jobHandler + jobThread + glueTypeEnum
        JobThread jobThread = XxlJobExecutor.getInstance().loadJobThread(triggerRequest.getJobId());
        IJobHandler jobHandler = jobThread!=null?jobThread.getHandler():null;
        String removeOldReason = null;
        GlueTypeEnum glueTypeEnum = GlueTypeEnum.match(triggerRequest.getGlueType());

        // hardened build: only BEAN is allowed, GLUE (groovy / script) is always rejected
        if (GlueTypeEnum.BEAN != glueTypeEnum) {
            SecurityTool.event("EXECUTOR_GLUE_REJECTED",
                    "jobId", triggerRequest.getJobId(),
                    "logId", triggerRequest.getLogId(),
                    "glueType", triggerRequest.getGlueType(),
                    "glueSourceLength", triggerRequest.getGlueSource()==null?0:triggerRequest.getGlueSource().length());
            // authenticated GLUE attempt: admin or token compromised, keep payload as evidence
            ThreatDetector.inspectAndCapture("executor-trigger", "glueSource", triggerRequest.getGlueSource(), true,
                    "jobId", triggerRequest.getJobId(), "logId", triggerRequest.getLogId(), "glueType", triggerRequest.getGlueType());
            return Response.of(XxlJobContext.HANDLE_CODE_FAIL, "fail, glue type [" + triggerRequest.getGlueType() + "] is disabled in hardened build, only BEAN is allowed.");
        }
        // hardened build: BEAN handler allowlist
        if (!XxlJobExecutor.getInstance().isHandlerAllowed(triggerRequest.getExecutorHandler())) {
            SecurityTool.event("EXECUTOR_HANDLER_REJECTED",
                    "jobId", triggerRequest.getJobId(),
                    "logId", triggerRequest.getLogId(),
                    "handler", triggerRequest.getExecutorHandler());
            ThreatDetector.inspectAndCapture("executor-handler-rejected", "executorParam", triggerRequest.getExecutorParams(), true,
                    "jobId", triggerRequest.getJobId(), "handler", triggerRequest.getExecutorHandler());
            return Response.of(XxlJobContext.HANDLE_CODE_FAIL, "job handler [" + triggerRequest.getExecutorHandler() + "] is not in executor handler allowlist.");
        }
        // hardened build: inspect BEAN param (alert only, param semantic belongs to handler)
        ThreatDetector.inspectAndCapture("executor-trigger", "executorParam", triggerRequest.getExecutorParams(), false,
                "jobId", triggerRequest.getJobId(), "logId", triggerRequest.getLogId(), "handler", triggerRequest.getExecutorHandler());

        // dispatch handler
        if (GlueTypeEnum.BEAN == glueTypeEnum) {

            // new jobhandler
            IJobHandler newJobHandler = XxlJobExecutor.getInstance().loadJobHandler(triggerRequest.getExecutorHandler());

            // valid old jobThread
            if (jobThread!=null && jobHandler != newJobHandler) {
                // change handler, need kill old thread
                removeOldReason = "change jobhandler or glue type, and terminate the old job thread.";

                jobThread = null;
                jobHandler = null;
            }

            // valid handler
            if (jobHandler == null) {
                jobHandler = newJobHandler;
                if (jobHandler == null) {
                    return Response.of(XxlJobContext.HANDLE_CODE_FAIL, "job handler [" + triggerRequest.getExecutorHandler() + "] not found.");
                }
            }

        } else if (GlueTypeEnum.GLUE_GROOVY == glueTypeEnum) {

            // valid old jobThread
            if (jobThread != null &&
                    !(jobThread.getHandler() instanceof GlueJobHandler
                        && ((GlueJobHandler) jobThread.getHandler()).getGlueUpdatetime()== triggerRequest.getGlueUpdatetime() )) {
                // change handler or gluesource updated, need kill old thread
                removeOldReason = "change job source or glue type, and terminate the old job thread.";

                jobThread = null;
                jobHandler = null;
            }

            // valid handler
            if (jobHandler == null) {
                try {
                    IJobHandler originJobHandler = GlueFactory.getInstance().loadNewInstance(triggerRequest.getGlueSource());
                    jobHandler = new GlueJobHandler(originJobHandler, triggerRequest.getGlueUpdatetime());
                } catch (Exception e) {
                    logger.error(e.getMessage(), e);
                    return Response.of(XxlJobContext.HANDLE_CODE_FAIL, e.getMessage());
                }
            }
        } else if (glueTypeEnum!=null && glueTypeEnum.isScript()) {

            // valid old jobThread
            if (jobThread != null &&
                    !(jobThread.getHandler() instanceof ScriptJobHandler
                            && ((ScriptJobHandler) jobThread.getHandler()).getGlueUpdatetime()== triggerRequest.getGlueUpdatetime() )) {
                // change script or gluesource updated, need kill old thread
                removeOldReason = "change job source or glue type, and terminate the old job thread.";

                jobThread = null;
                jobHandler = null;
            }

            // valid handler
            if (jobHandler == null) {
                jobHandler = new ScriptJobHandler(triggerRequest.getJobId(), triggerRequest.getGlueUpdatetime(), triggerRequest.getGlueSource(), GlueTypeEnum.match(triggerRequest.getGlueType()));
            }
        } else {
            return Response.of(XxlJobContext.HANDLE_CODE_FAIL, "glueType[" + triggerRequest.getGlueType() + "] is not valid.");
        }

        // executor block strategy
        if (jobThread != null) {
            ExecutorBlockStrategyEnum blockStrategy = ExecutorBlockStrategyEnum.match(triggerRequest.getExecutorBlockStrategy(), null);
            if (ExecutorBlockStrategyEnum.DISCARD_LATER == blockStrategy) {
                // discard when running
                if (jobThread.isRunningOrHasQueue()) {
                    return Response.of(XxlJobContext.HANDLE_CODE_FAIL, "block strategy effect："+ExecutorBlockStrategyEnum.DISCARD_LATER.getTitle());
                }
            } else if (ExecutorBlockStrategyEnum.COVER_EARLY == blockStrategy) {
                // kill running jobThread
                if (jobThread.isRunningOrHasQueue()) {
                    removeOldReason = "block strategy effect：" + ExecutorBlockStrategyEnum.COVER_EARLY.getTitle();

                    jobThread = null;
                }
            } else {
                // just queue trigger
            }
        }

        // replace thread (new or exists invalid)
        if (jobThread == null) {
            jobThread = XxlJobExecutor.getInstance().registJobThread(triggerRequest.getJobId(), jobHandler, removeOldReason);
        }

        // push data to queue
        return jobThread.pushTriggerQueue(triggerRequest);
    }

    @Override
    public Response<String> kill(KillRequest killRequest) {
        // kill handlerThread, and create new one
        JobThread jobThread = XxlJobExecutor.getInstance().loadJobThread(killRequest.getJobId());
        if (jobThread != null) {
            XxlJobExecutor.getInstance().removeJobThread(killRequest.getJobId(), "scheduling center kill job.");
            return Response.ofSuccess();
        }

        return Response.ofSuccess( "job thread already killed.");
    }

    @Override
    public Response<LogData> log(LogRequest logRequest) {
        // log filename: logPath/yyyy-MM-dd/9999.log
        String logFileName = XxlJobFileAppender.makeLogFileName(new Date(logRequest.getLogDateTime()), logRequest.getLogId());

        LogData logResult = XxlJobFileAppender.readLog(logFileName, logRequest.getFromLineNum());
        return Response.ofSuccess(logResult);
    }

}
