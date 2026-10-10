package com.xxl.job.core.server;

import com.xxl.job.core.constant.Const;
import com.xxl.job.core.executor.XxlJobExecutor;
import com.xxl.job.core.security.SecurityTool;
import com.xxl.job.core.security.ThreatDetector;
import com.xxl.job.core.openapi.executor.ExecutorBiz;
import com.xxl.job.core.openapi.executor.dto.IdleBeatRequest;
import com.xxl.job.core.openapi.executor.dto.KillRequest;
import com.xxl.job.core.openapi.executor.dto.LogRequest;
import com.xxl.job.core.openapi.executor.dto.TriggerRequest;
import com.xxl.job.core.openapi.executor.impl.ExecutorBizImpl;
import com.xxl.tool.core.StringTool;
import com.xxl.tool.error.ThrowableTool;
import com.xxl.tool.json.GsonTool;
import com.xxl.tool.response.Response;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.handler.timeout.IdleStateEvent;
import io.netty.handler.timeout.IdleStateHandler;
import io.netty.util.CharsetUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.*;

/**
 * Copy from : https://github.com/xuxueli/xxl-rpc
 *
 * @author xuxueli 2020-04-11 21:25
 */
public class EmbedServer {
    private static final Logger logger = LoggerFactory.getLogger(EmbedServer.class);

    private ExecutorBiz executorBiz;
    private Thread thread;

    public void start(final XxlJobExecutor xxlJobExecutor) {

        /**
         * init executor biz service
         */
        executorBiz = new ExecutorBizImpl();

        /**
         * start server
         */
        thread = new Thread(new Runnable() {
            @Override
            public void run() {
                // param
                EventLoopGroup bossGroup = new NioEventLoopGroup();
                EventLoopGroup workerGroup = new NioEventLoopGroup();
                ThreadPoolExecutor bizThreadPool = new ThreadPoolExecutor(
                        0,
                        200,
                        60L,
                        TimeUnit.SECONDS,
                        new LinkedBlockingQueue<Runnable>(2000),
                        new ThreadFactory() {
                            @Override
                            public Thread newThread(Runnable r) {
                                return new Thread(r, "xxl-job, EmbedServer bizThreadPool-" + r.hashCode());
                            }
                        },
                        new RejectedExecutionHandler() {
                            @Override
                            public void rejectedExecution(Runnable r, ThreadPoolExecutor executor) {
                                throw new RuntimeException("xxl-job, EmbedServer bizThreadPool is EXHAUSTED!");
                            }
                        });
                try {
                    // start server
                    ServerBootstrap bootstrap = new ServerBootstrap();
                    bootstrap.group(bossGroup, workerGroup)
                            .channel(NioServerSocketChannel.class)
                            .childHandler(new ChannelInitializer<SocketChannel>() {
                                @Override
                                public void initChannel(SocketChannel channel) throws Exception {
                                    channel.pipeline()
                                            .addLast(new IdleStateHandler(0, 0, 30 * 3, TimeUnit.SECONDS))  // beat 3N, close if idle
                                            .addLast(new HttpServerCodec())
                                            .addLast(new HttpObjectAggregator(5 * 1024 * 1024))  // merge request & reponse to FULL
                                            .addLast(new EmbedHttpServerHandler(executorBiz, xxlJobExecutor, bizThreadPool));
                                }
                            })
                            .childOption(ChannelOption.SO_KEEPALIVE, true);

                    // bind
                    ChannelFuture future = bootstrap.bind(xxlJobExecutor.getPort()).sync();

                    logger.info(">>>>>>>>>>> xxl-job remoting server start success, nettype = {}, port = {}", EmbedServer.class, xxlJobExecutor.getPort());

                    // start registry
                    xxlJobExecutor.getExecutorRegistryThreadHelper().start(xxlJobExecutor);

                    // wait util stop
                    future.channel().closeFuture().sync();

                } catch (InterruptedException e) {
                    logger.info(">>>>>>>>>>> xxl-job remoting server stop.");
                } catch (Throwable e) {
                    logger.error(">>>>>>>>>>> xxl-job remoting server error.", e);
                } finally {
                    // stop
                    try {
                        workerGroup.shutdownGracefully();
                        bossGroup.shutdownGracefully();
                    } catch (Throwable e) {
                        logger.error(e.getMessage(), e);
                    }
                }
            }
        });
        thread.setDaemon(true);    // daemon, service jvm, user thread leave >>> daemon leave >>> jvm leave
        thread.setName("xxl-job, EmbedServer");
        thread.start();
    }

    public void stop(final XxlJobExecutor xxlJobExecutor) throws Exception {
        // destroy server thread
        if (thread != null && thread.isAlive()) {
            thread.interrupt();
        }

        // stop registry
        xxlJobExecutor.getExecutorRegistryThreadHelper().stop(xxlJobExecutor);
        logger.info(">>>>>>>>>>> xxl-job remoting server destroy success.");
    }


    // ---------------------- registry ----------------------

    /**
     * netty_http server handler
     *
     * Copy from : https://github.com/xuxueli/xxl-rpc
     *
     * @author xuxueli 2015-11-24 22:25:15
     */
    public static class EmbedHttpServerHandler extends SimpleChannelInboundHandler<FullHttpRequest> {
        private static final Logger logger = LoggerFactory.getLogger(EmbedHttpServerHandler.class);

        private final ExecutorBiz executorBiz;
        private final XxlJobExecutor xxlJobExecutor;
        private final ThreadPoolExecutor bizThreadPool;

        public EmbedHttpServerHandler(final ExecutorBiz executorBiz, final XxlJobExecutor xxlJobExecutor, final ThreadPoolExecutor bizThreadPool) {
            this.executorBiz = executorBiz;
            this.xxlJobExecutor = xxlJobExecutor;
            this.bizThreadPool = bizThreadPool;
        }

        @Override
        protected void channelRead0(final ChannelHandlerContext ctx, FullHttpRequest msg) throws Exception {

            // request parse
            HttpMethod httpMethod = msg.method();
            String uri = msg.uri();
            String requestData = msg.content().toString(CharsetUtil.UTF_8);
            boolean keepAlive = HttpUtil.isKeepAlive(msg);
            String accessToken = msg.headers().get(Const.XXL_JOB_ACCESS_TOKEN);
            String appname = msg.headers().get(Const.XXL_JOB_APPNAME);
            String remoteAddress = String.valueOf(ctx.channel().remoteAddress());

            // invoke
            bizThreadPool.execute(new Runnable() {
                @Override
                public void run() {
                    // do invoke
                    Object responseObj = dispatchRequest(httpMethod, uri, requestData, accessToken, appname, remoteAddress);

                    // to json
                    String responseJson = GsonTool.toJson(responseObj);

                    // write response
                    writeResponse(ctx, keepAlive, responseJson);
                }
            });
        }

        private static final java.util.Set<String> KNOWN_URIS = java.util.Set.of("/beat", "/idleBeat", "/trigger", "/kill", "/log");
        private static final java.util.Set<String> LEGACY_EXPLOIT_URIS = java.util.Set.of("/run", "/run/");

        /**
         * hardened build: capture glueSource / executorParams of a rejected (unauthenticated / probe) trigger as evidence
         */
        private void captureTriggerPayload(String where, String requestData, Object... context) {
            if (StringTool.isBlank(requestData)) {
                return;
            }
            TriggerRequest triggerParam = null;
            try {
                triggerParam = GsonTool.fromJson(requestData, TriggerRequest.class);
            } catch (Throwable e) {
                // not json, keep raw body
            }
            if (triggerParam != null && (triggerParam.getGlueSource() != null || triggerParam.getExecutorParams() != null)) {
                ThreatDetector.inspectAndCapture(where, "glueSource", triggerParam.getGlueSource(), true, context);
                ThreatDetector.inspectAndCapture(where, "executorParam", triggerParam.getExecutorParams(), false, context);
            } else {
                ThreatDetector.inspectAndCapture(where, "requestBody", requestData, true, context);
            }
        }

        /**
         * dispatch request
         */
        private Object dispatchRequest(HttpMethod httpMethod, String uri, String requestData, String accessToken, String appname, String remoteAddress) {
            // hardened build: the RPC port is admin-only; reject any source outside the configured admin cidrs (not enforced if blank)
            if (!xxlJobExecutor.isAdminSourceAllowed(remoteAddress)) {
                SecurityTool.event("EXECUTOR_SCAN", "reason", "source not allowed", "method", httpMethod, "remote", remoteAddress, "uri", uri);
                ThreatDetector.trackFailure("executor-scan", remoteAddress);
                // still inspect the presented token, so a stolen token / canary / default token used from a non-admin host is not hidden by the source check
                if (SecurityTool.safeEquals(accessToken, xxlJobExecutor.getAccessToken())) {
                    SecurityTool.event("EXECUTOR_TOKEN_WRONG_SOURCE", "remote", remoteAddress, "uri", uri, "appname", appname);
                } else {
                    ThreatDetector.inspectPresentedToken(accessToken, "executor", "remote", remoteAddress, "uri", uri, "appname", appname);
                }
                return Response.ofFail("invalid request, source not allowed.");
            }
            // valid
            if (HttpMethod.POST != httpMethod) {
                // hardened build: admin only sends POST, anything else is a scanner / probe
                SecurityTool.event("EXECUTOR_SCAN", "reason", "http method", "method", httpMethod, "remote", remoteAddress, "uri", uri);
                ThreatDetector.trackFailure("executor-scan", remoteAddress);
                return Response.ofFail("invalid request, HttpMethod not support.");
            }
            if (uri == null || uri.trim().isEmpty()) {
                return Response.ofFail( "invalid request, uri-mapping empty.");
            }
            // hardened build: unknown uri, detect before auth
            if (!KNOWN_URIS.contains(uri)) {
                if (LEGACY_EXPLOIT_URIS.contains(uri)) {
                    // "/run" is the legacy (<=2.2) executor api targeted by public unauthenticated GLUE exploits
                    SecurityTool.event("EXECUTOR_EXPLOIT_PROBE", "remote", remoteAddress, "uri", uri, "appname", appname);
                    captureTriggerPayload("executor-legacy-probe", requestData, "remote", remoteAddress, "uri", uri);
                } else {
                    SecurityTool.event("EXECUTOR_SCAN", "reason", "unknown uri", "remote", remoteAddress, "uri", uri);
                }
                ThreatDetector.trackFailure("executor-scan", remoteAddress);
                return Response.ofFail( "invalid request, uri-mapping(" + uri + ") not found.");
            }

            // valid access token
            if (StringTool.isBlank(accessToken) || StringTool.isBlank(appname)) {
                SecurityTool.event("EXECUTOR_AUTH_FAIL", "reason", "token or appname empty", "remote", remoteAddress, "uri", uri);
                ThreatDetector.trackFailure("executor-auth", remoteAddress);
                if ("/trigger".equals(uri)) {
                    captureTriggerPayload("executor-trigger-unauth", requestData, "remote", remoteAddress);
                }
                return Response.ofFail("invalid request, accessToken or appname is empty.");
            }
            // hardened build: constant-time compare
            boolean tokenValid = SecurityTool.safeEquals(accessToken, xxlJobExecutor.getAccessToken());
            boolean appnameValid = appname.equals(xxlJobExecutor.getAppname());
            if (!(tokenValid && appnameValid)) {
                SecurityTool.event("EXECUTOR_AUTH_FAIL", "reason", tokenValid?"appname invalid":"token invalid",
                        "remote", remoteAddress, "uri", uri, "appname", appname);
                ThreatDetector.trackFailure("executor-auth", remoteAddress);
                if (!tokenValid) {
                    ThreatDetector.inspectPresentedToken(accessToken, "executor", "remote", remoteAddress, "uri", uri, "appname", appname);
                }
                if ("/trigger".equals(uri)) {
                    captureTriggerPayload("executor-trigger-unauth", requestData, "remote", remoteAddress);
                }
                return Response.ofFail("invalid request, accessToken or appname invalid.");
            }

            // services mapping
            try {
                switch (uri) {
                    case "/beat":
                        return executorBiz.beat();
                    case "/idleBeat":
                        IdleBeatRequest idleBeatParam = GsonTool.fromJson(requestData, IdleBeatRequest.class);
                        return executorBiz.idleBeat(idleBeatParam);
                    case "/trigger":
                        TriggerRequest triggerParam = GsonTool.fromJson(requestData, TriggerRequest.class);
                        return executorBiz.trigger(triggerParam);
                    case "/kill":
                        KillRequest killParam = GsonTool.fromJson(requestData, KillRequest.class);
                        return executorBiz.kill(killParam);
                    case "/log":
                        LogRequest logParam = GsonTool.fromJson(requestData, LogRequest.class);
                        return executorBiz.log(logParam);
                    default:
                        return Response.ofFail( "invalid request, uri-mapping(" + uri + ") not found.");
                }
            } catch (Throwable e) {
                logger.error(e.getMessage(), e);
                return Response.ofFail("request error:" + ThrowableTool.toString(e));
            }
        }

        /**
         * write response
         */
        private void writeResponse(ChannelHandlerContext ctx, boolean keepAlive, String responseJson) {
            // write response
            FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, Unpooled.copiedBuffer(responseJson, CharsetUtil.UTF_8));   //  Unpooled.wrappedBuffer(responseJson)
            response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/html;charset=UTF-8");       // HttpHeaderValues.TEXT_PLAIN.toString()
            response.headers().set(HttpHeaderNames.CONTENT_LENGTH, response.content().readableBytes());
            if (keepAlive) {
                response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE);
            }
            ctx.writeAndFlush(response);
        }

        @Override
        public void channelReadComplete(ChannelHandlerContext ctx) throws Exception {
            ctx.flush();
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            logger.error(">>>>>>>>>>> xxl-job provider netty_http server caught exception", cause);
            ctx.close();
        }

        @Override
        public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
            if (evt instanceof IdleStateEvent) {
                ctx.channel().close();      // beat 3N, close if idle
                logger.debug(">>>>>>>>>>> xxl-job provider netty_http server close an idle channel.");
            } else {
                super.userEventTriggered(ctx, evt);
            }
        }
    }

}
