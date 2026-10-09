# base image
FROM eclipse-temurin:17-jre

LABEL maintainer="xuxueli" hardened="true"

# set params
ENV PARAMS=""
ENV LOG_HOME=/data/applogs

# set timezone
ENV TZ=PRC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# hardened build: run as non-root, only the log dir is writable
RUN groupadd --system --gid 10001 xxljob \
    && useradd --system --uid 10001 --gid xxljob --no-create-home --shell /usr/sbin/nologin xxljob \
    && mkdir -p /data/applogs && chown -R 10001:10001 /data/applogs

# copy jar (exact name: target also contains -sources / -javadoc jars)
ARG JAR_FILE=xxl-job-executor-sample-springboot-ai-3.5.1-hardened.1.jar
COPY --chown=root:root --chmod=0444 target/${JAR_FILE} /app.jar

# expose port
EXPOSE 9999

USER 10001:10001

# command
# log home: -e LOG_HOME=/data/applogs
# jvm options: -e JAVA_OPTS="-Xms128m -Xmx128m"
# app params: -e PARAMS="--server.port=8080"
ENTRYPOINT ["sh","-c","exec java -DLOG_HOME=$LOG_HOME $JAVA_OPTS -jar /app.jar $PARAMS"]
