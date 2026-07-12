FROM eclipse-temurin:21-jdk-jammy AS builder

ARG PROGUARD_VERSION=7.9.1
WORKDIR /build
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip maven \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fL --retry 4 --retry-delay 2 --retry-all-errors \
      "https://github.com/Guardsquare/proguard/releases/download/v${PROGUARD_VERSION}/proguard-${PROGUARD_VERSION}.zip" \
      -o /tmp/proguard.zip \
    && unzip -q /tmp/proguard.zip -d /opt \
    && mv "/opt/proguard-${PROGUARD_VERSION}" /opt/proguard \
    && chmod +x /opt/proguard/bin/proguard.sh \
    && rm /tmp/proguard.zip

COPY java-src ./java-src
RUN mkdir -p java-build mc-license-deps \
    && javac --release 17 -d java-build $(find java-src -name '*.java') \
    && printf '%s\n' \
       '<project xmlns="http://maven.apache.org/POM/4.0.0">' \
       '  <modelVersion>4.0.0</modelVersion>' \
       '  <groupId>local</groupId><artifactId>plugin-protector-runtime</artifactId><version>1</version>' \
       '  <repositories><repository><id>flyte-releases</id><url>https://repo.flyte.gg/releases</url></repository></repositories>' \
       '  <dependencies>' \
       '    <dependency><groupId>org.mclicense</groupId><artifactId>library</artifactId><version>1.5.1</version></dependency>' \
       '    <dependency><groupId>org.json</groupId><artifactId>json</artifactId><version>20240303</version></dependency>' \
       '  </dependencies>' \
       '</project>' > pom.xml \
    && mvn -B -q dependency:copy-dependencies -DincludeScope=runtime -DoutputDirectory=/build/mc-license-deps \
    && find mc-license-deps -name '*.jar' -exec sh -c 'jar tf "$1"' _ {} \; | grep -q '^org/mclicense/library/MCLicense.class$' \
    && find mc-license-deps -name '*.jar' -exec sh -c 'jar tf "$1"' _ {} \; | grep -q '^org/json/JSONObject.class$'

FROM eclipse-temurin:21-jdk-jammy
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN python3 -m pip install --no-cache-dir -r requirements.txt
COPY . .
COPY --from=builder /opt/proguard /opt/proguard
COPY --from=builder /build/java-build /app/java-build
COPY --from=builder /build/mc-license-deps /opt/mc-license-deps
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /tmp/plugin-protector/jobs \
    && chown -R appuser:appuser /app /tmp/plugin-protector
USER appuser
ENV PYTHONUNBUFFERED=1 \
    PROGUARD_CMD=/opt/proguard/bin/proguard.sh \
    JOB_ROOT=/tmp/plugin-protector/jobs \
    MCL_PATCHER_CLASSPATH=/app/java-build \
    MCL_DEPENDENCY_DIR=/opt/mc-license-deps \
    MAX_UPLOAD_MB=100 \
    JOB_TTL_MINUTES=60 \
    OBFUSCATION_TIMEOUT_SECONDS=240 \
    LICENSE_TIMEOUT_SECONDS=45 \
    JAVA_MAX_HEAP_MB=512
EXPOSE 8080
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-8080} --workers 1 --threads 8 --timeout 0 --access-logfile - --error-logfile - app:app"]
