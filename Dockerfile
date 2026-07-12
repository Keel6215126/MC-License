FROM eclipse-temurin:17-jdk-jammy AS java_builder
WORKDIR /build
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates maven \
    && rm -rf /var/lib/apt/lists/*
COPY java-src ./java-src
RUN mkdir -p java-build vendor \
    && javac --release 17 -d java-build $(find java-src -name '*.java') \
    && printf '%s\n' \
       '<project xmlns="http://maven.apache.org/POM/4.0.0">' \
       '  <modelVersion>4.0.0</modelVersion>' \
       '  <groupId>local</groupId><artifactId>mc-license-dependencies</artifactId><version>1</version>' \
       '  <repositories><repository><id>flyte-releases</id><url>https://repo.flyte.gg/releases</url></repository></repositories>' \
       '  <dependencies>' \
       '    <dependency><groupId>org.mclicense</groupId><artifactId>library</artifactId><version>1.5.1</version></dependency>' \
       '    <dependency><groupId>org.json</groupId><artifactId>json</artifactId><version>20240303</version></dependency>' \
       '  </dependencies>' \
       '</project>' > pom.xml \
    && mvn -B -q dependency:copy-dependencies -DincludeScope=runtime -DoutputDirectory=/build/vendor \
    && find vendor -name '*.jar' -print -exec sh -c 'jar tf "$1"' _ {} \; | grep -q '^org/mclicense/library/MCLicense.class$' \
    && find vendor -name '*.jar' -print -exec sh -c 'jar tf "$1"' _ {} \; | grep -q '^org/json/JSONObject.class$'

FROM node:22.16.0-bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends openjdk-17-jre-headless ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json ./
RUN sed -i 's#https://packages.applied-caas-gateway1.internal.api.openai.org/artifactory/api/npm/npm-public/#https://registry.npmjs.org/#g' package-lock.json \
    && npm ci --omit=dev --no-audit --no-fund --progress=false
COPY src ./src
COPY public ./public
COPY --from=java_builder /build/java-build ./java-build
COPY --from=java_builder /build/vendor ./vendor
RUN mkdir -p /app/tmp
ENV NODE_ENV=production \
    TMP_DIR=/app/tmp \
    PORT=3000 \
    MCL_DEPENDENCY_DIR=/app/vendor
EXPOSE 3000
CMD ["node", "src/server.js"]
