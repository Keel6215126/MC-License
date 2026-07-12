FROM eclipse-temurin:17-jdk-jammy AS java_builder
WORKDIR /build
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY java-src ./java-src
RUN mkdir -p java-build vendor \
    && javac --release 17 -d java-build $(find java-src -name '*.java') \
    && curl -fL --retry 4 --retry-delay 2 --retry-all-errors \
       https://repo.flyte.gg/releases/org/mclicense/library/1.5.1/library-1.5.1.jar \
       -o vendor/mc-license-library-1.5.1.jar \
    && jar tf vendor/mc-license-library-1.5.1.jar | grep -q '^org/mclicense/library/MCLicense.class$'

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
    MCL_LIBRARY_JAR=/app/vendor/mc-license-library-1.5.1.jar
EXPOSE 3000
CMD ["node", "src/server.js"]
