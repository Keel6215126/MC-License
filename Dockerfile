FROM eclipse-temurin:17-jdk-jammy AS java_builder
WORKDIR /build
COPY java-src ./java-src
RUN mkdir -p java-build \
    && javac --release 17 -d java-build $(find java-src -name '*.java')

FROM node:22.16.0-bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends openjdk-17-jre-headless ca-certificates gosu \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm --version \
    && npm ci --omit=dev --no-audit --no-fund --progress=false
COPY src ./src
COPY public ./public
COPY docker-entrypoint.sh ./docker-entrypoint.sh
COPY --from=java_builder /build/java-build ./java-build
RUN mkdir -p /data /app/tmp \
    && chmod +x /app/docker-entrypoint.sh
ENV NODE_ENV=production \
    DATA_DIR=/data \
    TMP_DIR=/app/tmp \
    PORT=3000
EXPOSE 3000
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["node", "src/server.js"]
