# SafeSteps server — container image.
#
# Build from the REPOSITORY ROOT (the static PWA lives beside the server, and
# lib/static.js resolves it as ../.. relative to lib/):
#
#   docker build -f safesteps/server/Dockerfile -t safesteps .
#   docker run -p 8080:8080 --env-file safesteps/server/.env safesteps
#
# The image contains NO credentials. Everything secret arrives as environment
# variables at run time; .dockerignore keeps a stray .env out of the layer and
# the RUN below removes one anyway if the ignore file was overridden.
FROM node:22-alpine AS runtime

RUN addgroup -g 10001 safesteps && adduser -D -u 10001 -G safesteps safesteps

WORKDIR /app

# Mirror the repo layout the server expects: the app at /app, the server at
# /app/server. COPY --link keeps the static assets in their own layer.
COPY --chown=safesteps:safesteps safesteps/ /app/

# Defence in depth: never ship a dev .env, a local database or the test suite.
RUN rm -f /app/server/.env /app/server/*.db /app/server/*.db-wal /app/server/*.db-shm \
 && rm -rf /app/server/test

ENV NODE_ENV=production \
    PORT=8080 \
    HOST=0.0.0.0 \
    TRUST_PROXY=true \
    SQLITE_PATH=:memory:

USER safesteps
WORKDIR /app/server
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
