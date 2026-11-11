FROM node:20-alpine
RUN apk add --no-cache su-exec
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
# Source files may be owner-only on the build host; the app runs as the unprivileged "node" user and must be able to read them.
RUN chmod -R a+rX /app
ENV NODE_ENV=production DATA_DIR=/data PORT=3000
EXPOSE 3000
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
# Starts as root only to fix ownership of an existing /data volume, then drops to the unprivileged "node" user.
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["node", "server.js"]
