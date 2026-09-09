FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build
FROM node:24-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production HOST=0.0.0.0 PORT=4317 HOOK_SESSION_DIR=/var/lib/hook-web/sessions
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && mkdir -p /var/lib/hook-web/sessions && chown -R node:node /var/lib/hook-web
COPY --from=build --chown=node:node /app/dist ./dist
USER node
EXPOSE 4317
CMD ["node", "dist/server.js"]
