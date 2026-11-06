FROM node:26-bookworm-slim AS build
WORKDIR /app/god-view/backend
COPY god-view/backend/package*.json ./
RUN npm ci --ignore-scripts
COPY god-view/backend/tsconfig.json ./
COPY god-view/backend/src ./src
COPY shared /app/shared
RUN npm run build && npm prune --omit=dev --ignore-scripts

FROM node:26-bookworm-slim
WORKDIR /app/god-view/backend
COPY --from=build /app/god-view/backend/node_modules ./node_modules
COPY --from=build /app/god-view/backend/dist ./dist
COPY god-view/frontend /app/god-view/frontend
COPY shared/schemas/attacker-event.schema.json /app/shared/schemas/attacker-event.schema.json
ENV GODVIEW_FRONTEND_DIR=/app/god-view/frontend ATTACK_EVENT_SCHEMA=/app/shared/schemas/attacker-event.schema.json
USER node
CMD ["node", "dist/god-view/backend/src/server.js"]
