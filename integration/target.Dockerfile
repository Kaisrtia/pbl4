FROM node:26-bookworm-slim AS build
WORKDIR /app/target-app/server
COPY target-app/server/package*.json ./
RUN npm ci --ignore-scripts
COPY target-app/server/tsconfig*.json target-app/server/nest-cli.json ./
COPY target-app/server/src ./src
COPY shared /app/shared
RUN npm run build && npm prune --omit=dev --ignore-scripts

FROM node:26-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/sh lab && passwd -d lab && mkdir -p /run/sshd
WORKDIR /app
COPY --from=build /app/target-app/server/dist ./dist
COPY --from=build /app/target-app/server/node_modules ./node_modules
COPY target-app/server/data/public ./data/public
COPY integration/target-entrypoint.py integration/target-health.py /integration/
CMD ["python3", "/integration/target-entrypoint.py"]
