FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv tini && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt ./
RUN python3 -m venv /opt/worker-env && /opt/worker-env/bin/pip install --no-cache-dir -r requirements.txt
ENV PYTHON_BIN=/opt/worker-env/bin/python3 ATTACKER_BIND=0.0.0.0
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY scripts ./scripts
COPY public ./public
EXPOSE 9000 9001
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "dist/index.js"]
