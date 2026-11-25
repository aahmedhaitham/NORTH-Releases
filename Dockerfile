FROM node:26-slim AS frontend
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/index.html frontend/tsconfig.json frontend/vite.config.js ./
COPY frontend/src ./src
COPY frontend/public ./public
RUN npm run build -- --mode hosted

FROM python:3.14-slim
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/main.py backend/north.py backend/network.py backend/neighbors.py backend/sysmon.py backend/device_watch.py backend/cloud_sync.py ./
COPY backend/fixtures/demo.json backend/fixtures/linux-ssh-demo.jsonl ./fixtures/
COPY --from=frontend /src/dist ./web
ENV NORTH_PUBLIC_DEMO=1 NORTH_SEED_DEMO=1 NORTH_DB_PATH=/tmp/north.sqlite3 NORTH_WEB_ROOT=/app/web
USER 65534
CMD ["sh", "-c", "exec uvicorn main:app --host 0.0.0.0 --port \"${PORT:-10000}\""]
