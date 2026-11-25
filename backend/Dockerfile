FROM python:3.14-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt "psycopg[binary]==3.3.2"
COPY main.py north.py network.py neighbors.py sysmon.py ingest.py device_watch.py cloud_sync.py ./
COPY fixtures ./fixtures
USER 65534
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
