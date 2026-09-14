FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt requirements-postgres.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-postgres.txt
COPY . .

ENV AGENTMETER_HOST=0.0.0.0 \
    AGENTMETER_PORT=8765 \
    PYTHONUNBUFFERED=1
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/health', timeout=3)"
CMD ["python", "server.py"]
