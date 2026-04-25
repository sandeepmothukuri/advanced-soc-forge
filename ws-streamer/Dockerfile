FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY streamer.py .

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python3 -c "import websockets, asyncio; asyncio.run(websockets.connect('ws://localhost:8765'))" || exit 1

EXPOSE 8765

CMD ["python3", "-u", "streamer.py"]
