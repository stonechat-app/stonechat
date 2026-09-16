# The push gateway: the only holder of APNs/FCM credentials (main.py). Stateless
# — no database, no volume beyond the read-only credentials directory. Run it
# with docker-compose.yml next to this file (README.md).
FROM python:3.13-slim

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .

EXPOSE 8100
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8100"]
