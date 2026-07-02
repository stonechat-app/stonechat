FROM python:3.13-slim

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .

ENV ZEON_DB=/data/mailbox.db
RUN mkdir -p /data

EXPOSE 8080
CMD ["python", "main.py"]
