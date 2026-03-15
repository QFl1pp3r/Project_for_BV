FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install Flask + redis client
RUN pip install --no-cache-dir Flask==3.0.3 redis>=5.0

# Copy the streaming package (needed for Redis middleware)
COPY streaming/ ./streaming/

# Copy the vulnerable service itself
COPY vulnerable_service/ ./vulnerable_service/

RUN mkdir -p /app/vulnerable_service/data \
             /app/vulnerable_service/logs

EXPOSE 8999
CMD ["python", "vulnerable_service/app.py"]
