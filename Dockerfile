FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    default-libmysqlclient-dev \
    pkg-config \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install -no-cache-dir requirements.txt

COPY . .

CMD["gunicorn", "-b", "0.0.0.0:5000", "app:app"]
