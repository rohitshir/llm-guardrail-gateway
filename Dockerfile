FROM python:3.11-slim

WORKDIR /app

# Prevent Python from writing .pyc files and force unbuffered logs.
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install dependencies first for better Docker layer caching.
COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy application files.
COPY app ./app
COPY policies ./policies
COPY schemas ./schemas
COPY README.md ./README.md
COPY .env.example ./.env.example

# Create data directory for SQLite databases.
RUN mkdir -p data

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
