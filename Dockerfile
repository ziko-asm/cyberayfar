# Playwright-in rəsmi Python image-i — Chromium brauzeri artıq daxildir
FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy

WORKDIR /app

# Asılılıqları quraşdır (requests, bs4, dnspython, flask) + gunicorn
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Tətbiqi kopyala
COPY . .

ENV PYTHONUNBUFFERED=1

# Render $PORT verir. SSE üçün threads, headless üçün 1 worker (yaddaş).
CMD gunicorn --bind 0.0.0.0:${PORT:-10000} --timeout 180 --workers 1 --threads 8 app:app
