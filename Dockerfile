# -------- Stage 1: Build stage with all tools --------
FROM python:3.11-slim-bookworm AS builder

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN apt-get update && apt-get install -y \
    build-essential \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libpangocairo-1.0-0 \
    libharfbuzz0b \
    libfontconfig1 \
    --no-install-recommends

COPY requirements.txt .
RUN pip install --upgrade pip && pip install --prefix=/install -r requirements.txt

# -------- Stage 2: Final minimal image --------
FROM python:3.11-slim-bookworm

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Install only required shared libs (no build tools)
RUN apt-get update && apt-get install -y \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libpangocairo-1.0-0 \
    libharfbuzz0b \
    libfontconfig1 \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local
COPY . .

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
