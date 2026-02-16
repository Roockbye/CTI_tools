# ============================================================================
# CTI Sentinel - Dockerfile
# Image multi-stage pour l'application CTI Sentinel
# ============================================================================

FROM python:3.11-slim AS base

# Variables d'environnement
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Dépendances système
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Répertoire de travail
WORKDIR /app

# Copier et installer les dépendances
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code source
COPY . .

# Créer les répertoires nécessaires
RUN mkdir -p data logs cache backups export

# Volumes
VOLUME ["/app/data", "/app/logs", "/app/cache", "/app/backups", "/app/config"]

# Port API
EXPOSE 8000
# Port Dashboard
EXPOSE 8501

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8000/docs || exit 1

# Point d'entrée par défaut: scheduler
CMD ["python", "main.py", "scheduler"]
