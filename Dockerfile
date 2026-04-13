# ============================================================
# STAGE 1 : Builder (compilation des dépendances C)
# ============================================================
FROM python:3.10-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Dépendances de compilation uniquement
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY requirements.txt .

# Compiler les wheels dans un dossier séparé
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ============================================================
# STAGE 2 : Runtime (image finale légère)
# ============================================================
FROM python:3.10-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Dépendances runtime UNIQUEMENT (pas de build-essential)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-fra \
    tesseract-ocr-eng \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get purge -y --auto-remove

WORKDIR /app

# Copier uniquement les packages Python compilés depuis le builder
COPY --from=builder /install /usr/local

# Créer un utilisateur non-root pour la sécurité
RUN groupadd -r trustapp && useradd -r -g trustapp -m trustapp

# Copier le code source (exclure les fichiers sensibles via .dockerignore)
COPY --chown=trustapp:trustapp . .

# Répertoire sécurisé avec permissions restrictives
RUN mkdir -p security_vault/archive \
    && chown -R trustapp:trustapp security_vault \
    && chmod -R 700 security_vault

# Basculer sur l'utilisateur non-root
USER trustapp

EXPOSE 8000

# Healthcheck pour orchestration
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
