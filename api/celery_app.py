import os
from celery import Celery

# Configuration de Celery
# On utilise l'adresse du service redis définie dans docker-compose
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

celery_app = Celery(
    "trust_gateway_tasks",
    broker=REDIS_URL,
    backend=REDIS_URL
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

# Dossier pour les résultats PDF temporaires (accessible par le worker et l'API via volume partagé)
RESULTS_DIR = "/app/security_vault/task_results"
os.makedirs(RESULTS_DIR, exist_ok=True)
