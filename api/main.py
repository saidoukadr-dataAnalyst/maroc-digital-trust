import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routers import auth, document, blockchain, tasks

app = FastAPI(
    title="Maroc Digital Trust Gateway API",
    description="Enterprise API for PDF Certification, Verification, and Blockchain Anchoring.",
    version="2.0.0"
)

# ── CORS sécurisé (origines explicites uniquement) ──
ALLOWED_ORIGINS = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:3000,http://localhost:8080"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in ALLOWED_ORIGINS],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

# Include Routers
app.include_router(auth.router)
app.include_router(document.router)
app.include_router(blockchain.router)
app.include_router(tasks.router)


@app.get("/")
def root():
    return {"message": "Welcome to Maroc Digital Trust Gateway API. Visit /docs for the Swagger UI."}


@app.get("/health")
def health_check():
    """Endpoint de santé pour Docker HEALTHCHECK et orchestrateurs."""
    return {
        "status": "healthy",
        "version": "2.0.0",
        "service": "Maroc Digital Trust Gateway"
    }
