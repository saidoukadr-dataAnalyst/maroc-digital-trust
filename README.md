# Maroc Digital Trust Gateway

Application de démonstration pour la certification PDF, la vérification d'intégrité et l'ancrage blockchain.

## Objectif

Ce projet vise à fournir une solution de signature électronique PAdES, de gestion d'identités et de vérification de documents, intégrant une API FastAPI, un moteur cryptographique et des fonctions d'ancrage blockchain.

## Corrections de sécurité appliquées

- Authentification basée sur `bcrypt` dans `auth_manager.py`
- Suppression du fallback `default_pwd` dans `crypto_engine.py` et `pades_engine.py`
- Restrictions CORS configurées dans `api/main.py`
- Point de terminaison `/health` ajouté dans `api/main.py`
- Fichiers clés privés déplacés vers `security_vault/` et ignorés par `.gitignore`

## Installations recommandées

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Exécution

```powershell
uvicorn api.main:app --reload
```

## Mise en ligne sur GitHub

1. Crée un dépôt GitHub vide.
2. Puis dans le dossier du projet :

```powershell
git remote add origin https://github.com/TON_UTILISATEUR/NOM_DU_REPO.git
git push -u origin main
```

## Important

Ne pas versionner les clefs privées ou les secrets. Le dossier `security_vault/` est déjà ignoré dans `.gitignore`.
