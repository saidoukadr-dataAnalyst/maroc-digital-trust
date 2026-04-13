# Implémentation Audit Sécurité — Maroc Digital Trust Gateway

## P0 — Corrections immédiates
- [/] 1. Remplacer SHA-256 par bcrypt dans `auth_manager.py`
- [/] 2. Supprimer `"default_pwd"` dans `crypto_engine.py` + `pades_engine.py`
- [/] 3. Créer `.gitignore` + déplacer `cle_privee.pem`
- [/] 4. Restreindre CORS dans `api/main.py`
- [/] 5. Ajouter endpoint `/health`

## P1 — Sprint suivant
- [ ] 6. Scrypt KDF dans `crypto_engine.py`
- [ ] 7. DLP v2 avec scoring + regex marocains
- [ ] 8. Blockchain hybride (vraies TX + file d'attente)
- [ ] 9. KMS → PBKDF2 600K itérations
- [ ] 10. Logs chaînés HMAC + rotation

## P2 — Backlog
- [ ] 11. Lazy Loading + ThreadPoolExecutor
- [ ] 12. Dockerfile multi-stage + non-root user + `.dockerignore`
- [ ] 13. Docker Compose sécurisé (healthchecks, volumes nommés)
- [ ] 14. Chiffrer secrets TOTP via KMS
- [ ] 15. Supprimer `get_current_code()` debug
- [ ] 16. Corriger `datetime.utcnow()` déprécié
- [ ] 17. Séparer requirements (core/worker/ocr)
