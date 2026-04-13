"""
audit_logger.py — Logger d'Audit Sécurisé avec Chaînage HMAC
Maroc Digital Trust Gateway — Module Traçabilité

Sécurité :
- Chaînage HMAC (chaque entrée inclut le hash de la précédente)
- Horodatage UTC (insensible aux changements d'horloge locale)
- Rotation automatique des fichiers (max 10 Mo, 5 backups)
- Niveaux de sévérité distincts par action
"""
import logging
import json
import hashlib
import hmac
import os
from datetime import datetime, timezone
from pathlib import Path
from logging.handlers import RotatingFileHandler


class AuditLogger:
    """
    Logger d'audit sécurisé avec intégrité cryptographique.

    Chaque entrée de log contient :
    - Un horodatage UTC
    - Le hash HMAC de la précédente entrée (chaînage)
    - Un HMAC de l'entrée courante (détection de falsification)
    """

    SEVERITY_MAP = {
        "LOGIN": "INFO", "LOGOUT": "INFO",
        "DOUBLE_SIGN": "INFO", "VERIFY_SUCCESS": "INFO",
        "KEY_GEN": "INFO", "KEY_ROTATION": "INFO",
        "2FA_SETUP": "INFO", "2FA_FAIL": "WARNING",
        "DLP_BLOCK": "WARNING", "DLP_BYPASS": "CRITICAL",
        "VERIFY_FAIL": "WARNING",
        "ADD_USER": "INFO", "DEL_USER": "WARNING",
        "PWD_CHANGE": "INFO",
        "BLOCKCHAIN_ANCHOR": "INFO",
        "WORKFLOW_CREATE": "INFO", "WORKFLOW_APPROVE": "INFO", "WORKFLOW_REJECT": "WARNING",
        "KMS_ACCESS_START": "INFO", "KMS_ACCESS_SUCCESS": "INFO", "KMS_ACCESS_FAIL": "WARNING",
        "ASYNC_SIGN_SUCCESS": "INFO", "ASYNC_SIGN_FAIL": "WARNING",
        "ASYNC_BLOCKCHAIN_ANCHOR": "INFO",
    }

    LOG_LEVEL_MAP = {
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "CRITICAL": logging.CRITICAL,
    }

    def __init__(self, log_dir, hmac_key: bytes = None):
        self.log_path = Path(log_dir) / "audit.log"
        self.log_path.parent.mkdir(exist_ok=True)

        # Clé HMAC pour la signature des logs
        self._hmac_key = hmac_key or self._load_or_create_hmac_key(log_dir)
        self._last_hash = "GENESIS"

        # Configure logging avec rotation
        self.logger = logging.getLogger("AuditLogger")
        self.logger.setLevel(logging.DEBUG)

        if not self.logger.handlers:
            fh = RotatingFileHandler(
                str(self.log_path),
                maxBytes=10 * 1024 * 1024,  # 10 Mo
                backupCount=5,
                encoding="utf-8"
            )
            fh.setLevel(logging.DEBUG)
            self.logger.addHandler(fh)

    def _load_or_create_hmac_key(self, log_dir) -> bytes:
        """Charge ou génère la clé HMAC pour la signature des logs."""
        key_path = Path(log_dir) / ".audit_hmac_key"
        if key_path.exists():
            with open(key_path, "rb") as f:
                return f.read()
        key = os.urandom(32)
        with open(key_path, "wb") as f:
            f.write(key)
        return key

    def log_action(self, user_id, action, details):
        """
        Enregistre une action d'audit avec chaînage HMAC.

        Chaque entrée contient le HMAC de l'entrée précédente, créant
        une chaîne d'intégrité vérifiable. Si une entrée est modifiée,
        toutes les suivantes deviennent invalides.
        """
        level = self.SEVERITY_MAP.get(action, "INFO")

        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "user_id": user_id,
            "action": action,
            "details": details,
            "prev_hash": self._last_hash,
        }

        # Calculer le HMAC de l'entrée (intégrité)
        entry_str = json.dumps(log_entry, sort_keys=True)
        entry_hmac = hmac.new(
            self._hmac_key, entry_str.encode(), hashlib.sha256
        ).hexdigest()
        log_entry["hmac"] = entry_hmac
        self._last_hash = entry_hmac

        # Écrire le log avec le bon niveau
        message = json.dumps(log_entry, ensure_ascii=False)
        log_level = self.LOG_LEVEL_MAP.get(level, logging.INFO)
        self.logger.log(log_level, message)

        # Console output pour le développement
        print(f"[AUDIT] {user_id} | {action} | {details}")
