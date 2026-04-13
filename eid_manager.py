"""
eid_manager.py — Authentification Double Facteur (2FA / TOTP)
Maroc Digital Trust Gateway — Module Identité Numérique Sécurisée
"""
import json
import io
import base64
from pathlib import Path


class EIDManager:
    """
    Gère l'authentification à deux facteurs (2FA) via TOTP (Time-based One-Time Password).
    Compatible avec Google Authenticator, Microsoft Authenticator, et Authy.

    Chaque utilisateur dispose d'un secret TOTP unique, stocké chiffré dans users.json
    (si un KmsManager est fourni) ou en clair (fallback — déconseillé en production).
    """

    ISSUER = "Maroc Digital Trust Gateway"

    def __init__(self, users_file: Path, kms=None):
        self.users_file = Path(users_file)
        self._kms = kms  # KmsManager optionnel pour chiffrer le secret TOTP

    def _load_users(self) -> dict:
        if not self.users_file.exists():
            return {}
        with open(self.users_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_users(self, users: dict):
        with open(self.users_file, "w", encoding="utf-8") as f:
            json.dump(users, f, indent=2, ensure_ascii=False)

    def has_totp(self, username: str) -> bool:
        """Vérifie si l'utilisateur a activé le 2FA."""
        users = self._load_users()
        user = users.get(username, {})
        return bool(user.get("totp_secret") or user.get("totp_secret_enc"))

    def _get_totp_secret(self, username: str, password: str = None) -> str:
        """Récupère le secret TOTP (déchiffre si nécessaire)."""
        users = self._load_users()
        user = users.get(username, {})

        # Priorité au secret chiffré
        if user.get("totp_secret_enc") and self._kms and password:
            try:
                encrypted = user["totp_secret_enc"].encode("utf-8")
                return self._kms.decrypt_private_key(encrypted, password).decode("utf-8")
            except Exception:
                pass

        # Fallback : secret en clair
        return user.get("totp_secret", "")

    def setup_totp(self, username: str, password: str = None) -> dict:
        """
        Génère et enregistre un nouveau secret TOTP pour l'utilisateur.

        Args:
            username: Nom d'utilisateur
            password: Mot de passe pour chiffrer le secret via KMS (optionnel)

        Returns:
        {
            "secret": "BASE32SECRET",
            "uri": "otpauth://totp/...",
            "qr_image_bytes": bytes (PNG du QR Code de configuration)
        }
        """
        try:
            import pyotp
            import qrcode
        except ImportError as e:
            raise ImportError(f"Modules requis non installés : {e}. Exécutez : pip install pyotp qrcode")

        users = self._load_users()
        if username not in users:
            raise ValueError(f"Utilisateur '{username}' introuvable.")

        # Générer un secret aléatoire sécurisé
        secret = pyotp.random_base32()

        # Stocker le secret (chiffré si KMS disponible, sinon en clair)
        if self._kms and password:
            try:
                encrypted = self._kms.encrypt_private_key(secret.encode("utf-8"), password)
                users[username]["totp_secret_enc"] = encrypted.decode("utf-8")
                users[username].pop("totp_secret", None)  # Supprimer la version en clair
                print(f"[2FA] 🔐 Secret TOTP chiffré via KMS pour '{username}'")
            except Exception as e:
                print(f"[2FA] ⚠️ Chiffrement KMS échoué, stockage en clair: {e}")
                users[username]["totp_secret"] = secret
        else:
            users[username]["totp_secret"] = secret

        self._save_users(users)

        # Générer l'URI de configuration (format standard otpauth://)
        nom = users[username].get("nom", username)
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(
            name=f"{nom} ({username})",
            issuer_name=self.ISSUER
        )

        # Générer le QR Code de configuration
        qr_img = qrcode.make(uri)
        buf = io.BytesIO()
        qr_img.save(buf, format='PNG')
        qr_bytes = buf.getvalue()

        print(f"[2FA] 🔐 Secret TOTP configuré pour '{username}'")
        return {
            "secret":         secret,
            "uri":            uri,
            "qr_image_bytes": qr_bytes,
            "username":       username,
            "nom":            nom
        }

    def verify_totp(self, username: str, code: str, password: str = None) -> bool:
        """
        Vérifie un code TOTP à 6 chiffres fourni par l'utilisateur.

        Args:
            username: Nom d'utilisateur
            code:     Code à 6 chiffres
            password: Mot de passe pour déchiffrer le secret KMS (optionnel)

        Returns:
            True si le code est valide (fenêtre de ±30 secondes)
        """
        try:
            import pyotp
        except ImportError:
            raise ImportError("Module 'pyotp' requis. Exécutez : pip install pyotp")

        secret = self._get_totp_secret(username, password)

        if not secret:
            # Fallback : essayer le secret en clair directement
            users = self._load_users()
            secret = users.get(username, {}).get("totp_secret")

        if not secret:
            raise ValueError(f"Aucun secret 2FA configuré pour '{username}'. Activez d'abord le 2FA.")

        totp = pyotp.TOTP(secret)
        # valid_window=1 = accepte les codes de la fenêtre précédente et suivante (±30s)
        is_valid = totp.verify(str(code).strip(), valid_window=1)

        if is_valid:
            print(f"[2FA] ✅ Code TOTP valide pour '{username}'")
        else:
            print(f"[2FA] ❌ Code TOTP INVALIDE pour '{username}'")

        return is_valid

    def disable_totp(self, username: str) -> bool:
        """Désactive le 2FA pour un utilisateur."""
        users = self._load_users()
        if username in users:
            removed = False
            if "totp_secret" in users[username]:
                del users[username]["totp_secret"]
                removed = True
            if "totp_secret_enc" in users[username]:
                del users[username]["totp_secret_enc"]
                removed = True
            if removed:
                self._save_users(users)
                print(f"[2FA] 🔓 2FA désactivé pour '{username}'")
                return True
        return False
