import os
import base64
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend


# ── Constantes de sécurité ──
PBKDF2_ITERATIONS = 600_000   # OWASP 2025 minimum pour PBKDF2-SHA256
SALT_LENGTH = 32               # 256 bits (NIST SP 800-132)


class KmsManager:
    """
    Gestionnaire de clés sécurisé (KMS).
    Permet de chiffrer les clés privées et identités PKCS#12 stockées sur le disque.

    Sécurité :
    - PBKDF2-HMAC-SHA256 avec 600 000 itérations (OWASP 2025 minimum)
    - Sel de 256 bits (NIST SP 800-132)
    - Chiffrement Fernet (AES-128-CBC + HMAC-SHA256)
    """

    def __init__(self, vault_path: Path):
        self.vault_path = vault_path
        self.master_salt_path = vault_path / "master.salt"
        self._ensure_salt_exists()

    def _ensure_salt_exists(self):
        if not self.master_salt_path.exists():
            salt = os.urandom(SALT_LENGTH)  # 256 bits
            with open(self.master_salt_path, "wb") as f:
                f.write(salt)

    def _get_fernet(self, master_password: str) -> Fernet:
        """Génère une clé Fernet à partir du mot de passe maître."""
        with open(self.master_salt_path, "rb") as f:
            salt = f.read()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return Fernet(key)

    def encrypt_private_key(self, private_key_bytes: bytes, master_password: str) -> bytes:
        """Chiffre une clé privée pour stockage sur disque."""
        fernet = self._get_fernet(master_password)
        return fernet.encrypt(private_key_bytes)

    def decrypt_private_key(self, encrypted_bytes: bytes, master_password: str) -> bytes:
        """Déchiffre une clé privée pour utilisation en mémoire."""
        fernet = self._get_fernet(master_password)
        try:
            return fernet.decrypt(encrypted_bytes)
        except Exception:
            raise ValueError("Clé de déchiffrement incorrecte ou données corrompues.")

    def store_identity(self, username: str, p12_bytes: bytes, master_password: str):
        """Stocke une identité P12 chiffrée."""
        encrypted = self.encrypt_private_key(p12_bytes, master_password)
        secure_path = self.vault_path / f"secure_{username}.p12.enc"
        with open(secure_path, "wb") as f:
            f.write(encrypted)

    def load_identity(self, username: str, master_password: str) -> bytes:
        """Charge une identité P12 déchiffrée."""
        secure_path = self.vault_path / f"secure_{username}.p12.enc"
        if not secure_path.exists():
            # Fallback legacy (optionnel pour la migration)
            legacy_path = self.vault_path / f"cert_{username}.p12"
            if legacy_path.exists():
                with open(legacy_path, "rb") as f:
                    return f.read()
            raise FileNotFoundError(f"Identité sécurisée introuvable pour {username}")

        with open(secure_path, "rb") as f:
            encrypted = f.read()
        return self.decrypt_private_key(encrypted, master_password)
