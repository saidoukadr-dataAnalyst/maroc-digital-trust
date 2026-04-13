import hashlib
import os
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend


# ── Constantes de sécurité ──
MIN_PASSWORD_LENGTH = 12
SCRYPT_SALT_LENGTH = 32      # 256 bits
SCRYPT_N = 2**20             # 1M — Coût CPU/mémoire (NIST recommande ≥2^15)
SCRYPT_R = 8                 # Facteur de parallélisme mémoire
SCRYPT_P = 1                 # Parallélisme
SCRYPT_KEY_LENGTH = 32       # 256 bits (AES-256)


class CryptoEngine:
    def __init__(self, vault_path, archive_path):
        self.vault_path = vault_path
        self.archive_path = archive_path
        self.private_key = None
        self.public_key = None

    # ── Validation du mot de passe ──
    @staticmethod
    def _validate_password_strength(password: str) -> bool:
        """
        Vérifie que le mot de passe respecte la politique de sécurité.
        Politique : ≥12 caractères, 1 majuscule, 1 minuscule, 1 chiffre, 1 spécial.
        """
        if not password or len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError(
                f"Le mot de passe doit contenir au moins {MIN_PASSWORD_LENGTH} caractères."
            )
        checks = {
            "une majuscule": any(c.isupper() for c in password),
            "une minuscule": any(c.islower() for c in password),
            "un chiffre":    any(c.isdigit() for c in password),
            "un caractère spécial": any(c in "!@#$%^&*()-_=+[]{}|;:',.<>?/~`" for c in password),
        }
        missing = [name for name, ok in checks.items() if not ok]
        if missing:
            raise ValueError(
                f"Mot de passe trop faible. Il manque : {', '.join(missing)}."
            )
        return True

    # ── Dérivation KDF forte (Scrypt) ──
    @staticmethod
    def _derive_key_from_password(password: str, salt: bytes) -> bytes:
        """
        Dérive une clé de chiffrement à partir du mot de passe via Scrypt.

        Scrypt est préféré à PBKDF2 car il est memory-hard, rendant les
        attaques GPU/ASIC exponentiellement plus coûteuses.

        Paramètres :
        - N=2^20 : ~1 Go RAM nécessaire — protège contre les attaques FPGA/GPU
        - r=8    : Facteur de bloc mémoire standard
        - p=1    : Parallélisme (1 = séquentiel, plus sûr pour single-user)
        """
        kdf = Scrypt(
            salt=salt,
            length=SCRYPT_KEY_LENGTH,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            backend=default_backend()
        )
        return kdf.derive(password.encode("utf-8"))

    def sign_data(self, data):
        """Signe des données avec la clé privée."""
        if not self.private_key:
            raise Exception("Clé privée non chargée")
        return self.private_key.sign(data.encode(), ec.ECDSA(hashes.SHA256()))

    def verify_signature(self, signature, data_hash):
        """Vérifie la signature avec la clé publique chargée."""
        if not self.public_key:
            raise Exception("Clé publique non chargée")
        self.public_key.verify(bytes.fromhex(signature), data_hash.encode(), ec.ECDSA(hashes.SHA256()))

    def load_keys(self, password):
        """Charge la clé privée en la déchiffrant avec le mot de passe utilisateur."""
        priv_file = self.vault_path / "current_priv.pem"
        if not priv_file.exists():
            return False

        try:
            with open(priv_file, "rb") as f:
                pem_data = f.read()

            # Lire le sel stocké à côté de la clé
            salt_file = self.vault_path / "current_priv.salt"
            if salt_file.exists():
                with open(salt_file, "rb") as f:
                    salt = f.read()
                # Dériver la clé via Scrypt pour recréer le mot de passe de déchiffrement
                derived = self._derive_key_from_password(password, salt)
                decryption_pwd = derived
            else:
                # Fallback legacy (migration des anciennes clés sans sel)
                decryption_pwd = password.encode()

            self.private_key = serialization.load_pem_private_key(
                pem_data,
                password=decryption_pwd,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            return True
        except Exception:
            return False

    def generate_new_identity(self, password):
        """
        Génère une nouvelle identité ECDSA chiffrée sur disque.

        Processus sécurisé :
        1. Valide la force du mot de passe
        2. Génère un sel cryptographique unique (32 octets)
        3. Dérive une clé AES-256 via Scrypt (memory-hard)
        4. Chiffre la clé privée PEM avec cette clé dérivée
        5. Archive l'ancienne clé publique avec horodatage
        """
        # ── Étape 1 : Validation du mot de passe ──
        self._validate_password_strength(password)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        current_pub = self.vault_path / "current_pub.pem"

        # Archive l'ancienne clé publique si elle existe
        if current_pub.exists():
            current_pub.rename(self.archive_path / f"pub_key_{timestamp}.pem")

        # ── Étape 2 : Génération de la paire de clés EC ──
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

        # ── Étape 3 : Génération du sel et dérivation KDF ──
        salt = os.urandom(SCRYPT_SALT_LENGTH)
        derived_key = self._derive_key_from_password(password, salt)

        # Sauvegarder le sel (nécessaire pour le déchiffrement ultérieur)
        with open(self.vault_path / "current_priv.salt", "wb") as f:
            f.write(salt)

        # ── Étape 4 : Sauvegarde CHIFFRÉE avec clé dérivée Scrypt ──
        encryption_algo = serialization.BestAvailableEncryption(derived_key)

        with open(self.vault_path / "current_priv.pem", "wb") as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algo
            ))

        with open(self.vault_path / "current_pub.pem", "wb") as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        return True
