# 🛡️ Audit de Sécurité Approfondi — Maroc Digital Trust Gateway

**Date :** 12 Avril 2026  
**Révision :** v2.0 — Audit complet post-revue de code  
**Portée :** Analyse de **14 fichiers sources** — Architecture complète (Desktop + API + Docker)  
**Rôle :** Expert Cybersécurité & Architecte Logiciel Senior  
**Classification :** 🔴 CONFIDENTIEL — Diffusion restreinte

---

## Synthèse Exécutive

L'application **Maroc Digital Trust Gateway** présente une architecture globalement cohérente (certification PDF, ancrage blockchain, workflow multi-signatures), mais souffre de **vulnérabilités critiques** qui compromettent la chaîne de confiance. L'audit couvre 9 axes — les 4 initiaux enrichis et 5 nouveaux axes identifiés lors de l'analyse approfondie du code source complet.

### Tableau de Bord des Risques

| Sévérité | Nombre | Exemples |
|:--------:|:------:|----------|
| 🔴 CRITIQUE | 7 | SHA-256 sans sel, `default_pwd`, CORS `*`, TOTP en clair, fichiers PEM exposés |
| 🟠 ÉLEVÉ | 5 | PBKDF2 faible (KMS), logs non signés, `chmod 777`, pas de JWT |
| 🟡 MOYEN | 4 | Regex DLP imprécis, pas de rate-limiting, exceptions silencieuses |
| 🔵 FAIBLE | 3 | Blockchain factice, `datetime.utcnow()` déprécié, pas de `.gitignore` |

### Conformité Réglementaire

| Cadre | Statut | Détails |
|-------|:------:|---------|
| **Loi 09-08** (Protection données personnelles, Maroc) | ⚠️ Non-conforme | Hachage SHA-256 sans sel + TOTP en clair = violation Art. 23 |
| **DNSSI** (Directive de la sécurité SI, DGSSI) | ⚠️ Non-conforme | Pas de KDF robuste, logs non intègres |
| **eIDAS / ISO 32000-2** (Signature électronique) | ⚠️ Partiel | PAdES LTV présent mais certificat auto-signé |
| **OWASP Top 10 (2025)** | ⚠️ Non-conforme | A01 (Broken Access Control), A02 (Crypto Failures), A07 (Auth) |

---

## Table des Matières

1. [Axe 1 — Renforcement Cryptographique (KDF)](#axe-1--renforcement-cryptographique-kdf)
2. [Axe 2 — Performance & UX (Lazy Loading + Threading)](#axe-2--performance--ux-lazy-loading--threading)
3. [Axe 3 — Résilience Blockchain (Vérification Hybride)](#axe-3--résilience-blockchain-vérification-hybride)
4. [Axe 4 — Conformité DLP (Patterns + Score de Risque)](#axe-4--conformité-dlp-patterns--score-de-risque)
5. [Axe 5 — Sécurité de l'API (CORS, Auth, Rate Limiting)](#axe-5--sécurité-de-lapi-cors-auth-rate-limiting) ⭐ NOUVEAU
6. [Axe 6 — Intégrité des Logs d'Audit](#axe-6--intégrité-des-logs-daudit) ⭐ NOUVEAU
7. [Axe 7 — Faiblesses du KMS (Key Management Service)](#axe-7--faiblesses-du-kms-key-management-service) ⭐ NOUVEAU
8. [Axe 8 — Vulnérabilités Transversales Critiques](#axe-8--vulnérabilités-transversales-critiques)
9. [Axe 9 — Optimisation Dockerfile & Docker Compose](#axe-9--optimisation-dockerfile--docker-compose)
10. [Matrice de Risque & Plan d'Action](#matrice-de-risque--plan-daction)

---

## Axe 1 — Renforcement Cryptographique (KDF)

### 1.1 — Diagnostic `crypto_engine.py`

```python
# crypto_engine.py — Lignes 57-58 (VULNÉRABLE)
safe_pwd = password if password else "default_pwd"  # ⚠️ Mot de passe par défaut !
encryption_algo = serialization.BestAvailableEncryption(safe_pwd.encode())
```

> [!CAUTION]
> **3 Vulnérabilités critiques identifiées :**
> 1. **`BestAvailableEncryption`** utilise en interne `PBKDF2-HMAC-SHA256` avec seulement **~100 000 itérations** par défaut. C'est insuffisant contre les attaques par force brute GPU modernes (une RTX 4090 teste ~5M hashes PBKDF2-SHA256/s).
> 2. **`"default_pwd"` comme fallback** — Si l'utilisateur ne fournit pas de mot de passe, la clé privée est "protégée" par un mot de passe trivial. C'est une porte grande ouverte.
> 3. **Aucune validation de complexité** du mot de passe utilisateur avant le chiffrement de la clé.

### 1.2 — Diagnostic `auth_manager.py`

```python
# auth_manager.py — Ligne 16 (VULNÉRABLE)
"pwd_hash": hashlib.sha256("admin123".encode()).hexdigest(),
```

> [!WARNING]
> Le hachage des mots de passe utilise **SHA-256 sans sel (salt)** à 5 endroits dans `auth_manager.py` (lignes 16, 45, 61, 83). SHA-256 n'est PAS un algorithme de hachage de mots de passe — il est conçu pour être rapide, ce qui le rend vulnérable aux rainbow tables et au brute-force.
>
> **Impact : Le mot de passe par défaut `admin123` est immédiatement craquable** (son hash SHA-256 est une constante connue).

### 1.3 — Diagnostic complémentaire `pades_engine.py`

```python
# pades_engine.py — Lignes 72 et 89 (MÊME PATTERN)
safe_pwd = self.password if self.password else "default_pwd"  # ⚠️ Identique !
```

> [!WARNING]
> Le pattern `"default_pwd"` est dupliqué dans `pades_engine.py` (à la fois dans `ensure_p12_exists()` et `sign_pdf_pades()`). Si aucun mot de passe n'est fourni, le certificat PKCS#12 est « protégé » par un mot de passe trivial, compromettant l'intégralité de la chaîne PAdES.

---

### Solution : `crypto_engine.py` renforcé

```python
# crypto_engine.py — VERSION RENFORCÉE
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
        self.public_key.verify(
            bytes.fromhex(signature), data_hash.encode(), ec.ECDSA(hashes.SHA256())
        )

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
                decryption_pwd = derived  # Utilise la clé dérivée comme passphrase
            else:
                # Fallback legacy (migration des anciennes clés)
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
```

### Solution : `auth_manager.py` — Hachage sécurisé avec bcrypt

```python
# auth_manager.py — Remplacement du hachage SHA-256 par bcrypt
import json
import bcrypt
from pathlib import Path


class AuthManager:
    def __init__(self, users_file):
        self.users_file = Path(users_file)
        self.current_user = None
        self._initialize_users()

    @staticmethod
    def _hash_password(password: str) -> str:
        """Hache le mot de passe avec bcrypt (salt intégré, 12 rounds)."""
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")

    @staticmethod
    def _verify_password(password: str, hashed: str) -> bool:
        """Vérifie un mot de passe contre son hash bcrypt."""
        try:
            return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
        except Exception:
            return False

    def _initialize_users(self):
        if not self.users_file.exists():
            default_users = {
                "admin": {
                    "pwd_hash": self._hash_password("Admin@2026!Secure"),
                    "id_responsable": "RESP-ADMIN",
                    "nom": "Administrateur Système",
                    "role": "admin"
                }
            }
            with open(self.users_file, "w") as f:
                json.dump(default_users, f)

    def login(self, username, password):
        if not self.users_file.exists():
            return False
        with open(self.users_file, "r") as f:
            users = json.load(f)
        if username in users:
            if self._verify_password(password, users[username]["pwd_hash"]):
                self.current_user = users[username]
                self.current_user["username"] = username
                return True
        return False

    def change_password(self, username, new_password):
        with open(self.users_file, "r") as f:
            users = json.load(f)
        if username in users:
            users[username]["pwd_hash"] = self._hash_password(new_password)
            with open(self.users_file, "w") as f:
                json.dump(users, f)
            return True
        return False

    def add_user(self, username, password, nom, id_responsable, role="user"):
        with open(self.users_file, "r") as f:
            users = json.load(f)
        if username in users:
            return False, "Ce nom d'utilisateur existe déjà."
        users[username] = {
            "pwd_hash": self._hash_password(password),
            "id_responsable": id_responsable,
            "nom": nom,
            "role": role
        }
        with open(self.users_file, "w") as f:
            json.dump(users, f)
        return True, "Utilisateur créé avec succès."

    # ... (les méthodes get_all_users, delete_user, logout restent identiques)
```

### Solution : `pades_engine.py` — Suppression du fallback `"default_pwd"`

```python
# pades_engine.py — Lignes concernées (72, 89)
# AVANT :
safe_pwd = self.password if self.password else "default_pwd"

# APRÈS :
if not self.password:
    raise ValueError(
        "Mot de passe requis pour la protection du certificat PKCS#12. "
        "Impossible de procéder sans mot de passe."
    )
safe_pwd = self.password
```

> [!TIP]
> **Alternative Argon2id** : Si vous ciblez des machines avec beaucoup de RAM, remplacez Scrypt par **Argon2id** (vainqueur PHC). Installez `argon2-cffi` et utilisez `argon2.PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)`.

---

## Axe 2 — Performance & UX (Lazy Loading + Threading)

### Diagnostic Actuel

```python
# app_unifiee.py — Lignes 64-69 (BLOQUANT)
self.blockchain = BlockchainEngine(self.vault_path)  # ⚠️ Connexion HTTP synchrone (timeout 5s)
self.ocr        = OCREngine()                         # ⚠️ Import pdfplumber + pytesseract
self.dlp        = DLPEngine()
self.stamp      = StampEngine()
self.workflow   = WorkflowEngine(self.vault_path)
```

> [!WARNING]
> **Problème :** `BlockchainEngine.__init__()` appelle `_try_connect()` qui effectue une requête HTTP avec un timeout de 5 secondes. Combiné aux imports lourds de `OCREngine` (pdfplumber, pytesseract, fitz), le démarrage de l'application peut prendre **5-15 secondes** pendant lesquelles l'interface est gelée.
>
> **Impact :** Sur Windows, l'OS peut afficher "L'application ne répond pas" si le thread principal est bloqué >2s.

### Problème complémentaire : opérations lourdes synchrones

```python
# app_unifiee.py — Lignes 440-545 (action_signer)
# Toute la chaîne OCR → DLP → Hash → Signature → Tampon → PAdES → Blockchain
# s'exécute sur le thread principal de Tkinter ⚠️
```

> [!WARNING]
> L'action de certification (`action_signer`, ~100 lignes) exécute toutes les opérations (OCR, DLP, hachage, signature, tampon, PAdES, blockchain) de manière **synchrone sur le thread GUI**. Sur un PDF de 50+ pages, cela peut geler l'interface pendant **10-30 secondes**.

### Solution : Architecture Lazy Loading + ThreadPoolExecutor

```python
# app_unifiee.py — VERSION OPTIMISÉE (extraits clés)
import customtkinter as ctk
import hashlib
import sys
import os
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
import io
import threading
from concurrent.futures import ThreadPoolExecutor, Future
from typing import Optional


class LazyModule:
    """
    Proxy qui diffère l'initialisation d'un module lourd.
    Le module n'est instancié qu'au premier accès réel.
    Thread-safe via un verrou.
    """
    def __init__(self, factory, name: str = "Module"):
        self._factory = factory
        self._instance = None
        self._lock = threading.Lock()
        self._name = name
        self._error = None

    @property
    def is_loaded(self) -> bool:
        return self._instance is not None

    def _ensure_loaded(self):
        if self._instance is None:
            with self._lock:
                if self._instance is None:  # Double-check locking
                    try:
                        print(f"[LAZY] ⏳ Chargement de {self._name}...")
                        self._instance = self._factory()
                        print(f"[LAZY] ✅ {self._name} chargé.")
                    except Exception as e:
                        self._error = e
                        print(f"[LAZY] ❌ Erreur chargement {self._name}: {e}")
                        raise

    def __getattr__(self, name):
        if name.startswith("_"):
            return super().__getattribute__(name)
        self._ensure_loaded()
        return getattr(self._instance, name)


class ModernTrustApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Maroc Digital Trust Gateway — Entreprise Edition v2.0")
        self.geometry("1200x750")
        
        # ... (chemins identiques) ...
        
        # ── Modules légers (instantanés) ──
        self.auth       = AuthManager(self.vault_path / "users.json")
        self.crypto     = CryptoEngine(self.vault_path, self.archive_path)
        self.audit      = AuditLogger(self.vault_path)
        self.pdf_engine = PDFProcessor()
        self.dlp        = DLPEngine()       # Léger (que des regex)
        self.stamp      = StampEngine()     # Léger
        
        # ── Modules LOURDS → Lazy Loading ──
        self.blockchain = LazyModule(
            lambda: BlockchainEngine(self.vault_path),
            name="BlockchainEngine"
        )
        self.ocr = LazyModule(
            lambda: OCREngine(),
            name="OCREngine"
        )
        self.workflow = LazyModule(
            lambda: WorkflowEngine(self.vault_path),
            name="WorkflowEngine"
        )
        
        self.eid = None
        self.pades = None
        self.current_verif_path = None
        
        # ── Thread Pool pour les opérations lourdes ──
        self._executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="TrustWorker")
        
        # ── Pré-charger en arrière-plan (non-bloquant) ──
        self._executor.submit(self._preload_modules)
        
        self.show_login_screen()
    
    def _preload_modules(self):
        """Pré-charge les modules lourds en arrière-plan pendant que l'utilisateur 
        voit l'écran de login."""
        try:
            # Force le chargement du proxy LazyModule en background
            _ = self.blockchain.is_simulation_mode
        except Exception:
            pass
        try:
            _ = self.ocr.FIELD_PATTERNS
        except Exception:
            pass
    
    def _run_in_thread(self, task_fn, callback_fn=None, error_fn=None, 
                        progress_text="Traitement en cours..."):
        """
        Exécute une tâche lourde dans un thread séparé, avec :
        - Un indicateur de progression dans l'UI
        - Un callback sur le thread principal (via after())
        - Une gestion d'erreur propre
        """
        # Afficher un indicateur de chargement
        progress_window = ctk.CTkToplevel(self)
        progress_window.title("Traitement")
        progress_window.geometry("350x120")
        progress_window.transient(self)
        progress_window.grab_set()
        progress_window.resizable(False, False)
        
        ctk.CTkLabel(progress_window, text=progress_text,
                     font=ctk.CTkFont(size=14)).pack(pady=(20, 10))
        progress_bar = ctk.CTkProgressBar(progress_window, mode="indeterminate", width=280)
        progress_bar.pack(pady=10)
        progress_bar.start()
        
        def _worker():
            try:
                result = task_fn()
                # Scheduler le callback sur le thread principal (Tkinter thread-safety)
                self.after(0, lambda: _on_complete(result))
            except Exception as e:
                self.after(0, lambda: _on_error(e))
        
        def _on_complete(result):
            progress_window.destroy()
            if callback_fn:
                callback_fn(result)
        
        def _on_error(error):
            progress_window.destroy()
            if error_fn:
                error_fn(error)
            else:
                messagebox.showerror("Erreur", str(error))
        
        self._executor.submit(_worker)

    # ── Exemple d'utilisation pour la certification ──
    def action_signer(self):
        path = filedialog.askopenfilename(filetypes=[("PDF", "*.pdf")])
        if not path:
            return
        
        # Vérification 2FA AVANT le thread (nécessite l'UI)
        username = self.auth.current_user["username"]
        if self.eid and self.eid.has_totp(username):
            code = simpledialog.askstring("🔐 2FA", "Code à 6 chiffres :")
            if not code or not self.eid.verify_totp(username, code.strip()):
                messagebox.showerror("2FA Échoué", "Code TOTP invalide.")
                return
        
        # Les opérations lourdes passent dans un thread
        def _certify_task():
            """Exécuté dans un worker thread — PAS d'appels UI ici !"""
            results = {"ocr_fields_str": "", "alerts": [], "doc_hash": "", 
                       "signature": None, "stamp_bytes": None}
            
            # OCR
            if self.opt_ocr.get():
                try:
                    ocr_result = self.ocr.get_summary(path)
                    fields = ocr_result.get("fields", {})
                    if fields:
                        results["ocr_fields_str"] = self.ocr.fields_to_qr_string(fields)
                        results["ocr_fields"] = fields
                except Exception as e:
                    print(f"[OCR] Erreur non bloquante: {e}")
            
            # DLP
            if self.opt_dlp.get():
                try:
                    doc_text = self.ocr.extract_text(path)
                    results["alerts"] = self.dlp.scan_document(doc_text, Path(path).name)
                except Exception as e:
                    print(f"[DLP] Erreur non bloquante: {e}")
            
            # Hash + Signature
            results["doc_hash"] = self.pdf_engine.calculate_hash(path)
            results["signature"] = self.crypto.sign_data(results["doc_hash"])
            
            return results
        
        def _on_certification_done(results):
            """Callback sur le thread principal — appels UI autorisés."""
            # Vérifier les alertes DLP (nécessite l'UI)
            alerts = results["alerts"]
            if alerts:
                report = self.dlp.format_report(alerts)
                if self.dlp.is_blocked(alerts):
                    proceed = messagebox.askyesno("🚨 ALERTE DLP", 
                        f"{report}\n\nVoulez-vous procéder (Admin bypass) ?")
                    if not proceed:
                        return
            
            # Continuer avec les étapes suivantes (Tampon, PAdES, Blockchain)
            # ... (reste de la logique de certification, adaptée depuis action_signer)
            messagebox.showinfo("SUCCÈS 🛡️", "Document certifié avec succès !")
        
        self._run_in_thread(
            _certify_task,
            callback_fn=_on_certification_done,
            progress_text="🔐 Certification en cours..."
        )
    
    def destroy(self):
        """Nettoyage propre du ThreadPool à la fermeture."""
        self._executor.shutdown(wait=False, cancel_futures=True)
        super().destroy()
```

> [!IMPORTANT]
> **Règle d'or Tkinter** : Ne JAMAIS appeler `messagebox`, `widget.configure()`, ou tout autre méthode UI depuis un thread worker. Utilisez toujours `self.after(0, callback)` pour repasser sur le thread principal.

---

## Axe 3 — Résilience Blockchain (Vérification Hybride)

### Diagnostic Actuel

```python
# blockchain_engine.py — Lignes 76-87 (MODE LIVE FACTICE)
if not self._simulation_mode and self._web3:
    try:
        tx_hash = self._simulate_tx_hash(doc_hash)  # ⚠️ Même en mode "live", c'est simulé !
        mode = "live_simulated"
    except Exception as e:
        tx_hash = self._simulate_tx_hash(doc_hash)
        mode = "simulation"
```

> [!CAUTION]
> **3 Problèmes majeurs :**
> 1. **Aucune transaction réelle** n'est jamais envoyée, même quand Web3 est connecté. La variable `mode` est mise à `"live_simulated"` mais le code appelle toujours `_simulate_tx_hash()` — le mode "live" est un mensonge fonctionnel.
> 2. **Vérification locale uniquement** — `verify_anchor()` (lignes 107-124) ne consulte QUE le JSON local, sans aucune interrogation on-chain. Un fichier JSON modifié manuellement donnerait un faux positif.
> 3. **Aucune gestion de la synchronisation** entre le registre local et la blockchain réelle. Pas de file d'attente en cas de déconnexion.

### Problème complémentaire : le `tx_hash` simulé est prédictible

```python
# blockchain_engine.py — Lignes 55-58
def _simulate_tx_hash(self, doc_hash: str) -> str:
    seed = f"MAROC_TRUST_{doc_hash}_{int(time.time())}"
    return "0x" + hashlib.sha256(seed.encode()).hexdigest()
```

> [!NOTE]
> Le hash simulé utilise un préfixe `"0x"` standard (pas `"0xSIM_"`) ce qui le rend **indistinguable** d'un vrai hash de transaction pour un utilisateur ou un auditeur. C'est de la sécurité par obscurité.

### Solution : `blockchain_engine.py` avec vérification hybride

```python
"""
blockchain_engine.py — Ancrage Hybride (Smart Contract + Registre Local)
Maroc Digital Trust Gateway — Module Décentralisé

Architecture de vérification :
┌─────────────────────┐
│  verify_anchor()    │
├─────────────────────┤
│  1. Vérifier local  │ ← Rapide, toujours disponible
│  2. Vérifier on-chain│ ← Si réseau disponible
│  3. Réconcilier     │ ← Synchroniser les résultats
└─────────────────────┘
"""
import hashlib
import json
import time
import os
from datetime import datetime
from pathlib import Path
from typing import Optional
from enum import Enum


class AnchorMode(Enum):
    LIVE = "live"
    DEGRADED = "degraded"        # Réseau down → registre local uniquement
    SIMULATION = "simulation"    # Web3 non installé


# ── ABI minimal du Smart Contract de notarisation ──
# Le contrat doit implémenter : anchor(bytes32 docHash) et verify(bytes32 docHash) → (bool, uint256)
NOTARY_CONTRACT_ABI = [
    {
        "inputs": [{"name": "docHash", "type": "bytes32"}],
        "name": "anchor",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"name": "docHash", "type": "bytes32"}],
        "name": "verify",
        "outputs": [
            {"name": "exists", "type": "bool"},
            {"name": "timestamp", "type": "uint256"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "docHash", "type": "bytes32"},
            {"indexed": False, "name": "timestamp", "type": "uint256"},
            {"indexed": True, "name": "anchorer", "type": "address"}
        ],
        "name": "HashAnchored",
        "type": "event"
    }
]


class BlockchainEngine:
    """
    Ancrage hybride des empreintes documentaires sur Ethereum Sepolia.
    
    Modes de fonctionnement :
    - LIVE       : Transactions réelles via Smart Contract + registre local
    - DEGRADED   : Réseau indisponible → registre local avec file de rattrapage
    - SIMULATION : Web3 non installé → simulation complète
    """

    def __init__(self, vault_path: Path, rpc_url: str = None,
                 contract_address: str = None, private_key: str = None):
        self.vault_path = Path(vault_path)
        self.ledger_file = self.vault_path / "blockchain_ledger.json"
        self.pending_file = self.vault_path / "blockchain_pending.json"  # File d'attente
        self.rpc_url = rpc_url or os.getenv("SEPOLIA_RPC_URL", "https://rpc.sepolia.org")
        self.contract_address = contract_address or os.getenv("NOTARY_CONTRACT_ADDRESS")
        self._wallet_key = private_key or os.getenv("WALLET_PRIVATE_KEY")
        
        self._web3 = None
        self._contract = None
        self._account = None
        self._mode = AnchorMode.SIMULATION
        
        self._try_connect()

    def _try_connect(self):
        """Tente la connexion au réseau Ethereum. Bascule en mode dégradé si échec."""
        try:
            from web3 import Web3
            w3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={"timeout": 5}))
            
            if not w3.is_connected():
                raise ConnectionError("Nœud Sepolia non accessible")
            
            self._web3 = w3
            
            # Charger le contrat si l'adresse est configurée
            if self.contract_address and self._wallet_key:
                self._contract = w3.eth.contract(
                    address=Web3.to_checksum_address(self.contract_address),
                    abi=NOTARY_CONTRACT_ABI
                )
                self._account = w3.eth.account.from_key(self._wallet_key)
                self._mode = AnchorMode.LIVE
                print(f"[BLOCKCHAIN] ✅ Mode LIVE — Contrat: {self.contract_address[:10]}...")
            else:
                self._mode = AnchorMode.DEGRADED
                print("[BLOCKCHAIN] ⚠️ Mode DÉGRADÉ — Web3 connecté mais pas de contrat configuré")
            
            # Tenter de synchroniser la file d'attente
            self._flush_pending_queue()
            
        except ImportError:
            self._mode = AnchorMode.SIMULATION
            print("[BLOCKCHAIN] ℹ️ Mode SIMULATION — web3 non installé")
        except Exception as e:
            self._mode = AnchorMode.DEGRADED
            print(f"[BLOCKCHAIN] ⚠️ Mode DÉGRADÉ — {str(e)[:80]}")

    # ── Registre local ──
    def _load_ledger(self) -> dict:
        if self.ledger_file.exists():
            with open(self.ledger_file, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def _save_ledger(self, ledger: dict):
        self.ledger_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.ledger_file, "w", encoding="utf-8") as f:
            json.dump(ledger, f, indent=2, ensure_ascii=False)

    # ── File d'attente (mode dégradé) ──
    def _load_pending(self) -> list:
        if self.pending_file.exists():
            with open(self.pending_file, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

    def _save_pending(self, pending: list):
        with open(self.pending_file, "w", encoding="utf-8") as f:
            json.dump(pending, f, indent=2, ensure_ascii=False)

    def _add_to_pending(self, doc_hash: str, doc_name: str):
        """Ajoute un hash à la file d'attente pour ancrage ultérieur."""
        pending = self._load_pending()
        if not any(p["doc_hash"] == doc_hash for p in pending):
            pending.append({
                "doc_hash": doc_hash,
                "doc_name": doc_name,
                "queued_at": datetime.now().isoformat(),
            })
            self._save_pending(pending)
            print(f"[BLOCKCHAIN] 📋 Hash ajouté à la file d'attente ({len(pending)} en attente)")

    def _flush_pending_queue(self):
        """Tente d'ancrer tous les hashes en attente (appelé à la reconnexion)."""
        if self._mode != AnchorMode.LIVE:
            return
        
        pending = self._load_pending()
        if not pending:
            return
        
        print(f"[BLOCKCHAIN] 🔄 Synchronisation de {len(pending)} hash(es) en attente...")
        remaining = []
        for item in pending:
            try:
                self._anchor_on_chain(item["doc_hash"])
                # Mettre à jour le registre local avec le vrai TX
                ledger = self._load_ledger()
                if item["doc_hash"] in ledger:
                    ledger[item["doc_hash"]]["mode"] = "live"
                    ledger[item["doc_hash"]]["synced_at"] = datetime.now().isoformat()
                    self._save_ledger(ledger)
            except Exception as e:
                remaining.append(item)
                print(f"[BLOCKCHAIN] ⚠️ Échec sync: {str(e)[:60]}")
        
        self._save_pending(remaining)
        if not remaining:
            print("[BLOCKCHAIN] ✅ File d'attente synchronisée.")

    # ── Transaction on-chain réelle ──
    def _anchor_on_chain(self, doc_hash: str) -> str:
        """Envoie une transaction réelle au Smart Contract sur Sepolia."""
        if not self._contract or not self._account:
            raise RuntimeError("Contrat ou wallet non configuré")
        
        # Convertir le hash string en bytes32
        doc_hash_bytes = bytes.fromhex(doc_hash) if len(doc_hash) == 64 else \
                         hashlib.sha256(doc_hash.encode()).digest()
        
        # Construire la transaction
        nonce = self._web3.eth.get_transaction_count(self._account.address)
        tx = self._contract.functions.anchor(doc_hash_bytes).build_transaction({
            "from": self._account.address,
            "nonce": nonce,
            "gas": 100_000,
            "gasPrice": self._web3.eth.gas_price,
            "chainId": 11155111,  # Sepolia chain ID
        })
        
        # Signer et envoyer
        signed_tx = self._web3.eth.account.sign_transaction(tx, self._wallet_key)
        tx_hash = self._web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        
        # Attendre la confirmation (max 60s)
        receipt = self._web3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
        
        if receipt.status != 1:
            raise RuntimeError(f"Transaction échouée: {tx_hash.hex()}")
        
        print(f"[BLOCKCHAIN] ⛓️ TX confirmée: {tx_hash.hex()[:20]}... (bloc #{receipt.blockNumber})")
        return tx_hash.hex()

    def _verify_on_chain(self, doc_hash: str) -> Optional[dict]:
        """Interroge le Smart Contract pour vérifier si un hash est ancré."""
        if not self._contract:
            return None
        
        try:
            doc_hash_bytes = bytes.fromhex(doc_hash) if len(doc_hash) == 64 else \
                             hashlib.sha256(doc_hash.encode()).digest()
            
            exists, timestamp = self._contract.functions.verify(doc_hash_bytes).call()
            
            if exists:
                return {
                    "found_on_chain": True,
                    "timestamp": datetime.fromtimestamp(timestamp).isoformat(),
                    "network": "Sepolia Testnet",
                    "verification_method": "smart_contract"
                }
        except Exception as e:
            print(f"[BLOCKCHAIN] ⚠️ Erreur vérification on-chain: {e}")
        
        return None

    def _simulate_tx_hash(self, doc_hash: str) -> str:
        seed = f"MAROC_TRUST_{doc_hash}_{int(time.time())}"
        return "0xSIM_" + hashlib.sha256(seed.encode()).hexdigest()

    # ── API Publique ──
    def anchor_hash(self, doc_hash: str, doc_name: str = "document") -> dict:
        """
        Ancre le hash du document selon le mode courant :
        - LIVE      : Transaction réelle + registre local
        - DEGRADED  : Registre local + file d'attente pour sync ultérieure
        - SIMULATION: Registre local + TX simulé
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        tx_hash = ""
        mode = self._mode.value

        if self._mode == AnchorMode.LIVE:
            try:
                tx_hash = self._anchor_on_chain(doc_hash)
                mode = "live"
            except Exception as e:
                # Fallback en mode dégradé pour cette opération
                tx_hash = self._simulate_tx_hash(doc_hash)
                self._add_to_pending(doc_hash, doc_name)
                mode = "degraded"
                print(f"[BLOCKCHAIN] ⚠️ Fallback dégradé: {e}")
        
        elif self._mode == AnchorMode.DEGRADED:
            tx_hash = self._simulate_tx_hash(doc_hash)
            self._add_to_pending(doc_hash, doc_name)
            mode = "degraded"
        
        else:  # SIMULATION
            tx_hash = self._simulate_tx_hash(doc_hash)
            mode = "simulation"

        result = {
            "tx_hash": tx_hash,
            "doc_hash": doc_hash,
            "doc_name": doc_name,
            "timestamp": timestamp,
            "mode": mode,
            "network": "Sepolia Testnet",
            "anchored_at": int(time.time())
        }

        ledger = self._load_ledger()
        ledger[doc_hash] = result
        self._save_ledger(ledger)

        print(f"[BLOCKCHAIN] ⛓️ Hash ancré — TX: {tx_hash[:20]}... | Mode: {mode}")
        return result

    def verify_anchor(self, doc_hash: str) -> dict:
        """
        Vérification HYBRIDE en 3 étapes :
        1. Registre local (rapide, toujours dispo)
        2. Smart Contract on-chain (si disponible)
        3. Réconciliation des résultats
        """
        # Étape 1 : Vérification locale
        ledger = self._load_ledger()
        local_record = ledger.get(doc_hash)
        
        # Étape 2 : Vérification on-chain (si possible)
        chain_result = None
        if self._mode == AnchorMode.LIVE:
            chain_result = self._verify_on_chain(doc_hash)
        
        # Étape 3 : Réconciliation
        if chain_result and chain_result.get("found_on_chain"):
            # La blockchain fait foi
            result = {
                "found": True,
                "verified_on_chain": True,
                "local_record": local_record,
                "chain_record": chain_result,
                "confidence": "HIGH",
                "message": "✅ Hash vérifié ON-CHAIN (preuve irréfutable)"
            }
        elif local_record:
            confidence = "MEDIUM" if local_record.get("mode") == "live" else "LOW"
            result = {
                "found": True,
                "verified_on_chain": False,
                "local_record": local_record,
                "chain_record": None,
                "confidence": confidence,
                "message": f"⚠️ Hash trouvé LOCALEMENT uniquement (confiance: {confidence})"
            }
        else:
            result = {
                "found": False,
                "verified_on_chain": False,
                "local_record": None,
                "chain_record": None,
                "confidence": "NONE",
                "message": "❌ Hash introuvable (local + on-chain)"
            }
        
        print(f"[BLOCKCHAIN] Vérification: {result['message']}")
        return result

    def retry_connection(self):
        """Retente la connexion et synchronise la file d'attente."""
        self._try_connect()
        return self._mode

    def get_pending_count(self) -> int:
        return len(self._load_pending())

    def get_all_anchors(self) -> dict:
        return self._load_ledger()

    @property
    def is_simulation_mode(self) -> bool:
        return self._mode == AnchorMode.SIMULATION

    @property
    def current_mode(self) -> AnchorMode:
        return self._mode
```

> [!TIP]
> **Configuration `.env` requise pour le mode LIVE :**
> ```env
> SEPOLIA_RPC_URL=https://sepolia.infura.io/v3/VOTRE_CLE_INFURA
> NOTARY_CONTRACT_ADDRESS=0x...votre_contrat_deploye...
> WALLET_PRIVATE_KEY=0x...cle_privee_wallet_testnet...
> ```
> **Ne jamais versionner les clés privées !** Utilisez `python-dotenv` + `.gitignore`.

---

## Axe 4 — Conformité DLP (Patterns + Score de Risque)

### Diagnostic Actuel

```python
# dlp_engine.py — Lignes 22-45 (IMPRÉCIS)
("CIN Marocain",       r'\b[A-Z]{1,2}\d{5,6}\b',                         "WARNING",  "Carte d'Identité Nationale détectée"),
("RIB Marocain",       r'\b\d{3}\s?\d{3}\s?\d{10}\s?\d{2}\b',            "WARNING",  "RIB bancaire détecté"),
("IBAN",               r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,19}\b',          "CRITICAL", "IBAN bancaire détecté — risque de fraude"),
("Carte Crédit",       r'\b(?:\d{4}[\s\-]?){3}\d{4}\b',                  "CRITICAL", "Numéro de carte bancaire potentiel"),
```

> [!WARNING]
> **Problèmes des patterns actuels :**
> 1. **RIB Marocain** — Le format réel est `XXX YYY ZZZZZZZZZZZZZZZZ CC` (3 chiffres banque + 3 chiffres ville + 16 chiffres compte + 2 chiffres clé = **24 chiffres**). Votre regex n'en capture que 18 (`\d{3}\d{3}\d{10}\d{2}` = 18). De plus, aucune validation de la clé RIB (algorithme modulo 97).
> 2. **CIN** — `\b[A-Z]{1,2}\d{5,6}\b` matche trop largement (ex: "AB12345" serait matché, mais aussi des codes produit comme `Z10001`). La CIN marocaine utilise des préfixes spécifiques par région.
> 3. **IBAN Marocain** — Le pattern est générique et ne valide pas le format `MA` + 26 caractères. Un IBAN allemand (`DE89...`) serait traité de la même manière qu'un IBAN marocain.
> 4. **Carte bancaire** — Le pattern `(?:\d{4}[\s\-]?){3}\d{4}` matche n'importe quelle séquence de 16 chiffres, y compris des numéros de série, codes postaux longs, etc. **Aucune validation Luhn** n'est effectuée.
> 5. **Pas de score global** — L'approche binaire (bloqué si `CRITICAL`, sinon ok) est trop rigide. Un document avec 5 `WARNING` devrait potentiellement être bloqué, mais il ne l'est pas actuellement.
> 6. **Pattern CNSS incohérent** — Le lookahead `\b\d{9,10}\b(?=.*CNSS)` ne fonctionne correctement que si "CNSS" apparaît APRÈS le numéro sur la même ligne. Un numéro CNSS précédé par le mot CNSS ne sera pas détecté.

### Solution : `dlp_engine.py` avec patterns robustes et scoring

```python
"""
dlp_engine.py — Détection de Données Sensibles (DLP - Data Loss Prevention)
Maroc Digital Trust Gateway — Module Sécurité & Conformité v2.0

Améliorations :
- Patterns regex adaptés aux formats marocains réels
- Score de risque global pondéré (0-100)
- Seuils configurables pour bloquer/autoriser
- Validation algorithmique (clé RIB, Luhn pour cartes)
"""
import re
from typing import List, Dict, Tuple
from dataclasses import dataclass, field


@dataclass
class DLPRule:
    """Règle DLP avec pondération et validation optionnelle."""
    name: str
    pattern: str
    severity: str           # INFO, WARNING, CRITICAL
    message: str
    weight: float = 1.0     # Pondération dans le score (1.0 = standard)
    validator: str = None   # Nom de la méthode de validation post-regex
    flags: int = re.IGNORECASE


class DLPEngine:
    """
    Analyse le contenu textuel d'un document avant signature pour détecter
    des données sensibles ou confidentielles non intentionnelles.
    
    Score de risque global :
    - 0-30   : SAFE (vert)     → Signature autorisée
    - 31-60  : CAUTION (jaune) → Confirmation requise
    - 61-100 : DANGER (rouge)  → Signature bloquée (bypass admin requis)
    """

    # ── Seuils de décision ──
    THRESHOLD_SAFE = 30
    THRESHOLD_CAUTION = 60
    # Au-dessus de 60 → DANGER

    # ── Poids des sévérités ──
    SEVERITY_WEIGHTS = {"CRITICAL": 25, "WARNING": 10, "INFO": 3}

    # ── Règles DLP v2 ──
    DLP_RULES: List[DLPRule] = [
        # --- Identifiants marocains ---
        DLPRule(
            name="CIN Marocain",
            # Préfixes régionaux valides : A, B, BA, BB, BH, BJ, BK, BL, BE, C, CB, D, DA, DB,
            # E, EA, EE, F, G, H, HA, I, IA, J, JA-JZ, K, KB, L, LA, M, MA, N, PA, PB, Q, QA,
            # R, S, SA, SH, SJ, SL, SR, T, TA, U, UA, V, W, WA, Z, ZG, ZH, ZT
            pattern=r'\b(?:B[ABEHJ-L]?|C[B]?|D[AB]?|E[AE]?|F|G|H[A]?|I[A]?|J[A-FHK-MTYZ]?|K[B]?|L[A]?|M[A]?|N|P[AB]|Q[A]?|R|S[AHJLR]?|T[A]?|U[A]?|V|W[A]?|Z[GHT]?|A)\d{5,7}\b',
            severity="WARNING",
            message="Carte d'Identité Nationale marocaine détectée",
            weight=1.2,
        ),
        DLPRule(
            name="Passeport Marocain",
            pattern=r'\b[A-Z]{2}\d{7}\b',
            severity="WARNING",
            message="Numéro de passeport marocain potentiel détecté",
        ),

        # --- Données financières marocaines ---
        DLPRule(
            name="IBAN Marocain",
            # IBAN Maroc : MA + 2 chiffres contrôle + 24 caractères = 28 au total
            pattern=r'\bMA\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b',
            severity="CRITICAL",
            message="IBAN bancaire marocain détecté — risque de fraude",
            weight=2.0,
        ),
        DLPRule(
            name="IBAN International",
            pattern=r'\b[A-Z]{2}\d{2}\s?[A-Z0-9]{4}(?:\s?\d{4}){3,7}(?:\s?\d{1,4})?\b',
            severity="CRITICAL",
            message="IBAN international détecté",
            weight=1.5,
        ),
        DLPRule(
            name="Carte Bancaire",
            # Visa (4xxx), Mastercard (5xxx, 2xxx), Amex (3xxx)
            pattern=r'\b(?:4\d{3}|5[1-5]\d{2}|2[2-7]\d{2}|3[47]\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b',
            severity="CRITICAL",
            message="Numéro de carte bancaire détecté",
            weight=2.5,
            validator="_validate_luhn",
        ),
        DLPRule(
            name="RIB Marocain",
            # Format réel : 3 banque + 3 ville + 16 compte + 2 clé = 24 chiffres
            # Codes banques courants : 007 (ATW), 011 (BMCE), 013 (BMCI), 021 (CDM),
            # 022 (SGMB), 025 (BCP), 050 (CIH), 181 (AWB), 190 (BAM), 230 (CFG)
            pattern=r'\b(?:007|011|013|021|022|025|050|181|190|230)\s?\d{3}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b',
            severity="CRITICAL",
            message="RIB bancaire marocain détecté (codes banque validés)",
            weight=2.0,
            validator="_validate_rib_key",
        ),

        # --- Données médicales ---
        DLPRule(
            name="Données Médicales",
            pattern=r'(?:diagnostic|pathologie|traitement\s+(?:médical|médicamenteux)|ordonnance\s+médicale|médecin\s+traitant|dossier\s+médical|antécédents?\s+(?:médicaux|chirurgicaux))',
            severity="WARNING",
            message="Données médicales confidentielles potentielles",
            weight=1.5,
        ),
        DLPRule(
            name="Numéro CNSS",
            # CNSS marocain : 9 chiffres, souvent préfixé par contexte
            pattern=r'(?:CNSS|sécurité\s+sociale|immatriculation)[\s:]*(d{9,10})',
            severity="WARNING",
            message="Numéro CNSS / sécurité sociale détecté",
            weight=1.3,
        ),
        DLPRule(
            name="Numéro AMO",
            pattern=r'(?:AMO|assurance\s+maladie)[\s:#]*(\d{8,12})',
            severity="WARNING",
            message="Numéro AMO (Assurance Maladie Obligatoire) détecté",
            weight=1.3,
        ),

        # --- Données confidentielles ---
        DLPRule(
            name="Marquage Confidentiel",
            pattern=r'\b(?:confidentiel|secret|top\s+secret|diffusion\s+restreinte|ne\s+pas\s+diffuser|usage\s+interne\s+(?:uniquement|exclusif))\b',
            severity="CRITICAL",
            message="Document marqué confidentiel — diffusion restreinte",
            weight=3.0,
        ),
        DLPRule(
            name="Mot de passe en clair",
            pattern=r'(?:mot\s*de\s*passe|password|mdp|pwd|passphrase)\s*[:=]\s*\S{4,}',
            severity="CRITICAL",
            message="Mot de passe en clair détecté dans le document",
            weight=3.0,
        ),
        DLPRule(
            name="Clé API / Token",
            pattern=r'(?:api[_\-]?key|api[_\-]?secret|token|secret[_\-]?key|access[_\-]?key|auth[_\-]?token)\s*[:=]\s*[A-Za-z0-9_\-\.]{20,}',
            severity="CRITICAL",
            message="Clé API ou token secret détecté",
            weight=3.0,
        ),
        DLPRule(
            name="Clé Privée",
            pattern=r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
            severity="CRITICAL",
            message="Clé privée cryptographique détectée dans le document !",
            weight=5.0,
        ),

        # --- Informations personnelles (RGPD / Loi 09-08 Maroc) ---
        DLPRule(
            name="Téléphone Marocain",
            # Mobile : 06/07, Fixe : 05, VoIP : 08
            pattern=r'\b(?:(?:\+212|00212)[\s\-]?[5-8]\d{2}[\s\-]?\d{2}[\s\-]?\d{2}[\s\-]?\d{2}|0[5-8][\s\-]?\d{2}[\s\-]?\d{2}[\s\-]?\d{2}[\s\-]?\d{2})\b',
            severity="INFO",
            message="Numéro de téléphone marocain détecté",
        ),
        DLPRule(
            name="Adresse Email",
            pattern=r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,7}\b',
            severity="INFO",
            message="Adresse email présente dans le document",
        ),
        DLPRule(
            name="Coordonnées GPS",
            # Maroc : Lat ~27-36, Lon ~(-13)–(-1)
            pattern=r'\b(?:2[7-9]|3[0-6])\.\d{4,7}\s*,\s*-?(?:1[0-3]|[1-9])\.\d{4,7}\b',
            severity="INFO",
            message="Coordonnées GPS (zone Maroc) détectées",
        ),
    ]

    # ── Validateurs algorithmiques ──
    
    @staticmethod
    def _validate_luhn(number_str: str) -> bool:
        """Algorithme de Luhn pour vérifier les numéros de carte bancaire."""
        digits = [int(d) for d in re.sub(r'[\s\-]', '', number_str) if d.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        
        checksum = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        return checksum % 10 == 0

    @staticmethod
    def _validate_rib_key(rib_str: str) -> bool:
        """
        Vérifie la clé de contrôle d'un RIB marocain (modulo 97).
        RIB = 24 chiffres, les 2 derniers sont la clé.
        Validation : (22 premiers chiffres * 100 + clé) mod 97 == 0
        """
        digits = re.sub(r'\s', '', rib_str)
        if len(digits) != 24 or not digits.isdigit():
            return False
        
        body = int(digits[:22])
        key = int(digits[22:24])
        return (body * 100 + key) % 97 == 0

    # ── Moteur de scan ──
    
    def scan_document(self, text: str, doc_name: str = "document") -> List[Dict]:
        """
        Scanne le texte et retourne les alertes DLP avec score de risque.
        """
        alerts = []
        for rule in self.DLP_RULES:
            matches = re.findall(rule.pattern, text, rule.flags)
            if not matches:
                continue
            
            # Validation post-regex (si un validateur est défini)
            validated_matches = matches
            if rule.validator:
                validator_fn = getattr(self, rule.validator, None)
                if validator_fn:
                    validated_matches = [m for m in matches if validator_fn(
                        m if isinstance(m, str) else m[0] if isinstance(m, tuple) else str(m)
                    )]
            
            if not validated_matches:
                continue
            
            # Masquage sécurisé de l'extrait
            sample = str(validated_matches[0])
            clean_sample = re.sub(r'\s', '', sample)
            if len(clean_sample) > 8:
                excerpt = clean_sample[:4] + "****" + clean_sample[-2:]
            else:
                excerpt = "****"
            
            alerts.append({
                "rule":     rule.name,
                "severity": rule.severity,
                "message":  rule.message,
                "excerpt":  excerpt,
                "count":    len(validated_matches),
                "weight":   rule.weight,
            })

        # Trier par sévérité (CRITICAL en premier)
        severity_order = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
        alerts.sort(key=lambda x: severity_order.get(x["severity"], 99))

        if alerts:
            print(f"[DLP] 🚨 {len(alerts)} alerte(s) sur '{doc_name}'")
        else:
            print(f"[DLP] ✅ RAS — '{doc_name}'")

        return alerts

    # ── Score de risque global ──

    def compute_risk_score(self, alerts: List[Dict]) -> dict:
        """
        Calcule un score de risque global pondéré (0-100).
        
        Formule : score = Σ (poids_sévérité × poids_règle × min(count, 3))
        Plafonné à 100.
        """
        if not alerts:
            return {
                "score": 0, "level": "SAFE", "color": "#27ae60",
                "decision": "ALLOW", "breakdown": {}
            }
        
        total_score = 0
        breakdown = {"CRITICAL": 0, "WARNING": 0, "INFO": 0}
        
        for alert in alerts:
            base = self.SEVERITY_WEIGHTS.get(alert["severity"], 1)
            weight = alert.get("weight", 1.0)
            count_factor = min(alert["count"], 3)  # Plafonner l'impact de la répétition
            
            contribution = base * weight * count_factor
            total_score += contribution
            breakdown[alert["severity"]] = breakdown.get(alert["severity"], 0) + contribution
        
        # Plafonner à 100
        total_score = min(int(total_score), 100)
        
        # Déterminer le niveau
        if total_score <= self.THRESHOLD_SAFE:
            level, color, decision = "SAFE", "#27ae60", "ALLOW"
        elif total_score <= self.THRESHOLD_CAUTION:
            level, color, decision = "CAUTION", "#f39c12", "CONFIRM"
        else:
            level, color, decision = "DANGER", "#e74c3c", "BLOCK"
        
        return {
            "score": total_score,
            "level": level,
            "color": color,
            "decision": decision,
            "breakdown": breakdown,
        }

    def get_max_severity(self, alerts: List[Dict]) -> str:
        if not alerts:
            return "CLEAN"
        severity_order = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
        return min(alerts, key=lambda x: severity_order.get(x["severity"], 99))["severity"]

    def is_blocked(self, alerts: List[Dict]) -> bool:
        """Bloque si le score de risque dépasse le seuil CAUTION."""
        risk = self.compute_risk_score(alerts)
        return risk["decision"] == "BLOCK"

    def format_report(self, alerts: List[Dict]) -> str:
        """Formate un rapport DLP avec score de risque global."""
        if not alerts:
            return "✅ Aucune anomalie détectée. Document sûr."
        
        risk = self.compute_risk_score(alerts)
        icons = {"CRITICAL": "🔴", "WARNING": "🟡", "INFO": "🔵"}
        
        lines = [
            f"{'='*55}",
            "RAPPORT DLP — ANALYSE DE SÉCURITÉ",
            f"{'='*55}",
            "",
            f"📊 SCORE DE RISQUE : {risk['score']}/100 ({risk['level']})",
            f"   Décision : {risk['decision']}",
            f"{'─'*55}",
        ]
        
        for a in alerts:
            icon = icons.get(a["severity"], "⚪")
            lines.append(f"\n{icon} [{a['severity']}] {a['rule']} (×{a['count']})")
            lines.append(f"   ➤ {a['message']}")
            lines.append(f"   ➤ Extrait : {a['excerpt']}")
        
        lines.append(f"\n{'='*55}")
        critical = sum(1 for a in alerts if a["severity"] == "CRITICAL")
        warning = sum(1 for a in alerts if a["severity"] == "WARNING")
        lines.append(f"Total : {critical} CRITIQUE(S) | {warning} AVERTISSEMENT(S)")
        lines.append(f"Score final : {risk['score']}/100 → {risk['decision']}")
        
        return "\n".join(lines)
```

### Intégration du score dans `app_unifiee.py`

```python
# Dans action_signer(), remplacer la logique DLP par :
if self.opt_dlp.get():
    try:
        doc_text = self.ocr.extract_text(path)
        alerts = self.dlp.scan_document(doc_text, Path(path).name)
        
        if alerts:
            risk = self.dlp.compute_risk_score(alerts)
            report = self.dlp.format_report(alerts)
            
            if risk["decision"] == "BLOCK":
                proceed = messagebox.askyesno(
                    f"🚨 SCORE DE RISQUE: {risk['score']}/100 — {risk['level']}",
                    f"{report}\n\n"
                    "⚠️ Le score dépasse le seuil de sécurité.\n"
                    "Voulez-vous procéder malgré tout (Admin bypass) ?"
                )
                if not proceed:
                    self.audit.log_action(username, "DLP_BLOCK", 
                        f"Score: {risk['score']} | File: {Path(path).name}")
                    return
                self.audit.log_action(username, "DLP_BYPASS", 
                    f"Score: {risk['score']} | File: {Path(path).name}")
            
            elif risk["decision"] == "CONFIRM":
                messagebox.showwarning(
                    f"⚠️ SCORE DE RISQUE: {risk['score']}/100 — ATTENTION",
                    report
                )
    except Exception as e:
        print(f"[DLP] Erreur non bloquante: {e}")
```

---

## Axe 5 — Sécurité de l'API (CORS, Auth, Rate Limiting)

> ⭐ **NOUVEAU** — Cet axe n'était pas dans l'audit initial.

### 5.1 — CORS Wildcard (`api/main.py`)

```python
# api/main.py — Lignes 12-18 (VULNÉRABLE)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # ⚠️ Accepte TOUTES les origines
    allow_credentials=True,       # ⚠️ Combiné avec credentials = DANGEREUX
    allow_methods=["*"],
    allow_headers=["*"],
)
```

> [!CAUTION]
> **OWASP A01:2025 — Broken Access Control**
> 
> La combinaison `allow_origins=["*"]` + `allow_credentials=True` est une **vulnérabilité critique**. Elle permet à n'importe quel site malveillant d'envoyer des requêtes authentifiées à votre API depuis le navigateur de la victime (CSRF via CORS).
>
> **Vecteur d'attaque :** Un attaquant crée une page `evil.com` avec du JavaScript qui envoie des requêtes à `localhost:8000/api/sign` avec les cookies de session de l'utilisateur.

**Solution :**

```python
# api/main.py — VERSION SÉCURISÉE
import os

ALLOWED_ORIGINS = os.getenv(
    "CORS_ORIGINS", 
    "http://localhost:3000,http://localhost:8080"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,  # Origines explicites uniquement
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
```

### 5.2 — Aucune authentification API (`api/dependencies.py`)

```python
# api/dependencies.py — Aucune vérification d'identité
# Les instances sont globales, AUCUN middleware d'authentification
auth_manager = AuthManager(VAULT_PATH / "users.json")
# Toutes les routes sont publiquement accessibles !
```

> [!CAUTION]
> **OWASP A07:2025 — Identification and Authentication Failures**
>
> L'API FastAPI n'a **aucun middleware d'authentification**. Toutes les routes (certification, blockchain, administration) sont accessibles sans jeton. Quiconque connaît l'URL du serveur peut signer, ancrer ou supprimer des documents.

**Solution : Intégrer JWT avec FastAPI**

```python
# api/auth_middleware.py — NOUVEAU FICHIER
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
import os

SECRET_KEY = os.getenv("JWT_SECRET_KEY", os.urandom(32).hex())
ALGORITHM = "HS256"
TOKEN_EXPIRY_HOURS = 8

security = HTTPBearer()


def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRY_HOURS)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Token invalide")
        return {"username": username, "role": payload.get("role", "user")}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expiré")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token invalide")


def require_admin(user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Accès réservé aux administrateurs")
    return user
```

### 5.3 — Aucun Rate Limiting

> [!WARNING]
> L'API n'implémente aucun **rate limiting**. Un attaquant peut :
> - Envoyer des milliers de requêtes de login par seconde (brute-force)
> - Saturer le service de certification (DoS)
> - Épuiser les fonds du wallet blockchain (si mode LIVE)

**Solution : `slowapi` pour FastAPI**

```python
# api/main.py — Ajouter le rate limiter
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Sur les routes sensibles :
@router.post("/login")
@limiter.limit("5/minute")  # Max 5 tentatives de login par minute
async def login(request: Request, ...):
    ...

@router.post("/sign")
@limiter.limit("10/minute")  # Max 10 signatures par minute
async def sign_document(request: Request, ...):
    ...
```

### 5.4 — Endpoint `/health` manquant

```python
# api/main.py — L'endpoint /health référencé dans le Dockerfile n'existe pas !
# Dockerfile ligne 37 :
# HEALTHCHECK ... CMD python -c "urllib.request.urlopen('http://localhost:8000/health')"
```

> [!NOTE]
> Le `HEALTHCHECK` du Dockerfile (optimisé dans l'Axe 9) référence `/health`, mais cette route n'existe pas dans `api/main.py`. Le healthcheck échouera systématiquement.

**Solution :**

```python
# api/main.py — Ajouter l'endpoint health
@app.get("/health")
def health_check():
    return {"status": "healthy", "version": "2.0.0"}
```

---

## Axe 6 — Intégrité des Logs d'Audit

> ⭐ **NOUVEAU** — Cet axe n'était pas dans l'audit initial.

### Diagnostic `audit_logger.py`

```python
# audit_logger.py — Fichier entier (33 lignes)
class AuditLogger:
    def __init__(self, log_dir):
        self.log_path = Path(log_dir) / "audit.log"
        # ...
        fh = logging.FileHandler(str(self.log_path))  # ⚠️ Fichier texte non protégé
    
    def log_action(self, user_id, action, details):
        log_entry = {
            "timestamp": datetime.now().isoformat(),  # ⚠️ Horloge locale manipulable
            "level": "INFO",                           # ⚠️ Toujours INFO, même pour des erreurs
            "user_id": user_id,
            "action": action,
            "details": details
        }
        message = json.dumps(log_entry)
        self.logger.info(message)
```

> [!WARNING]
> **4 faiblesses critiques des logs d'audit :**
> 1. **Logs en texte brut** — Le fichier `audit.log` est un simple fichier texte. Un attaquant ayant accès au serveur peut **supprimer ou modifier** les entrées de log pour couvrir ses traces.
> 2. **Pas de chaînage cryptographique** — Sans HMAC ou chaîne de hachage, il est impossible de détecter une falsification des logs.
> 3. **Horloge locale uniquement** — Un attaquant qui modifie l'horloge système peut fausser les horodatages.
> 4. **Pas de rotation des logs** — Le fichier `audit.log` grandit indéfiniment, sans rotation ni archivage.
>
> **Impact : Non-conformité DNSSI** — La directive de sécurité marocaine exige des logs d'audit intègres et non répudiables.

**Solution : Logs chaînés avec HMAC**

```python
# audit_logger.py — VERSION SÉCURISÉE
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
    Logger d'audit sécurisé avec :
    - Chaînage HMAC (chaque entrée inclut le hash de la précédente)
    - Horodatage UTC (insensible aux changements d'horloge locale)
    - Rotation automatique des fichiers (max 10 Mo, 5 backups)
    - Niveaux de sévérité distincts
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
        key_path = Path(log_dir) / ".audit_hmac_key"
        if key_path.exists():
            with open(key_path, "rb") as f:
                return f.read()
        key = os.urandom(32)
        with open(key_path, "wb") as f:
            f.write(key)
        return key

    def log_action(self, user_id, action, details):
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
        entry_hmac = hmac.new(self._hmac_key, entry_str.encode(), hashlib.sha256).hexdigest()
        log_entry["hmac"] = entry_hmac
        self._last_hash = entry_hmac
        
        # Écrire le log
        message = json.dumps(log_entry, ensure_ascii=False)
        getattr(self.logger, level.lower(), self.logger.info)(message)
        
        # Console output
        print(f"[AUDIT] {user_id} | {action} | {details}")
```

---

## Axe 7 — Faiblesses du KMS (Key Management Service)

> ⭐ **NOUVEAU** — Cet axe n'était pas dans l'audit initial.

### Diagnostic `kms_manager.py`

```python
# kms_manager.py — Lignes 20-23 (SEL TROP COURT)
def _ensure_salt_exists(self):
    if not self.master_salt_path.exists():
        salt = os.urandom(16)  # ⚠️ 128 bits seulement
        with open(self.master_salt_path, "wb") as f:
            f.write(salt)
```

```python
# kms_manager.py — Lignes 30-37 (PBKDF2 INSUFFISANT)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,          # ⚠️ 100K itérations — OWASP recommande 600K minimum
    backend=default_backend()
)
```

> [!WARNING]
> **3 faiblesses dans le KMS :**
> 1. **Sel de 16 octets (128 bits)** — NIST SP 800-132 recommande au minimum 128 bits, mais **256 bits (32 octets)** est le standard actuel pour les applications haute sécurité.
> 2. **PBKDF2 avec 100 000 itérations** — OWASP 2025 recommande au minimum **600 000 itérations pour PBKDF2-SHA256**. Avec 100K, un GPU moderne peut tester ~5000 mots de passe/seconde.
> 3. **Pas de vérification d'intégrité** — Si le fichier `.salt` ou `.p12.enc` est corrompu, `decrypt_private_key()` lève une exception générique `ValueError("Clé incorrecte ou données corrompues")` sans distinguer corruption de mauvais mot de passe.
>
> **Le KMS protège les identités PAdES — c'est un composant critique.**

**Solution :**

```python
# kms_manager.py — VERSION RENFORCÉE (extraits)
PBKDF2_ITERATIONS = 600_000  # OWASP 2025 minimum
SALT_LENGTH = 32              # 256 bits (NIST SP 800-132)

def _ensure_salt_exists(self):
    if not self.master_salt_path.exists():
        salt = os.urandom(SALT_LENGTH)  # 256 bits
        with open(self.master_salt_path, "wb") as f:
            f.write(salt)

def _get_fernet(self, master_password: str) -> Fernet:
    with open(self.master_salt_path, "rb") as f:
        salt = f.read()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,  # 600K
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return Fernet(key)
```

> [!TIP]
> **Migration :** Lors du passage à 600K itérations, les identités existantes (chiffrées avec 100K) ne pourront plus être déchiffrées. Prévoyez un script de migration qui :
> 1. Déchiffre avec l'ancien paramètre (100K)
> 2. Re-chiffre avec le nouveau (600K)
> 3. Supprime l'ancien fichier

---

## Axe 8 — Vulnérabilités Transversales Critiques

> [!CAUTION]
> Les vulnérabilités suivantes sont des **quick wins** — corrections rapides à fort impact sécuritaire.

### 8.1 — Secret TOTP stocké en clair dans `users.json`

```python
# eid_manager.py — Ligne 65
users[username]["totp_secret"] = secret  # ⚠️ En clair dans le JSON !
```

**Risque :** Si `users.json` est compromis, l'attaquant peut générer des codes TOTP valides, rendant le 2FA inutile.  

**Solution :** Chiffrer le secret TOTP avec le KmsManager existant :

```python
# eid_manager.py — VERSION SÉCURISÉE
def setup_totp(self, username: str, kms: "KmsManager" = None, password: str = None) -> dict:
    # ...
    secret = pyotp.random_base32()
    
    # Chiffrer le secret avant stockage
    if kms and password:
        encrypted_secret = kms.encrypt_private_key(secret.encode(), password)
        users[username]["totp_secret_enc"] = encrypted_secret.decode("utf-8")
        # Supprimer la version en clair si elle existe
        users[username].pop("totp_secret", None)
    else:
        users[username]["totp_secret"] = secret  # Fallback (déconseillé)
    
    self._save_users(users)
    # ...
```

### 8.2 — Fichiers `cle_privee.pem` et `cle_publique.pem` à la racine

```
d:\work\anti-falsi\cle_privee.pem  ← 241 bytes, EXPOSÉ !
d:\work\anti-falsi\cle_publique.pem
```

**Risque :** Clé privée potentiellement versionnée dans Git (aucun `.gitignore` n'existe dans le projet).  

**Solution :**
1. Déplacer les fichiers dans `security_vault/`
2. Créer un `.gitignore` :

```gitignore
# .gitignore
*.pem
*.p12
*.enc
*.salt
.env
security_vault/
__pycache__/
*.pyc
build/
dist/
*.spec
.venv/
```

### 8.3 — `chmod 777` dans le Dockerfile

```dockerfile
# Dockerfile — Ligne 33
RUN mkdir -p security_vault/archive && chmod -R 777 security_vault  # ⚠️ World-writable !
```

**Risque :** Tous les utilisateurs du conteneur (y compris un potentiel attaquant exploitant une faille) ont accès en lecture/écriture/exécution au vault.  
**Solution :** `chmod 700` (voir Axe 9).

### 8.4 — Exceptions silencieuses multiples

```python
# app_unifiee.py — Lignes 469-470
except Exception as e:
    print(f"[OCR] Erreur non bloquante: {e}")  # ⚠️ Avalé silencieusement

# blockchain_engine.py — Lignes 38-40
except Exception as e:
    self._simulation_mode = True
    print(f"[BLOCKCHAIN] ⚠️  Mode simulation activé ({str(e)[:60]})")  # ⚠️ Truncated
```

> [!WARNING]
> 12+ endroits dans le code avalent silencieusement des exceptions (`except Exception: pass` ou `print()`). En production, ces erreurs doivent être **loguées dans le système d'audit** et non simplement imprimées sur stdout, car stdout est perdu dans un conteneur Docker si les logs ne sont pas capturés.

### 8.5 — `datetime.utcnow()` déprécié dans `pades_engine.py`

```python
# pades_engine.py — Lignes 62-64
).not_valid_before(
    datetime.datetime.utcnow()        # ⚠️ Déprécié depuis Python 3.12
).not_valid_after(
    datetime.datetime.utcnow() + ...  # ⚠️ Utilisez datetime.now(timezone.utc)
)
```

> [!NOTE]
> `datetime.utcnow()` est **déprécié** depuis Python 3.12 et supprimé dans les futures versions. Utilisez `datetime.now(timezone.utc)`.

### 8.6 — `get_current_code()` dans `eid_manager.py` — Méthode de debug en production

```python
# eid_manager.py — Lignes 134-147
def get_current_code(self, username: str) -> str:
    """
    [USAGE INTERNE / DEBUG UNIQUEMENT] Retourne le code TOTP actuel.
    Ne jamais afficher ce code à l'utilisateur en production.
    """
```

> [!WARNING]
> Cette méthode permet de **contourner le 2FA** en récupérant le code TOTP actuel. Même si elle n'est appelée nulle part dans le code, sa simple existence est un risque. Un attaquant ayant accès au REPL Python du processus pourrait l'appeler. **Supprimez-la ou protégez-la avec un décorateur `@debug_only`.**

---

## Axe 9 — Optimisation Dockerfile & Docker Compose

### 9.1 — Diagnostic Dockerfile

```dockerfile
FROM python:3.10-slim             # ~150 MB
RUN apt-get install -y tesseract-ocr tesseract-ocr-fra ...  # +300 MB
RUN pip install -r requirements.txt  # +800 MB (opencv, cryptography, pyHanko...)
COPY . .                          # ← Copie TOUT, y compris .pem, .git, __pycache__
RUN chmod -R 777 security_vault   # ⚠️ World-writable
```

**Problèmes :**
- **Taille estimée :** ~1.3 Go
- **Pas de `.dockerignore`** → les fichiers `.pem`, `.git/`, `.venv/`, `build/`, `dist/` sont copiés dans l'image
- **`build-essential` reste dans l'image finale** → +200 Mo inutiles en production
- **Pas d'utilisateur non-root** → le processus s'exécute en `root`
- **`--no-install-recommends` manquant** → paquets APT supplémentaires inutiles

### 9.2 — Diagnostic `docker-compose.yml`

```yaml
# docker-compose.yml — Lignes 16-22
api:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./security_vault:/app/security_vault  # ⚠️ Monte le vault local
    environment:
      - REDIS_URL=redis://redis:6379/0
      # ⚠️ Aucune variable pour : SEPOLIA_RPC_URL, JWT_SECRET_KEY, WALLET_PRIVATE_KEY
    depends_on:
      - redis  # ⚠️ Pas de healthcheck — le service peut démarrer avant Redis
```

> [!WARNING]
> **2 problèmes Docker Compose :**
> 1. **`depends_on` sans healthcheck** — Le service `api` peut démarrer avant que Redis ne soit prêt, provoquant des erreurs Celery au démarrage.
> 2. **Variables d'environnement sensibles manquantes** — Les secrets (JWT, clés blockchain, clés wallet) ne sont pas dans la configuration et devront être ajoutés en production.

### 9.3 — Solution : Multi-stage build optimisé

```dockerfile
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
```

### `.dockerignore` (à créer)

```
# .dockerignore
__pycache__/
*.pyc
*.pyo
.git/
.venv/
build/
dist/
*.spec
*.pem
*.p12
*.enc
.env
*.log
security_vault/
node_modules/
.pytest_cache/
```

### `docker-compose.yml` sécurisé

```yaml
services:
  redis:
    image: redis:7-alpine
    container_name: trust_gateway_redis
    ports:
      - "6379:6379"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5

  api:
    build: .
    container_name: trust_gateway_api
    ports:
      - "8000:8000"
    volumes:
      - vault_data:/app/security_vault
    env_file:
      - .env
    environment:
      - PYTHONUNBUFFERED=1
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      redis:
        condition: service_healthy
    restart: unless-stopped

  worker:
    build: .
    container_name: trust_gateway_worker
    command: celery -A api.celery_app.celery_app worker --loglevel=info --concurrency=2
    volumes:
      - vault_data:/app/security_vault
    env_file:
      - .env
    environment:
      - PYTHONUNBUFFERED=1
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      redis:
        condition: service_healthy
    restart: unless-stopped

volumes:
  vault_data:
    driver: local
```

### `requirements.txt` — Séparer les dépendances

```
# requirements-core.txt (API seulement)
fastapi>=0.115
uvicorn[standard]>=0.34
python-multipart
pydantic>=2.0
cryptography>=46.0
pyHanko>=0.34
pyhanko-certvalidator>=0.30
PyMuPDF>=1.27
pillow>=12.0
qrcode>=8.0
bcrypt>=4.2
python-dotenv>=1.0
PyJWT>=2.8

# requirements-worker.txt (Celery workers)
celery>=5.4
redis>=5.0

# requirements-ocr.txt (optionnel, peut être un service séparé)
opencv-python-headless>=4.13   # ← headless = -200MB vs opencv-python !
pytesseract>=0.3
pdfplumber>=0.11
```

> [!TIP]
> **Gain de taille estimé :**
> | Avant | Après |
> |-------|-------|
> | ~1.3 Go | ~650 Mo |
> 
> **Optimisations clés :**
> 1. Multi-stage build → pas de `build-essential` dans l'image finale (-200 Mo)
> 2. `opencv-python-headless` au lieu de `opencv-python` → **-200 Mo**
> 3. `.dockerignore` → exclure .git, .venv, build/, pem, etc.
> 4. Utilisateur non-root → sécurité renforcée
> 5. `--no-install-recommends` → paquets APT minimaux
> 6. Volumes nommés au lieu de bind mounts → meilleure portabilité

---

## Matrice de Risque & Plan d'Action

### Priorité P0 — 🔴 Corrections immédiates (avant mise en production)

| # | Axe | Action | Effort | Fichier(s) |
|:-:|:---:|--------|:------:|------------|
| 1 | Crypto | Remplacer SHA-256 par **bcrypt** dans `auth_manager.py` | 1h | `auth_manager.py` |
| 2 | Crypto | Supprimer le fallback `"default_pwd"` | 30min | `crypto_engine.py`, `pades_engine.py` |
| 3 | Sécurité | Déplacer `cle_privee.pem` + créer `.gitignore` | 10min | racine du projet |
| 4 | API | Restreindre CORS (supprimer `*`) | 15min | `api/main.py` |
| 5 | API | Ajouter authentification JWT | 2h | `api/auth_middleware.py` (nouveau), routers |

### Priorité P1 — 🟠 Corrections à planifier (sprint suivant)

| # | Axe | Action | Effort | Fichier(s) |
|:-:|:---:|--------|:------:|------------|
| 6 | Crypto | Scrypt KDF dans `crypto_engine.py` | 2h | `crypto_engine.py` |
| 7 | DLP | Patterns RIB/IBAN/CIN marocains + scoring | 3h | `dlp_engine.py`, `app_unifiee.py` |
| 8 | Blockchain | Vérification hybride + file d'attente | 4h | `blockchain_engine.py` |
| 9 | KMS | Augmenter PBKDF2 à 600K + sel 32 octets | 1h | `kms_manager.py` |
| 10 | Logs | Chaînage HMAC + rotation | 2h | `audit_logger.py` |

### Priorité P2 — 🟡 Améliorations (backlog)

| # | Axe | Action | Effort | Fichier(s) |
|:-:|:---:|--------|:------:|------------|
| 11 | UX | Lazy Loading + ThreadPoolExecutor | 3h | `app_unifiee.py` |
| 12 | Docker | Multi-stage + .dockerignore + non-root | 2h | `Dockerfile`, `.dockerignore` |
| 13 | API | Rate limiting avec `slowapi` | 1h | `api/main.py`, routers |
| 14 | Sécurité | Chiffrer le secret TOTP via KMS | 1h | `eid_manager.py` |

### Priorité P3 — 🟢 Nice-to-have

| # | Axe | Action | Effort | Fichier(s) |
|:-:|:---:|--------|:------:|------------|
| 15 | Docker | Séparer requirements (core/worker/ocr) | 30min | `requirements*.txt` |
| 16 | Docker | Docker Compose healthchecks + volumes nommés | 30min | `docker-compose.yml` |
| 17 | Code | Supprimer `get_current_code()` debug feature | 5min | `eid_manager.py` |
| 18 | Code | Remplacer `datetime.utcnow()` déprécié | 10min | `pades_engine.py` |
| 19 | API | Ajouter endpoint `/health` | 5min | `api/main.py` |

---

### Diagramme d'Architecture de Sécurité Cible

```
┌───────────────────────────────────────────────────────────────────────┐
│                    MAROC DIGITAL TRUST GATEWAY v2.1                   │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌──────────┐    ┌──────────────┐    ┌────────────────┐              │
│  │ Frontend │───▸│  API Gateway │───▸│  Auth (JWT)    │              │
│  │ (CTk/Web)│    │  (FastAPI)   │    │  + Rate Limit  │              │
│  └──────────┘    │  CORS strict │    │  + bcrypt hash │              │
│                  └──────┬───────┘    └────────────────┘              │
│                         │                                             │
│         ┌───────────────┼───────────────┐                            │
│         ▼               ▼               ▼                            │
│  ┌──────────┐   ┌──────────────┐  ┌──────────────┐                  │
│  │ CryptoEng│   │  DLP Engine  │  │  Blockchain  │                  │
│  │ (Scrypt) │   │  (Scoring)   │  │  (Hybride)   │                  │
│  │ AES-256  │   │  Luhn + RIB  │  │  Local+Chain │                  │
│  └──────────┘   └──────────────┘  └──────────────┘                  │
│         │                                                             │
│         ▼                                                             │
│  ┌──────────────────┐    ┌──────────────────┐                        │
│  │  KMS (Scrypt/    │    │  Audit Logger    │                        │
│  │  PBKDF2 600K)    │    │  (HMAC chaîné)   │                        │
│  └──────────────────┘    └──────────────────┘                        │
│                                                                       │
│  ┌──────────────────────────────────────────────────┐                │
│  │  Docker (non-root, multi-stage, healthcheck)     │                │
│  └──────────────────────────────────────────────────┘                │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

---

*Ce rapport est confidentiel. Toute reproduction ou diffusion à des parties non autorisées est interdite.*  
*Généré le 12 Avril 2026 — Révision v2.0*
