import json
import bcrypt
from pathlib import Path


class AuthManager:
    """
    Gestionnaire d'authentification sécurisé.
    Utilise bcrypt (12 rounds, salt intégré) pour le hachage des mots de passe.
    """

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
        """Initialise un utilisateur par défaut admin avec un mot de passe sécurisé."""
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
        else:
            # Migration : ajouter le rôle "admin" à l'ancien compte s'il n'existe pas
            with open(self.users_file, "r") as f:
                users = json.load(f)
            updated = False
            for username, u in users.items():
                if "role" not in u:
                    u["role"] = "admin" if username == "admin" or u.get("id_responsable") == "RESP-001" else "user"
                    updated = True
                # Migration bcrypt : détecter les anciens hash SHA-256 (64 hex chars)
                if len(u.get("pwd_hash", "")) == 64 and all(c in "0123456789abcdef" for c in u["pwd_hash"]):
                    print(f"[AUTH] ⚠️ Hash SHA-256 legacy détecté pour '{username}' — Le mot de passe devra être réinitialisé.")
                    # On ne peut pas migrer un hash SHA-256 vers bcrypt sans le mot de passe en clair
                    # L'utilisateur devra se re-connecter et changer son mot de passe
            if updated:
                with open(self.users_file, "w") as f:
                    json.dump(users, f)

    def login(self, username, password):
        """Valide les identifiants et démarre une session."""
        if not self.users_file.exists():
            return False

        with open(self.users_file, "r") as f:
            users = json.load(f)

        if username in users:
            stored_hash = users[username]["pwd_hash"]

            # Support legacy SHA-256 (migration transparente)
            if len(stored_hash) == 64 and all(c in "0123456789abcdef" for c in stored_hash):
                import hashlib
                if hashlib.sha256(password.encode()).hexdigest() == stored_hash:
                    # Migration automatique vers bcrypt au login
                    users[username]["pwd_hash"] = self._hash_password(password)
                    with open(self.users_file, "w") as f:
                        json.dump(users, f)
                    print(f"[AUTH] ✅ Hash migré de SHA-256 vers bcrypt pour '{username}'")
                    self.current_user = users[username]
                    self.current_user["username"] = username
                    return True
                return False

            # Vérification bcrypt standard
            if self._verify_password(password, stored_hash):
                self.current_user = users[username]
                self.current_user["username"] = username
                return True
        return False

    def logout(self):
        self.current_user = None

    def change_password(self, username, new_password):
        """Mise à jour du mot de passe (bcrypt)."""
        with open(self.users_file, "r") as f:
            users = json.load(f)

        if username in users:
            users[username]["pwd_hash"] = self._hash_password(new_password)
            with open(self.users_file, "w") as f:
                json.dump(users, f)
            return True
        return False

    # --- MÉTHODES D'ADMINISTRATION ---
    def get_all_users(self):
        """Retourne la liste des utilisateurs (sans les mots de passe)."""
        with open(self.users_file, "r") as f:
            users = json.load(f)
        return {k: {key: val for key, val in v.items() if key != "pwd_hash"} for k, v in users.items()}

    def add_user(self, username, password, nom, id_responsable, role="user"):
        """Ajoute un nouvel utilisateur (bcrypt)."""
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

    def delete_user(self, username):
        """Supprime un utilisateur."""
        with open(self.users_file, "r") as f:
            users = json.load(f)

        if username in users:
            if users[username].get("role") == "admin" and len([u for u in users.values() if u.get("role") == "admin"]) <= 1:
                return False, "Impossible de supprimer le dernier administrateur."

            del users[username]
            with open(self.users_file, "w") as f:
                json.dump(users, f)
            return True, "Utilisateur supprimé."
        return False, "Utilisateur introuvable."
