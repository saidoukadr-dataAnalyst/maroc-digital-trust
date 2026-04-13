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
        self.pending_file = self.vault_path / "blockchain_pending.json"
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

        doc_hash_bytes = bytes.fromhex(doc_hash) if len(doc_hash) == 64 else \
                         hashlib.sha256(doc_hash.encode()).digest()

        nonce = self._web3.eth.get_transaction_count(self._account.address)
        tx = self._contract.functions.anchor(doc_hash_bytes).build_transaction({
            "from": self._account.address,
            "nonce": nonce,
            "gas": 100_000,
            "gasPrice": self._web3.eth.gas_price,
            "chainId": 11155111,  # Sepolia chain ID
        })

        signed_tx = self._web3.eth.account.sign_transaction(tx, self._wallet_key)
        tx_hash = self._web3.eth.send_raw_transaction(signed_tx.raw_transaction)

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
        """Génère un faux tx_hash clairement identifiable comme simulé."""
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
