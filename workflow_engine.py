"""
workflow_engine.py — Parapheur Électronique / Workflow Multi-signatures
Maroc Digital Trust Gateway — Module Workflows Documentaires
"""
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Optional


class WorkflowEngine:
    """
    Gère les workflows de signature séquentielle (Parapheur Électronique).
    
    Un workflow est asocié à un document PDF. Il définit une liste ordonnée de
    signataires. Chaque signataire doit valider à son tour avant que le document
    passe au suivant.
    
    Structure du fichier de workflow JSON :
    {
        "doc_name": "contrat.pdf",
        "doc_path": "/abs/path/contrat.pdf",
        "created_by": "admin",
        "created_at": "2026-01-01 10:00:00",
        "status": "in_progress" | "completed" | "rejected",
        "signataires": [
            {
                "username": "directeur",
                "nom": "Directeur Général",
                "order": 1,
                "status": "pending" | "approved" | "rejected",
                "signed_at": null | "2026-01-01 11:00:00",
                "comment": ""
            },
            ...
        ]
    }
    """

    def __init__(self, vault_path: Path):
        self.vault_path = Path(vault_path)
        self.workflows_dir = self.vault_path / "workflows"
        self.workflows_dir.mkdir(parents=True, exist_ok=True)

    def _get_workflow_path(self, doc_path: str) -> Path:
        """Retourne le chemin du fichier JSON du workflow associé à un document."""
        doc_stem = Path(doc_path).stem
        return self.workflows_dir / f"{doc_stem}_workflow.json"

    def create_workflow(self, doc_path: str, signataires: List[dict], created_by: str) -> dict:
        """
        Crée un nouveau workflow de signatures pour un document.
        
        Args:
            doc_path:    Chemin absolu du PDF d'origine
            signataires: Liste ordonnée [{"username": "...", "nom": "..."}]
            created_by:  Username du créateur du flux
        
        Returns:
            Le workflow créé
        """
        doc_path = str(Path(doc_path).resolve())
        workflow = {
            "doc_name":   Path(doc_path).name,
            "doc_path":   doc_path,
            "created_by": created_by,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status":     "in_progress",
            "current_step": 0,
            "signataires": [
                {
                    "username":  s["username"],
                    "nom":       s.get("nom", s["username"]),
                    "order":     idx + 1,
                    "status":    "pending",
                    "signed_at": None,
                    "comment":   ""
                }
                for idx, s in enumerate(signataires)
            ]
        }

        wf_path = self._get_workflow_path(doc_path)
        with open(wf_path, "w", encoding="utf-8") as f:
            json.dump(workflow, f, indent=2, ensure_ascii=False)

        print(f"[WORKFLOW] ✅ Workflow créé : {workflow['doc_name']} → {[s['username'] for s in signataires]}")
        return workflow

    def get_workflow(self, doc_path: str) -> Optional[dict]:
        """Charge le workflow d'un document. Retourne None si aucun workflow."""
        wf_path = self._get_workflow_path(doc_path)
        if not wf_path.exists():
            return None
        with open(wf_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_workflow(self, workflow: dict):
        """Sauvegarde l'état du workflow."""
        wf_path = self._get_workflow_path(workflow["doc_path"])
        with open(wf_path, "w", encoding="utf-8") as f:
            json.dump(workflow, f, indent=2, ensure_ascii=False)

    def get_pending_for_user(self, username: str) -> List[dict]:
        """Retourne la liste des documents en attente de signature pour un utilisateur."""
        pending = []
        for wf_file in self.workflows_dir.glob("*_workflow.json"):
            with open(wf_file, "r", encoding="utf-8") as f:
                wf = json.load(f)
            if wf.get("status") != "in_progress":
                continue
            # Vérifier si c'est le tour de cet utilisateur
            current_step = wf.get("current_step", 0)
            signataires = wf.get("signataires", [])
            if current_step < len(signataires):
                current_sig = signataires[current_step]
                if current_sig["username"] == username and current_sig["status"] == "pending":
                    pending.append(wf)
        return pending

    def get_all_workflows(self) -> List[dict]:
        """Retourne tous les workflows."""
        workflows = []
        for wf_file in self.workflows_dir.glob("*_workflow.json"):
            with open(wf_file, "r", encoding="utf-8") as f:
                workflows.append(json.load(f))
        return workflows

    def approve_step(self, doc_path: str, username: str, comment: str = "") -> dict:
        """
        Approuve l'étape actuelle du workflow pour l'utilisateur donné.
        Passe au signataire suivant ou clôture le workflow si c'était le dernier.

        Returns:
            dict avec "success", "message", "workflow", "next_signer" | None
        """
        wf = self.get_workflow(doc_path)
        if not wf:
            return {"success": False, "message": "Aucun workflow trouvé pour ce document."}

        current_step = wf.get("current_step", 0)
        signataires = wf.get("signataires", [])

        if current_step >= len(signataires):
            return {"success": False, "message": "Ce workflow est déjà terminé."}

        current_sig = signataires[current_step]
        if current_sig["username"] != username:
            return {"success": False, "message": f"Ce n'est pas votre tour de signer. En attente de : {current_sig['username']}"}

        # Marquer l'étape comme approuvée
        signataires[current_step]["status"] = "approved"
        signataires[current_step]["signed_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        signataires[current_step]["comment"] = comment
        wf["signataires"] = signataires

        # Passer à l'étape suivante
        next_step = current_step + 1
        wf["current_step"] = next_step

        next_signer = None
        if next_step >= len(signataires):
            wf["status"] = "completed"
            wf["completed_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            message = "✅ Workflow complété ! Toutes les signatures ont été recueillies."
            print(f"[WORKFLOW] 🎉 Workflow '{wf['doc_name']}' complété.")
        else:
            next_signer = signataires[next_step]["username"]
            message = f"✅ Étape {current_step + 1} approuvée. En attente de : {next_signer}"
            print(f"[WORKFLOW] ➡️  '{wf['doc_name']}' → Step {next_step + 1} : {next_signer}")

        self._save_workflow(wf)
        return {"success": True, "message": message, "workflow": wf, "next_signer": next_signer}

    def reject_step(self, doc_path: str, username: str, reason: str = "") -> dict:
        """Rejette le workflow (annule tout le flux)."""
        wf = self.get_workflow(doc_path)
        if not wf:
            return {"success": False, "message": "Aucun workflow trouvé."}

        current_step = wf.get("current_step", 0)
        signataires = wf.get("signataires", [])

        if current_step < len(signataires):
            signataires[current_step]["status"] = "rejected"
            signataires[current_step]["signed_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            signataires[current_step]["comment"] = reason

        wf["signataires"] = signataires
        wf["status"] = "rejected"
        wf["rejected_by"] = username
        wf["rejected_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self._save_workflow(wf)
        print(f"[WORKFLOW] ❌ Workflow '{wf['doc_name']}' rejeté par {username}.")
        return {"success": True, "message": f"Workflow rejeté par {username}. Motif : {reason}"}

    def get_status_summary(self, workflow: dict) -> str:
        """Retourne un résumé lisible de l'état du workflow."""
        lines = [f"Document : {workflow['doc_name']}", f"Statut : {workflow['status'].upper()}", ""]
        for s in workflow.get("signataires", []):
            icons = {"pending": "⏳", "approved": "✅", "rejected": "❌"}
            icon = icons.get(s["status"], "?")
            date_txt = f" ({s['signed_at']})" if s["signed_at"] else ""
            lines.append(f"  {icon} Étape {s['order']} : {s['nom']}{date_txt}")
        return "\n".join(lines)
