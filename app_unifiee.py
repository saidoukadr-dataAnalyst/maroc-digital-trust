import customtkinter as ctk
import hashlib
import sys
import os
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
import io

def resource_path(relative_path):
    """ Gère les chemins pour PyInstaller (Bundle vs Local) """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return Path(base_path) / relative_path

try:
    from auth_manager import AuthManager
    from crypto_engine import CryptoEngine
    from pdf_processor import PDFProcessor
    from audit_logger import AuditLogger
    from pades_engine import PadesEngine
    # ── Nouveaux Modules ──
    from blockchain_engine import BlockchainEngine
    from ocr_engine import OCREngine
    from dlp_engine import DLPEngine
    from stamp_engine import StampEngine
    from workflow_engine import WorkflowEngine
    from eid_manager import EIDManager
except ImportError as e:
    import tkinter as tk
    from tkinter import messagebox
    root = tk.Tk(); root.withdraw()
    messagebox.showerror("Erreur de Chargement", f"Module manquant : {str(e)}")
    sys.exit(1)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class ModernTrustApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Maroc Digital Trust Gateway — Entreprise Edition v2.0")
        self.geometry("1200x750")

        if getattr(sys, 'frozen', False):
            self.exe_dir = Path(sys.executable).parent
        else:
            self.exe_dir = Path(__file__).parent

        self.vault_path   = self.exe_dir / "security_vault"
        self.archive_path = self.vault_path / "archive"
        self.vault_path.mkdir(exist_ok=True)
        self.archive_path.mkdir(exist_ok=True)

        # ── Modules de base ──
        self.auth       = AuthManager(self.vault_path / "users.json")
        self.crypto     = CryptoEngine(self.vault_path, self.archive_path)
        self.audit      = AuditLogger(self.vault_path)
        self.pdf_engine = PDFProcessor()

        # ── Nouveaux Modules ──
        self.blockchain = BlockchainEngine(self.vault_path)
        self.ocr        = OCREngine()
        self.dlp        = DLPEngine()
        self.stamp      = StampEngine()
        self.workflow   = WorkflowEngine(self.vault_path)
        self.eid        = None   # initialisé après login (besoin du users_file)

        self.pades = None
        self.current_verif_path = None
        self.show_login_screen()

    # ─────────────────────────────────────────────
    # UTILITAIRES
    # ─────────────────────────────────────────────
    def _clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

    def _clear_main(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    # ─────────────────────────────────────────────
    # ÉCRAN DE CONNEXION
    # ─────────────────────────────────────────────
    def show_login_screen(self):
        self._clear_window()
        login_frame = ctk.CTkFrame(self, width=420, height=520, corner_radius=20)
        login_frame.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(login_frame, text="🛡️ TRUST GATEWAY",
                     font=ctk.CTkFont(size=26, weight="bold")).pack(pady=(40, 5))
        ctk.CTkLabel(login_frame, text="Maroc Digital Trust Gateway v2.0",
                     font=ctk.CTkFont(size=12), text_color="gray").pack(pady=(0, 25))

        self.entry_user = ctk.CTkEntry(login_frame, placeholder_text="Utilisateur", width=300, height=45)
        self.entry_user.pack(pady=8)
        self.entry_pwd  = ctk.CTkEntry(login_frame, placeholder_text="Mot de passe", show="*", width=300, height=45)
        self.entry_pwd.pack(pady=8)

        ctk.CTkButton(login_frame, text="Accéder au Système",
                      command=self.action_login, width=240, height=50).pack(pady=35)

        self.entry_pwd.bind("<Return>", lambda e: self.action_login())

    def action_login(self):
        try:
            user = self.entry_user.get()
            pwd  = self.entry_pwd.get()
            if self.auth.login(user, pwd):
                # Initialiser les modules dépendants de l'utilisateur
                self.eid = EIDManager(self.vault_path / "users.json")
                p12_file = self.vault_path / f"cert_{user}.p12"
                self.pades = PadesEngine(p12_file, pwd)
                self.pades.ensure_p12_exists(self.auth.current_user['nom'])
                if self.crypto.load_keys(pwd):
                    self.audit.log_action(user, "LOGIN", "Succès - Clés chargées")
                    self.setup_main_ui()
                else:
                    res = messagebox.askyesno("Initialisation", "Aucune identité trouvée. En créer une ?")
                    if res:
                        self.crypto.generate_new_identity(pwd)
                        self.audit.log_action(user, "KEY_GEN", "Nouvelle identité créée")
                        self.setup_main_ui()
            else:
                messagebox.showerror("Erreur", "Identifiants invalides")
        except Exception as e:
            import traceback
            messagebox.showerror("Erreur Fatale", f"Détails : {str(e)}\n\nTraceback:\n{traceback.format_exc()}")

    # ─────────────────────────────────────────────
    # INTERFACE PRINCIPALE
    # ─────────────────────────────────────────────
    def setup_main_ui(self):
        self._clear_window()
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ── Sidebar ──
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        ctk.CTkLabel(self.sidebar, text="🛡️ MAROC TRUST",
                     font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(25, 5))
        ctk.CTkLabel(self.sidebar, text="Entreprise Edition v2.0",
                     font=ctk.CTkFont(size=10), text_color="gray").pack(pady=(0, 20))

        # Navigation principale
        nav_items = [
            ("📝  Certification",       self.show_sign_tab,       "#1e6fbf"),
            ("🔍  Vérification",        self.show_verif_tab,      "#1e6fbf"),
            ("📋  Parapheur",           self.show_workflow_tab,   "#1e6fbf"),
            ("⛓️  Blockchain",          self.show_blockchain_tab, "#16a085"),
        ]
        for text, cmd, color in nav_items:
            ctk.CTkButton(self.sidebar, text=text, command=cmd,
                          height=40, fg_color=color).pack(pady=5, padx=20, fill="x")

        if self.auth.current_user.get("role") == "admin":
            ctk.CTkButton(self.sidebar, text="👥  Gestion Accès",
                          command=self.show_admin_tab,
                          height=40, fg_color="#8e44ad").pack(pady=5, padx=20, fill="x")

        # Gouvernance
        ctk.CTkLabel(self.sidebar, text="SÉCURITÉ & GOUVERNANCE",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="gray").pack(pady=(20, 5))

        gov_items = [
            ("🔐  Activer 2FA",         self.action_setup_2fa,    "#2c3e50"),
            ("🔄  Rotation Identité",   self.action_rotate_keys,  "#d35400"),
            ("🔑  Changer Password",    self.action_change_pwd,   "#2c3e50"),
        ]
        for text, cmd, color in gov_items:
            ctk.CTkButton(self.sidebar, text=text, command=cmd,
                          height=36, fg_color=color).pack(pady=4, padx=20, fill="x")

        # Info utilisateur
        user_info = f"👤 {self.auth.current_user['nom']}\nID: {self.auth.current_user['id_responsable']}"
        ctk.CTkLabel(self.sidebar, text=user_info,
                     font=ctk.CTkFont(size=11)).pack(side="bottom", pady=10)
        ctk.CTkButton(self.sidebar, text="🚪  Déconnexion",
                      fg_color="#c0392b",
                      command=self.show_login_screen).pack(side="bottom", pady=5, padx=20, fill="x")

        # Main View
        self.main_frame = ctk.CTkFrame(self, corner_radius=15, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")

        self.show_sign_tab()

    # ─────────────────────────────────────────────
    # ONGLET : CERTIFICATION (avec DLP + OCR + Tampon)
    # ─────────────────────────────────────────────
    def show_sign_tab(self):
        self._clear_main()
        container = ctk.CTkFrame(self.main_frame)
        container.pack(expand=True, fill="both", padx=40, pady=30)

        ctk.CTkLabel(container, text="Double Certification PDF",
                     font=ctk.CTkFont(size=26, weight="bold")).pack(pady=15)

        info_box = ctk.CTkFrame(container, fg_color="#1a1a1a", border_width=1)
        info_box.pack(pady=8, padx=40, fill="x")
        ctk.CTkLabel(info_box, text="Protocole : PAdES (ISO) + QR Souverain + Tampon Visuel",
                     font=ctk.CTkFont(size=13, weight="bold"), text_color="#27ae60").pack(pady=8)
        ctk.CTkLabel(info_box, text=f"Signataire : {self.auth.current_user['nom']}",
                     font=ctk.CTkFont(size=13)).pack(pady=3)
        ctk.CTkLabel(info_box, text=f"Identifiant : {self.auth.current_user['id_responsable']}",
                     font=ctk.CTkFont(size=13), text_color="#3498db").pack(pady=(3, 10))

        # Options
        opts_frame = ctk.CTkFrame(container, fg_color="transparent")
        opts_frame.pack(pady=10)

        self.opt_ocr = ctk.CTkCheckBox(opts_frame, text="Activer OCR (extraction champs clés)")
        self.opt_ocr.pack(side="left", padx=15)
        self.opt_ocr.select()

        self.opt_dlp = ctk.CTkCheckBox(opts_frame, text="Activer DLP (scan données sensibles)")
        self.opt_dlp.pack(side="left", padx=15)
        self.opt_dlp.select()

        self.opt_blockchain = ctk.CTkCheckBox(opts_frame, text="Ancrer sur Blockchain")
        self.opt_blockchain.pack(side="left", padx=15)

        ctk.CTkButton(container, text="  CERTIFIER & SCELLER",
                      height=60, font=ctk.CTkFont(size=16, weight="bold"),
                      command=self.action_signer).pack(pady=30)

    # ─────────────────────────────────────────────
    # ONGLET : VÉRIFICATION
    # ─────────────────────────────────────────────
    def show_verif_tab(self):
        self._clear_main()
        container = ctk.CTkFrame(self.main_frame)
        container.pack(expand=True, fill="both", padx=40, pady=30)

        ctk.CTkLabel(container, text="Validation d'Intégrité",
                     font=ctk.CTkFont(size=26, weight="bold")).pack(pady=25)

        self.lbl_file = ctk.CTkLabel(container, text="Déposez ou sélectionnez un fichier",
                                      text_color="gray")
        self.lbl_file.pack(pady=8)

        ctk.CTkButton(container, text="Sélectionner le PDF",
                      command=self.select_verif_file).pack(pady=8)

        # Option blockchain
        self.opt_verif_blockchain = ctk.CTkCheckBox(container, text="Vérifier également sur Blockchain")
        self.opt_verif_blockchain.pack(pady=10)

        ctk.CTkButton(container, text="  VÉRIFIER L'AUTHENTICITÉ",
                      fg_color="#27ae60", height=60,
                      font=ctk.CTkFont(size=16, weight="bold"),
                      command=self.action_verifier).pack(pady=30)

    # ─────────────────────────────────────────────
    # ONGLET : PARAPHEUR (Workflow Multi-signatures)
    # ─────────────────────────────────────────────
    def show_workflow_tab(self):
        self._clear_main()
        container = ctk.CTkFrame(self.main_frame)
        container.pack(expand=True, fill="both", padx=20, pady=20)

        ctk.CTkLabel(container, text="📋 Parapheur Électronique",
                     font=ctk.CTkFont(size=24, weight="bold")).pack(pady=10)

        # Bouton créer nouveau flux
        top_bar = ctk.CTkFrame(container, fg_color="transparent")
        top_bar.pack(fill="x", padx=20, pady=5)
        ctk.CTkButton(top_bar, text="➕ Créer un nouveau flux de signatures",
                      command=self.action_create_workflow,
                      fg_color="#27ae60", height=38).pack(side="left")

        # Section "En attente de ma signature"
        username = self.auth.current_user["username"]
        pending = self.workflow.get_pending_for_user(username)

        ctk.CTkLabel(container, text=f"En attente de votre signature ({len(pending)})",
                     font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", padx=20, pady=(15, 5))

        pending_frame = ctk.CTkScrollableFrame(container, height=150)
        pending_frame.pack(fill="x", padx=20)

        if not pending:
            ctk.CTkLabel(pending_frame, text="✅ Aucun document en attente",
                         text_color="gray").pack(pady=10)
        else:
            for wf in pending:
                row = ctk.CTkFrame(pending_frame, fg_color="#2a2a2a")
                row.pack(fill="x", pady=4, padx=5)
                ctk.CTkLabel(row, text=f"📄 {wf['doc_name']} — Créé par : {wf['created_by']}",
                             font=ctk.CTkFont(size=13)).pack(side="left", padx=10, pady=8)
                ctk.CTkButton(row, text="✅ Approuver",
                              fg_color="#27ae60", width=110,
                              command=lambda w=wf: self.action_approve_workflow(w)).pack(side="right", padx=5, pady=5)
                ctk.CTkButton(row, text="❌ Rejeter",
                              fg_color="#c0392b", width=90,
                              command=lambda w=wf: self.action_reject_workflow(w)).pack(side="right", padx=2, pady=5)

        # Tous les workflows
        ctk.CTkLabel(container, text="Tous les workflows",
                     font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", padx=20, pady=(15, 5))

        all_frame = ctk.CTkScrollableFrame(container)
        all_frame.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        all_wfs = self.workflow.get_all_workflows()
        if not all_wfs:
            ctk.CTkLabel(all_frame, text="Aucun workflow créé.", text_color="gray").pack(pady=10)
        else:
            status_colors = {"in_progress": "#e67e22", "completed": "#27ae60", "rejected": "#c0392b"}
            for wf in all_wfs:
                row = ctk.CTkFrame(all_frame, fg_color="#1e1e1e")
                row.pack(fill="x", pady=3, padx=5)
                color = status_colors.get(wf.get("status", ""), "gray")
                ctk.CTkLabel(row, text=f"📄 {wf['doc_name']}",
                             font=ctk.CTkFont(size=12, weight="bold")).pack(side="left", padx=10, pady=6)
                ctk.CTkLabel(row, text=wf.get("status", "?").upper(),
                             font=ctk.CTkFont(size=11), text_color=color).pack(side="left", padx=5)
                sigs = " → ".join(s["username"] for s in wf.get("signataires", []))
                ctk.CTkLabel(row, text=f"({sigs})",
                             font=ctk.CTkFont(size=11), text_color="gray").pack(side="left", padx=5)
                ctk.CTkButton(row, text="Détails", width=70,
                              command=lambda w=wf: messagebox.showinfo(
                                  "Statut Workflow", self.workflow.get_status_summary(w)
                              )).pack(side="right", padx=10, pady=4)

    # ─────────────────────────────────────────────
    # ONGLET : BLOCKCHAIN
    # ─────────────────────────────────────────────
    def show_blockchain_tab(self):
        self._clear_main()
        container = ctk.CTkFrame(self.main_frame)
        container.pack(expand=True, fill="both", padx=40, pady=30)

        mode_txt = "🟢 Connecté (Sepolia Testnet)" if not self.blockchain.is_simulation_mode else "🟡 Mode Simulation (Hors Ligne)"
        mode_color = "#27ae60" if not self.blockchain.is_simulation_mode else "#e67e22"

        ctk.CTkLabel(container, text="⛓️ Ancrage Blockchain",
                     font=ctk.CTkFont(size=26, weight="bold")).pack(pady=15)
        ctk.CTkLabel(container, text=mode_txt,
                     font=ctk.CTkFont(size=13), text_color=mode_color).pack(pady=5)

        ctk.CTkLabel(container, text="Ancrez le hash d'un PDF sur la blockchain pour une preuve permanente et décentralisée.",
                     font=ctk.CTkFont(size=12), text_color="gray", wraplength=600).pack(pady=10)

        btn_frame = ctk.CTkFrame(container, fg_color="transparent")
        btn_frame.pack(pady=20)

        ctk.CTkButton(btn_frame, text="⛓️  Ancrer un PDF",
                      command=self.action_anchor_blockchain,
                      height=50, fg_color="#16a085", width=200).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="🔎  Vérifier un Ancrage",
                      command=self.action_verify_blockchain,
                      height=50, fg_color="#2c3e50", width=200).pack(side="left", padx=10)

        # Registre des ancrages
        ctk.CTkLabel(container, text="Registre des Ancrages",
                     font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", pady=(20, 5))

        ledger_frame = ctk.CTkScrollableFrame(container)
        ledger_frame.pack(fill="both", expand=True)

        anchors = self.blockchain.get_all_anchors()
        if not anchors:
            ctk.CTkLabel(ledger_frame, text="Aucun document ancré pour l'instant.",
                         text_color="gray").pack(pady=15)
        else:
            for doc_hash, record in list(anchors.items())[:30]:
                row = ctk.CTkFrame(ledger_frame, fg_color="#1a1a1a")
                row.pack(fill="x", pady=3, padx=5)
                ctk.CTkLabel(row, text=f"🗂️ {record.get('doc_name','?')}",
                             font=ctk.CTkFont(size=12, weight="bold")).pack(side="left", padx=10, pady=6)
                ctk.CTkLabel(row, text=f"{record.get('timestamp','')}",
                             font=ctk.CTkFont(size=11), text_color="gray").pack(side="left", padx=5)
                tx = record.get("tx_hash", "?")
                ctk.CTkLabel(row, text=f"TX: {tx[:22]}...",
                             font=ctk.CTkFont(size=11), text_color="#3498db").pack(side="right", padx=10)

    # ─────────────────────────────────────────────
    # ONGLET : ADMIN
    # ─────────────────────────────────────────────
    def show_admin_tab(self):
        self._clear_main()
        container = ctk.CTkFrame(self.main_frame)
        container.pack(expand=True, fill="both", padx=30, pady=30)

        ctk.CTkLabel(container, text="Gestion des Accès",
                     font=ctk.CTkFont(size=26, weight="bold")).pack(pady=10)

        form_frame = ctk.CTkFrame(container, fg_color="#2c3e50")
        form_frame.pack(fill="x", pady=10, padx=20)

        col1 = ctk.CTkFrame(form_frame, fg_color="transparent")
        col1.pack(side="left", padx=20, pady=10)
        col2 = ctk.CTkFrame(form_frame, fg_color="transparent")
        col2.pack(side="left", padx=20, pady=10)

        self.add_user_entry = ctk.CTkEntry(col1, placeholder_text="Nom d'utilisateur")
        self.add_user_entry.pack(pady=5)
        self.add_pwd_entry  = ctk.CTkEntry(col1, placeholder_text="Mot de passe", show="*")
        self.add_pwd_entry.pack(pady=5)

        self.add_nom_entry = ctk.CTkEntry(col2, placeholder_text="Nom complet")
        self.add_nom_entry.pack(pady=5)
        self.add_id_entry  = ctk.CTkEntry(col2, placeholder_text="ID Responsable (ex: RESP-002)")
        self.add_id_entry.pack(pady=5)

        self.add_role_var = ctk.StringVar(value="user")
        ctk.CTkRadioButton(col2, text="Admin", variable=self.add_role_var, value="admin").pack(side="left", padx=5)
        ctk.CTkRadioButton(col2, text="User",  variable=self.add_role_var, value="user").pack(side="left",  padx=5)

        ctk.CTkButton(form_frame, text="Ajouter Utilisateur",
                      fg_color="#27ae60",
                      command=self.action_add_user).pack(side="right", padx=20, pady=10)

        list_frame = ctk.CTkScrollableFrame(container)
        list_frame.pack(expand=True, fill="both", pady=10, padx=20)

        users = self.auth.get_all_users()
        for u_name, u_info in users.items():
            row = ctk.CTkFrame(list_frame)
            row.pack(fill="x", pady=5, padx=5)
            totp_icon = "🔐" if self.eid and self.eid.has_totp(u_name) else "🔓"
            info_txt  = f"{totp_icon} {u_info.get('nom','?')} ({u_name}) — Rôle: {u_info.get('role','user')} — ID: {u_info.get('id_responsable','?')}"
            ctk.CTkLabel(row, text=info_txt).pack(side="left", padx=10, pady=5)
            ctk.CTkButton(row, text="Supprimer", fg_color="#c0392b", width=90,
                          command=lambda n=u_name: self.action_delete_user(n)).pack(side="right", padx=10, pady=5)

    # ─────────────────────────────────────────────
    # ACTIONS MÉTIERS — CERTIFICATION
    # ─────────────────────────────────────────────
    def action_signer(self):
        path = filedialog.askopenfilename(filetypes=[("PDF", "*.pdf")])
        if not path:
            return

        try:
            # ── Étape 0 : Vérification 2FA si activé ──
            username = self.auth.current_user["username"]
            if self.eid and self.eid.has_totp(username):
                code = simpledialog.askstring("🔐 Authentification 2FA",
                                              "Entrez le code à 6 chiffres de votre application (Google Authenticator) :",
                                              show="")
                if not code or not self.eid.verify_totp(username, code.strip()):
                    messagebox.showerror("2FA Échoué", "Code TOTP invalide. Signature annulée.")
                    self.audit.log_action(username, "2FA_FAIL", f"File: {Path(path).name}")
                    return

            # ── Étape 1 : OCR (si activé) ──
            ocr_fields_str = ""
            if self.opt_ocr.get():
                try:
                    ocr_result = self.ocr.get_summary(path)
                    fields     = ocr_result.get("fields", {})
                    if fields:
                        fields_preview = "\n".join(f"  • {k}: {', '.join(str(v) for v in vals[:2])}"
                                                   for k, vals in fields.items())
                        messagebox.showinfo("🔍 OCR — Champs Détectés",
                                            f"Champs extraits du document :\n\n{fields_preview}\n\nCes données seront intégrées dans le QR Code.")
                        ocr_fields_str = self.ocr.fields_to_qr_string(fields)
                except Exception as e:
                    print(f"[OCR] Erreur non bloquante: {e}")

            # ── Étape 2 : DLP (si activé) ──
            if self.opt_dlp.get():
                try:
                    doc_text = self.ocr.extract_text(path)
                    alerts   = self.dlp.scan_document(doc_text, Path(path).name)
                    if alerts:
                        report = self.dlp.format_report(alerts)
                        if self.dlp.is_blocked(alerts):
                            proceed = messagebox.askyesno(
                                "🚨 ALERTE DLP — DONNÉES CRITIQUES DÉTECTÉES",
                                f"{report}\n\n⚠️ Des données CRITIQUES ont été détectées.\n"
                                "Voulez-vous tout de même procéder à la certification (Admin bypass) ?"
                            )
                            if not proceed:
                                self.audit.log_action(username, "DLP_BLOCK", f"File: {Path(path).name}")
                                return
                            self.audit.log_action(username, "DLP_BYPASS", f"File: {Path(path).name}")
                        else:
                            messagebox.showwarning("⚠️ DLP — Avertissement", report)
                except Exception as e:
                    print(f"[DLP] Erreur non bloquante: {e}")

            # ── Étape 3 : Hachage ──
            doc_hash = self.pdf_engine.calculate_hash(path)

            # ── Étape 4 : Signature ECDSA ──
            signature = self.crypto.sign_data(doc_hash)
            info_qr   = (f"ID:{self.auth.current_user['id_responsable']}"
                         f"|HASH:{doc_hash}"
                         f"|SIG:{signature.hex()}")
            if ocr_fields_str:
                info_qr += f"|{ocr_fields_str}"

            # ── Étape 5 : Génération du Tampon Visuel ──
            from datetime import datetime
            date_str = datetime.now().strftime("%d/%m/%Y %H:%M")
            stamp_color = "#8e44ad" if self.auth.current_user.get("role") == "admin" else "#1a3a6e"
            stamp_bytes = self.stamp.generate_stamp(
                qr_data       = info_qr,
                signataire_nom= self.auth.current_user["nom"],
                date_str      = date_str,
                color_hex     = stamp_color
            )

            # ── Étape 6 : Insertion du Tampon dans le PDF (couche QR) ──
            temp_path   = Path(path).parent / f"temp_{Path(path).stem}_stamp.pdf"
            self.pdf_engine.sign_pdf(path, stamp_bytes, temp_path)

            # ── Étape 7 : Couche PAdES ──
            output_path = Path(path).parent / f"{Path(path).stem}_certifie.pdf"
            self.pades.sign_pdf_pades(temp_path, output_path)
            if temp_path.exists():
                temp_path.unlink()

            # ── Étape 8 : Blockchain (si activé) ──
            blockchain_info = ""
            if self.opt_blockchain.get():
                try:
                    anchor = self.blockchain.anchor_hash(doc_hash, Path(path).name)
                    blockchain_info = f"\n\n⛓️ Ancré sur Blockchain\nTX Hash : {anchor['tx_hash'][:30]}..."
                    self.audit.log_action(username, "BLOCKCHAIN_ANCHOR", f"TX: {anchor['tx_hash'][:20]}")
                except Exception as e:
                    blockchain_info = f"\n\n⚠️ Blockchain échoué: {str(e)[:60]}"

            self.audit.log_action(username, "DOUBLE_SIGN", f"File: {Path(path).name}")
            messagebox.showinfo("SUCCÈS 🛡️",
                                f"Document certifié avec succès !\n\n"
                                f"1. ✅ Couche PAdES (Adobe Ready)\n"
                                f"2. ✅ Tampon Visuel Officiel + QR Souverain\n"
                                f"3. ✅ Scan OCR & DLP{blockchain_info}\n\n"
                                f"Fichier : {output_path.name}")

        except Exception as e:
            messagebox.showerror("Erreur de Certification", str(e))

    # ─────────────────────────────────────────────
    # ACTIONS MÉTIERS — VÉRIFICATION
    # ─────────────────────────────────────────────
    def select_verif_file(self):
        f = filedialog.askopenfilename(filetypes=[("PDF", "*.pdf")])
        if f:
            self.current_verif_path = f
            self.lbl_file.configure(text=Path(f).name, text_color="#3498db")

    def action_verifier(self):
        if not self.current_verif_path:
            messagebox.showwarning("Attention", "Veuillez d'abord sélectionner un PDF.")
            return
        try:
            username = self.auth.current_user["username"]
            data = self.pdf_engine.extract_qr_data(self.current_verif_path)
            self.crypto.verify_signature(data["SIG"], data["HASH"])

            # Vérification Blockchain optionnelle
            blockchain_txt = ""
            if self.opt_verif_blockchain.get():
                result = self.blockchain.verify_anchor(data["HASH"])
                if result["found"]:
                    rec = result["record"]
                    blockchain_txt = (f"\n\n⛓️ Hash vérifié sur Blockchain\n"
                                      f"Ancré le : {rec['timestamp']}\n"
                                      f"TX : {rec['tx_hash'][:28]}...")
                else:
                    blockchain_txt = "\n\n⚠️ Hash NON trouvé dans le registre blockchain."

            self.audit.log_action(username, "VERIFY_SUCCESS", f"File: {Path(self.current_verif_path).name}")
            messagebox.showinfo("AUTHENTIQUE ✅",
                                f"Document validé par le système !\n\n"
                                f"Signataire ID : {data.get('ID', '?')}\n"
                                f"Empreinte : {data['HASH'][:24]}...{blockchain_txt}\n\n"
                                f"Note : La signature PAdES peut aussi être vérifiée dans Adobe Acrobat.")
        except Exception as e:
            username = self.auth.current_user["username"]
            self.audit.log_action(username, "VERIFY_FAIL",
                                  f"File: {Path(self.current_verif_path).name} | Error: {str(e)}")
            messagebox.showerror("ALERTE ❌",
                                 f"Document corrompu ou signature invalide !\n\n{str(e)}")

    # ─────────────────────────────────────────────
    # ACTIONS MÉTIERS — WORKFLOW
    # ─────────────────────────────────────────────
    def action_create_workflow(self):
        path = filedialog.askopenfilename(filetypes=[("PDF", "*.pdf")])
        if not path:
            return

        all_users = self.auth.get_all_users()
        user_list = [f"{info.get('nom','?')} ({uname})"
                     for uname, info in all_users.items()
                     if uname != self.auth.current_user["username"]]

        if not user_list:
            messagebox.showwarning("Attention", "Aucun autre utilisateur disponible comme signataire.")
            return

        signataires_str = simpledialog.askstring(
            "Créer un Workflow",
            f"Entrez les usernames des signataires séquentiels (séparés par des virgules) :\n"
            f"Utilisateurs : {', '.join([u.split('(')[1].rstrip(')') for u in user_list])}"
        )
        if not signataires_str:
            return

        signataires = [{"username": u.strip()} for u in signataires_str.split(",") if u.strip()]
        if not signataires:
            return

        # Résoudre les noms
        all_users_raw = all_users
        for s in signataires:
            info = all_users_raw.get(s["username"], {})
            s["nom"] = info.get("nom", s["username"])

        self.workflow.create_workflow(path, signataires, self.auth.current_user["username"])
        self.audit.log_action(self.auth.current_user["username"], "WORKFLOW_CREATE",
                              f"Doc: {Path(path).name} | Signataires: {signataires_str}")
        messagebox.showinfo("Workflow Créé",
                            f"Flux de signature créé pour :\n{Path(path).name}\n\n"
                            f"Ordre : {' → '.join(s['username'] for s in signataires)}")
        self.show_workflow_tab()

    def action_approve_workflow(self, wf: dict):
        comment = simpledialog.askstring("Commentaire", "Commentaire (optionnel) :")
        result  = self.workflow.approve_step(wf["doc_path"], self.auth.current_user["username"],
                                             comment or "")
        if result["success"]:
            self.audit.log_action(self.auth.current_user["username"], "WORKFLOW_APPROVE",
                                  f"Doc: {wf['doc_name']}")
            messagebox.showinfo("Approuvé ✅", result["message"])
            self.show_workflow_tab()
        else:
            messagebox.showerror("Erreur", result["message"])

    def action_reject_workflow(self, wf: dict):
        reason = simpledialog.askstring("Motif de Rejet", "Motif du rejet :")
        result = self.workflow.reject_step(wf["doc_path"], self.auth.current_user["username"],
                                           reason or "Non spécifié")
        if result["success"]:
            self.audit.log_action(self.auth.current_user["username"], "WORKFLOW_REJECT",
                                  f"Doc: {wf['doc_name']}")
            messagebox.showinfo("Rejeté", result["message"])
            self.show_workflow_tab()
        else:
            messagebox.showerror("Erreur", result["message"])

    # ─────────────────────────────────────────────
    # ACTIONS MÉTIERS — BLOCKCHAIN
    # ─────────────────────────────────────────────
    def action_anchor_blockchain(self):
        path = filedialog.askopenfilename(filetypes=[("PDF", "*.pdf")])
        if not path:
            return
        try:
            doc_hash = self.pdf_engine.calculate_hash(path)
            anchor   = self.blockchain.anchor_hash(doc_hash, Path(path).name)
            self.audit.log_action(self.auth.current_user["username"], "BLOCKCHAIN_ANCHOR",
                                  f"File: {Path(path).name} | TX: {anchor['tx_hash'][:20]}")
            messagebox.showinfo("⛓️ Ancré !",
                                f"Hash ancré avec succès !\n\n"
                                f"Document : {Path(path).name}\n"
                                f"Hash SHA-256 : {doc_hash[:32]}...\n"
                                f"TX Hash : {anchor['tx_hash']}\n"
                                f"Mode : {anchor['mode']}\n"
                                f"Réseau : {anchor['network']}")
            self.show_blockchain_tab()
        except Exception as e:
            messagebox.showerror("Erreur Blockchain", str(e))

    def action_verify_blockchain(self):
        path = filedialog.askopenfilename(filetypes=[("PDF", "*.pdf")])
        if not path:
            return
        try:
            doc_hash = self.pdf_engine.calculate_hash(path)
            result   = self.blockchain.verify_anchor(doc_hash)
            if result["found"]:
                rec = result["record"]
                messagebox.showinfo("✅ Hash Trouvé",
                                    f"Ce document a bien été ancré !\n\n"
                                    f"Document : {rec.get('doc_name','?')}\n"
                                    f"Ancré le : {rec.get('timestamp','?')}\n"
                                    f"TX Hash : {rec.get('tx_hash', '?')}\n"
                                    f"Réseau : {rec.get('network','?')}")
            else:
                messagebox.showwarning("❌ Hash Introuvable",
                                       f"Ce document n'a pas encore été ancré sur la blockchain.\n\n"
                                       f"Hash : {doc_hash[:32]}...")
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    # ─────────────────────────────────────────────
    # ACTIONS MÉTIERS — 2FA / TOTP
    # ─────────────────────────────────────────────
    def action_setup_2fa(self):
        username = self.auth.current_user["username"]
        if not self.eid:
            messagebox.showerror("Erreur", "Module 2FA non initialisé.")
            return

        if self.eid.has_totp(username):
            choice = messagebox.askyesno("2FA Déjà Actif",
                                         "Le 2FA est déjà configuré pour votre compte.\n"
                                         "Voulez-vous le réinitialiser ?")
            if not choice:
                return

        try:
            setup_data = self.eid.setup_totp(username)
            self.audit.log_action(username, "2FA_SETUP", "Secret TOTP généré")

            # Afficher le QR Code de configuration dans une nouvelle fenêtre
            win = ctk.CTkToplevel(self)
            win.title("Configuration 2FA — Google Authenticator")
            win.geometry("500x550")
            win.grab_set()

            ctk.CTkLabel(win, text="🔐 Configuration du Double Facteur (2FA)",
                         font=ctk.CTkFont(size=16, weight="bold")).pack(pady=15)
            ctk.CTkLabel(win, text="Scannez ce QR Code avec Google Authenticator ou Authy :",
                         font=ctk.CTkFont(size=12)).pack(pady=5)

            # Afficher le QR Code
            qr_image = Image.open(io.BytesIO(setup_data["qr_image_bytes"]))
            qr_image = qr_image.resize((280, 280), Image.LANCZOS)
            qr_photo = ImageTk.PhotoImage(qr_image)

            qr_label = ctk.CTkLabel(win, image=qr_photo, text="")
            qr_label.image = qr_photo  # Garder la référence
            qr_label.pack(pady=15)

            ctk.CTkLabel(win, text=f"Secret (saisie manuelle) :\n{setup_data['secret']}",
                         font=ctk.CTkFont(size=11, family="Courier"),
                         text_color="#3498db").pack(pady=5)

            # Vérification immédiate
            ctk.CTkLabel(win, text="Entrez le code de votre app pour confirmer l'activation :",
                         font=ctk.CTkFont(size=12)).pack(pady=(10, 3))
            code_entry = ctk.CTkEntry(win, placeholder_text="Code à 6 chiffres",
                                      width=180, height=40, justify="center")
            code_entry.pack(pady=5)

            def confirm_setup():
                code = code_entry.get().strip()
                if self.eid.verify_totp(username, code):
                    messagebox.showinfo("✅ 2FA Activé",
                                        "Le 2FA est maintenant actif sur votre compte !\n"
                                        "Un code vous sera demandé à chaque signature.")
                    win.destroy()
                else:
                    messagebox.showerror("❌ Code Invalide",
                                         "Le code est incorrect. Réessayez.")

            ctk.CTkButton(win, text="✅ Confirmer & Activer",
                          command=confirm_setup, height=40).pack(pady=15)

        except Exception as e:
            messagebox.showerror("Erreur 2FA", str(e))

    # ─────────────────────────────────────────────
    # ACTIONS MÉTIERS — ROTATION & PASSWORD
    # ─────────────────────────────────────────────
    def action_rotate_keys(self):
        pwd = simpledialog.askstring("Sécurité",
                                     "Entrez votre mot de passe pour confirmer la rotation :", show='*')
        if pwd and self.auth.login(self.auth.current_user['username'], pwd):
            self.crypto.generate_new_identity(pwd)
            self.audit.log_action(self.auth.current_user['username'], "KEY_ROTATION",
                                  "Nouvelle identité générée")
            messagebox.showinfo("Sécurité", "Rotation effectuée. Nouvelle clé active.")
        else:
            messagebox.showerror("Erreur", "Mot de passe incorrect")

    def action_change_pwd(self):
        old_pwd = simpledialog.askstring("Sécurité", "Ancien mot de passe :", show='*')
        if old_pwd and self.auth.login(self.auth.current_user['username'], old_pwd):
            new_pwd = simpledialog.askstring("Sécurité", "Nouveau mot de passe :", show='*')
            if new_pwd:
                self.auth.change_password(self.auth.current_user['username'], new_pwd)
                self.crypto.generate_new_identity(new_pwd)
                self.audit.log_action(self.auth.current_user['username'], "PWD_CHANGE",
                                      "Mot de passe et clé mis à jour")
                messagebox.showinfo("Succès", "Mot de passe et identité mis à jour avec succès.")
        else:
            messagebox.showerror("Erreur", "Identifiants invalides")

    # ─────────────────────────────────────────────
    # ACTIONS MÉTIERS — ADMIN
    # ─────────────────────────────────────────────
    def action_add_user(self):
        username = self.add_user_entry.get()
        pwd      = self.add_pwd_entry.get()
        nom      = self.add_nom_entry.get()
        id_resp  = self.add_id_entry.get()
        role     = self.add_role_var.get()
        if not all([username, pwd, nom, id_resp]):
            messagebox.showwarning("Erreur", "Tous les champs sont obligatoires.")
            return
        success, msg = self.auth.add_user(username, pwd, nom, id_resp, role)
        if success:
            self.audit.log_action(self.auth.current_user['username'], "ADD_USER",
                                  f"Créé : {username}")
            messagebox.showinfo("Succès", msg)
            self.show_admin_tab()
        else:
            messagebox.showerror("Erreur", msg)

    def action_delete_user(self, username):
        if messagebox.askyesno("Confirmation",
                               f"Voulez-vous vraiment supprimer l'utilisateur {username} ?"):
            success, msg = self.auth.delete_user(username)
            if success:
                self.audit.log_action(self.auth.current_user['username'], "DEL_USER",
                                      f"Supprimé : {username}")
                messagebox.showinfo("Succès", msg)
                self.show_admin_tab()
            else:
                messagebox.showerror("Erreur", msg)


if __name__ == "__main__":
    app = ModernTrustApp()
    app.mainloop()
