import fitz  # PyMuPDF
import cv2
import numpy as np
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import io
import qrcode
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

class LegalTrustApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Système de Confiance Numérique - Cité de l'Innovation")
        self.geometry("700x500")
        
        # Gestion des clés (Chargement ou Création)
        self.chemin_cle = Path(__file__).parent / "cle_publique.pem"
        self.private_key, self.public_key = self._initialiser_cles()
        
        self.create_widgets()

    def _initialiser_cles(self):
        """Charge la clé existante ou en crée une nouvelle pour la démo."""
        if self.chemin_cle.exists():
            with open(self.chemin_cle, "rb") as f:
                pub_key = serialization.load_pem_public_key(f.read())
            # Note: En prod, la clé privée serait sur un token sécurisé
            priv_key = ec.generate_private_key(ec.SECP256R1()) 
            return priv_key, pub_key
        else:
            priv_key = ec.generate_private_key(ec.SECP256R1())
            pub_key = priv_key.public_key()
            with open(self.chemin_cle, "wb") as f:
                f.write(pub_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            return priv_key, pub_key

    def create_widgets(self):
        tab_control = ttk.Notebook(self)
        
        # --- ONGLET SIGNATURE ---
        self.tab_sign = ttk.Frame(tab_control)
        tab_control.add(self.tab_sign, text='🖊️ Signer un Document')
        self.setup_sign_tab()
        
        # --- ONGLET VÉRIFICATION ---
        self.tab_verify = ttk.Frame(tab_control)
        tab_control.add(self.tab_verify, text='🔍 Vérifier un Document')
        self.setup_verify_tab()
        
        tab_control.pack(expand=1, fill="both")

    def setup_sign_tab(self):
        frame = ttk.Frame(self.tab_sign, padding="30")
        frame.pack(fill=tk.BOTH)
        
        ttk.Label(frame, text="ID Responsable :").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.ent_resp = ttk.Entry(frame, width=30)
        self.ent_resp.grid(row=0, column=1, pady=5)
        
        btn_sign = ttk.Button(frame, text="Sélectionner PDF et Signer", command=self.signer_processus)
        btn_sign.grid(row=1, column=0, columnspan=2, pady=20)

    def setup_verify_tab(self):
        frame = ttk.Frame(self.tab_verify, padding="30")
        frame.pack(fill=tk.BOTH)

        self.path_orig = tk.StringVar(value="Non sélectionné")
        self.path_sig = tk.StringVar(value="Non sélectionné")

        ttk.Label(frame, text="1. Document Original :").grid(row=0, column=0, sticky=tk.W, pady=10)
        ttk.Label(frame, textvariable=self.path_orig, foreground="blue", width=40).grid(row=0, column=1)
        ttk.Button(frame, text="Parcourir", command=lambda: self.ouvrir_file(self.path_orig)).grid(row=0, column=2)

        ttk.Label(frame, text="2. Document Signé :").grid(row=1, column=0, sticky=tk.W, pady=10)
        ttk.Label(frame, textvariable=self.path_sig, foreground="blue", width=40).grid(row=1, column=1)
        ttk.Button(frame, text="Parcourir", command=lambda: self.ouvrir_file(self.path_sig)).grid(row=1, column=2)

        ttk.Button(frame, text="Lancer la Vérification", command=self.verifier_processus).grid(row=2, column=0, columnspan=3, pady=30)

    def ouvrir_file(self, var):
        f = filedialog.askopenfilename(filetypes=[("PDF", "*.pdf")])
        if f: var.set(f)

    # --- LOGIQUE DE SIGNATURE ---
    def signer_processus(self):
        resp = self.ent_resp.get()
        if not resp:
            messagebox.showwarning("Erreur", "Veuillez entrer l'ID Responsable")
            return
        
        f_path = filedialog.askopenfilename(filetypes=[("PDF", "*.pdf")])
        if not f_path: return

        try:
            # 1. Hacher et Signer l'ORIGINAL
            with open(f_path, "rb") as f:
                data = f.read()
            signature = self.private_key.sign(data, ec.ECDSA(hashes.SHA256()))
            sig_hex = signature.hex()

            # 2. Créer QR Code
            info = f"ID_RESPONSABLE:{resp}\nDATE:{datetime.now().strftime('%Y-%m-%d %H:%M')}\nSIGNATURE_ECDSA:{sig_hex}"
            qr_img = qrcode.make(info)
            buf = io.BytesIO()
            qr_img.save(buf, format='PNG')

            # 3. Insérer dans une COPIE du PDF
            doc = fitz.open(f_path)
            page = doc[-1]
            rect = fitz.Rect(page.rect.width-120, page.rect.height-120, page.rect.width-20, page.rect.height-20)
            page.insert_image(rect, stream=buf.getvalue())
            
            out_path = Path(f_path).parent / f"{Path(f_path).stem}_signe.pdf"
            doc.save(str(out_path))
            messagebox.showinfo("Succès", f"Document signé créé :\n{out_path.name}")
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    # --- LOGIQUE DE VÉRIFICATION ---
    def verifier_processus(self):
        p_orig = self.path_orig.get()
        p_sig = self.path_sig.get()
        
        if "Non sélectionné" in [p_orig, p_sig]:
            messagebox.showwarning("Attention", "Sélectionnez les deux fichiers.")
            return

        try:
            # 1. Extraire Signature du fichier SIGNÉ
            doc_sig = fitz.open(p_sig)
            img_list = doc_sig[-1].get_images(full=True)
            if not img_list: raise ValueError("Pas de QR Code trouvé.")
            
            xref = img_list[0][0]
            img_bytes = doc_sig.extract_image(xref)["image"]
            nparr = np.frombuffer(img_bytes, np.uint8)
            img_cv = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            
            val, _, _ = cv2.QRCodeDetector().detectAndDecode(img_cv)
            if not val: raise ValueError("Contenu QR illisible.")

            # Extraire la signature du texte du QR
            infos = {l.split(':')[0].strip(): l.split(':', 1)[1].strip() for l in val.split('\n') if ':' in l}
            sig_hex = infos.get("SIGNATURE_ECDSA")

            # 2. Comparer avec le contenu du fichier ORIGINAL
            with open(p_orig, "rb") as f:
                data_orig = f.read()

            self.public_key.verify(bytes.fromhex(sig_hex), data_orig, ec.ECDSA(hashes.SHA256()))
            
            messagebox.showinfo("Authentique ✅", f"Succès ! Le document original correspond à la signature.\nSigné par : {infos.get('ID_RESPONSABLE')}")
            
        except InvalidSignature:
            messagebox.showerror("Alerte ❌", "Falsification détectée ! Le document original ne correspond pas à la signature du QR.")
        except Exception as e:
            messagebox.showerror("Erreur", f"Échec de lecture : {e}")

if __name__ == "__main__":
    app = LegalTrustApp()
    app.mainloop()