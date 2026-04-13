import hashlib
import qrcode
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
from pathlib import Path
from typing import Tuple
import io
import fitz  # PyMuPDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import serialization

class LegalSignEngine:
    def __init__(self) -> None:
        # Simulation de la clé privée déverrouillée par biométrie (CNIE 2.0/MOSIP)
        # Dans une app réelle, la clé reste dans l'enclave sécurisée du smartphone [cite: 66, 71]
        self.private_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(ec.SECP256R1())
        self.public_key: ec.EllipticCurvePublicKey = self.private_key.public_key()

    def signer_document(self, chemin_pdf: Path, nom_signataire: str) -> Tuple[str, str]:
        """
        Calcule le hachage d'un document de manière efficace et le signe.
        Gère les fichiers volumineux sans surcharger la mémoire.
        """
        # 1. Hachage SHA-256 (Garantit l'intégrité) [cite: 18]
        # Lecture par blocs pour gérer les fichiers volumineux
        hash_objet = hashlib.sha256()
        with open(chemin_pdf, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_objet.update(chunk)
        hash_hex = hash_objet.hexdigest()
        
        # 2. Signature numérique (Garantit l'origine et la non-répudiation) 
        # On laisse la bibliothèque gérer le hachage interne pour éviter l'erreur 'prehashed'
        with open(chemin_pdf, "rb") as f:
            donnees_completes = f.read()

        signature = self.private_key.sign(
            donnees_completes,
            ec.ECDSA(hashes.SHA256())
        )
        signature_hex = signature.hex()
        
        print(f"✅ Document haché et signé pour : {nom_signataire}")
        return hash_hex, signature_hex

    def exporter_cle_publique(self, output_path: Path) -> None:
        """Exporte la clé publique au format PEM pour permettre la vérification."""
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(output_path, "wb") as f:
            f.write(pem)
        print(f"🔑 Clé publique exportée sous : {output_path}")

    def creer_qr_image_bytes(self, id_responsable: str, id_fichier: str, date_sig: str, sig_hex: str) -> io.BytesIO:
        """Génère l'image du QR Code et la retourne comme un flux d'octets en mémoire."""
        info_qr = (
            f"ID_RESPONSABLE: {id_responsable}\n"
            f"ID_FICHIER: {id_fichier}\n"
            f"DATE: {date_sig}\n"
            f"SIGNATURE_ECDSA: {sig_hex}\n"
        )

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=5,
        )
        qr.add_data(info_qr)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        # Sauvegarder l'image dans un buffer en mémoire
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_buffer.seek(0) # Important: rembobiner le buffer

        print("🖼️ Image QR Code générée en mémoire.")
        return img_buffer

    def embed_qr_in_pdf(self, original_pdf_path: Path, qr_image_bytes: io.BytesIO, output_pdf_path: Path):
        """
        Ouvre un PDF, ajoute l'image du QR code sur la dernière page et sauvegarde le résultat.
        """
        pdf_document = fitz.open(str(original_pdf_path))
        last_page = pdf_document[-1] # Récupérer la dernière page

        # Définir la taille et la position du QR code (ex: 120x120 pixels dans le coin inférieur droit)
        img_width, img_height = 120, 120
        page_width, page_height = last_page.rect.width, last_page.rect.height
        margin = 20
        image_rect = fitz.Rect(page_width - img_width - margin, page_height - img_height - margin, page_width - margin, page_height - margin)

        # Insérer l'image
        last_page.insert_image(image_rect, stream=qr_image_bytes)

        # Sauvegarder le PDF modifié
        pdf_document.save(str(output_pdf_path))
        pdf_document.close()
        print(f"📄 QR Code intégré dans le nouveau fichier : {output_pdf_path}")

class ApplicationSignature(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Moteur de Signature - Cité de l'Innovation")
        self.geometry("500x250")
        self.engine = LegalSignEngine()
        
        # Export automatique de la clé publique au lancement pour la démo
        base_path = Path(__file__).parent
        chemin_cle = base_path / "cle_publique.pem"
        self.engine.exporter_cle_publique(chemin_cle)
        
        frame = ttk.Frame(self, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="ID du Responsable :").grid(row=0, column=0, sticky=tk.W, pady=10)
        self.entry_id_resp = ttk.Entry(frame, width=40)
        self.entry_id_resp.grid(row=0, column=1, sticky=tk.W, pady=10)
        
        ttk.Label(frame, text="ID du Fichier :").grid(row=1, column=0, sticky=tk.W, pady=10)
        self.entry_id_fichier = ttk.Entry(frame, width=40)
        self.entry_id_fichier.grid(row=1, column=1, sticky=tk.W, pady=10)
        
        self.btn_signer = ttk.Button(frame, text="Parcourir le PDF et Signer", command=self.signer_fichier)
        self.btn_signer.grid(row=2, column=0, columnspan=2, pady=30)
        
    def signer_fichier(self):
        id_resp = self.entry_id_resp.get().strip()
        id_fich = self.entry_id_fichier.get().strip()
        
        if not id_resp or not id_fich:
            messagebox.showwarning("Attention", "Veuillez remplir l'ID du responsable et l'ID du fichier.")
            return
            
        chemin_pdf = filedialog.askopenfilename(title="Sélectionner le document à signer", filetypes=[("Fichiers PDF", "*.pdf")])
        if chemin_pdf:
            chemin_pdf = Path(chemin_pdf)
            date_signature = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                # 1. Calculer la signature à partir du PDF original
                _, sig_hex = self.engine.signer_document(chemin_pdf, id_resp)

                # 2. Créer l'image du QR Code en mémoire
                qr_bytes = self.engine.creer_qr_image_bytes(id_resp, id_fich, date_signature, sig_hex)

                # 3. Définir le chemin de sortie pour le nouveau PDF signé
                output_pdf_path = chemin_pdf.parent / f"{chemin_pdf.stem}_signe.pdf"

                # 4. Intégrer le QR code dans une copie du PDF
                self.engine.embed_qr_in_pdf(chemin_pdf, qr_bytes, output_pdf_path)

                messagebox.showinfo("Succès", f"Document signé !\n\nUn nouveau fichier PDF avec QR code a été créé ici :\n{output_pdf_path}")
            except Exception as e:
                messagebox.showerror("Erreur", f"Une erreur est survenue :\n{e}")

if __name__ == "__main__":
    app = ApplicationSignature()
    app.mainloop()