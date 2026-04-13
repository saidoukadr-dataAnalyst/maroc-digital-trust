import hashlib
import qrcode
import io
import fitz  # PyMuPDF
import cv2
import numpy as np
from pathlib import Path

class PDFProcessor:
    @staticmethod
    def calculate_hash(file_path):
        """Calcule le hash SHA-256 d'un fichier."""
        with open(file_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    @staticmethod
    def create_qr_code(data):
        """Génère un QR code à partir de données textuelles."""
        qr = qrcode.make(data)
        buf = io.BytesIO()
        qr.save(buf, format='PNG')
        return buf.getvalue()

    @staticmethod
    def sign_pdf(input_path, qr_stream, output_path):
        """Insère un QR code dans la dernière page d'un PDF."""
        doc = fitz.open(input_path)
        page = doc[-1]
        
        # Positionnement en bas à droite
        rect = fitz.Rect(
            page.rect.width - 150, 
            page.rect.height - 150, 
            page.rect.width - 10, 
            page.rect.height - 10
        )
        
        page.insert_image(rect, stream=qr_stream)
        doc.save(str(output_path))
        doc.close()

    @staticmethod
    def extract_qr_data(pdf_path):
        """Extrait les données d'un QR code présent dans un PDF."""
        doc = fitz.open(pdf_path)
        page = doc[-1]
        
        img_info = page.get_image_info()
        if not img_info: raise ValueError("Aucun sceau QR trouvé.")
        
        mat = fitz.Matrix(2, 2)
        pix = page.get_pixmap(matrix=mat, clip=img_info[-1]["bbox"])
        img_np = np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.h, pix.w, pix.n)
        img_cv = cv2.cvtColor(img_np, cv2.COLOR_RGB2BGR)
        
        val, _, _ = cv2.QRCodeDetector().detectAndDecode(img_cv)
        if not val: raise ValueError("Sceau illisible.")
        
        # Parse data format ID:xxx|HASH:xxx|SIG:xxx
        return {l.split(':')[0]: l.split(':', 1)[1] for l in val.split('|')}
