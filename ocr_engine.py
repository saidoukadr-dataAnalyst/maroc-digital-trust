"""
ocr_engine.py — Extraction OCR Intelligente des PDFs
Maroc Digital Trust Gateway — Module Analyse Documentaire
"""
import re
from pathlib import Path


class OCREngine:
    """
    Extrait le texte et les champs clés d'un document PDF.
    Utilise pdfplumber pour les PDFs natifs et pytesseract pour les PDFs scannés (images).
    """

    # Patterns regex pour les champs sensibles / clés marocains
    FIELD_PATTERNS = {
        "CIN":       r'\b([A-Z]{1,2}\d{5,6})\b',
        "IBAN":      r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,19}\b',
        "Date":      r'\b(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4})\b',
        "Montant":   r'\b(\d[\d\s]*[,\.]?\d*)\s*(MAD|DH|EUR|USD|€|\$)',
        "Telephone": r'\b(0[5-7]\d{8}|\+212\d{9})\b',
        "Email":     r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b',
        "Nom":       r'(?:Nom\s*(?:complet)?|NOM)\s*[:\-]?\s*([A-ZÀÂÇÉÈÊËÎÏÔÛÙÜŸÆŒ][a-zàâçéèêëîïôûùüÿæœ]+(?:\s+[A-ZÀÂÇÉÈÊËÎÏÔÛÙÜŸÆŒ][a-zàâçéèêëîïôûùüÿæœ]+)*)',
        "Matricule": r'\b(RESP[-\s]?\d{3}|MAT[-\s]?\d{4,8})\b',
    }

    def extract_text(self, pdf_path: str) -> str:
        """
        Extrait le texte d'un PDF via pdfplumber (texte natif).
        Tente le fallback Tesseract OCR si le texte extrait est trop court.
        """
        pdf_path = Path(pdf_path)
        full_text = ""

        # Méthode 1 : pdfplumber (rapide, pour PDFs avec texte natif)
        try:
            import pdfplumber
            with pdfplumber.open(str(pdf_path)) as pdf:
                for page in pdf.pages:
                    page_text = page.extract_text()
                    if page_text:
                        full_text += page_text + "\n"
        except ImportError:
            print("[OCR] pdfplumber non installé, tentative Tesseract...")
        except Exception as e:
            print(f"[OCR] Erreur pdfplumber: {e}")

        # Méthode 2 : Tesseract OCR via pytesseract (pour les PDFs scannés)
        if len(full_text.strip()) < 50:
            try:
                import pytesseract
                import fitz  # PyMuPDF
                doc = fitz.open(str(pdf_path))
                for page in doc:
                    mat = fitz.Matrix(2, 2)  # Zoom x2 pour meilleure OCR
                    pix = page.get_pixmap(matrix=mat)
                    img_bytes = pix.tobytes("png")
                    # Convert to PIL Image
                    from PIL import Image
                    import io
                    img = Image.open(io.BytesIO(img_bytes))
                    text = pytesseract.image_to_string(img, lang='fra+ara+eng')
                    full_text += text + "\n"
                doc.close()
                print("[OCR] ✅ Texte extrait via Tesseract")
            except ImportError:
                print("[OCR] ⚠️  pytesseract non installé.")
            except Exception as e:
                print(f"[OCR] Erreur Tesseract: {e}")

        return full_text.strip()

    def extract_key_fields(self, text: str) -> dict:
        """
        Analyse le texte et extrait les champs clés via regex.

        Retourne un dictionnaire : { "CIN": ["AB123456"], "Date": ["01/03/2026"], ... }
        """
        results = {}
        for field_name, pattern in self.FIELD_PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            # Nettoyage et déduplication
            cleaned = list(set(m.strip() if isinstance(m, str) else m[0].strip() for m in matches if m))
            if cleaned:
                results[field_name] = cleaned

        return results

    def get_summary(self, pdf_path: str) -> dict:
        """
        Point d'entrée principal : extrait le texte + les champs clés.

        Retourne :
        {
            "text": "...",
            "fields": { "CIN": [...], "Date": [...] },
            "char_count": 1234,
            "ocr_used": True/False
        }
        """
        text = self.extract_text(pdf_path)
        fields = self.extract_key_fields(text)
        return {
            "text": text,
            "fields": fields,
            "char_count": len(text),
            "fields_count": sum(len(v) for v in fields.values()),
        }

    def fields_to_qr_string(self, fields: dict) -> str:
        """Sérialise les champs extraits en une chaîne compacte pour inclusion dans le QR Code."""
        parts = []
        for key, values in fields.items():
            parts.append(f"{key}:{','.join(str(v) for v in values[:2])}")  # Max 2 valeurs par champ
        return "FIELDS:" + "|".join(parts) if parts else ""
