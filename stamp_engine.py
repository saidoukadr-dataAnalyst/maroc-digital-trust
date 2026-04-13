"""
stamp_engine.py — Tampon Officiel Visuel Dynamique
Maroc Digital Trust Gateway — Module Génération de Sceaux
"""
import io
import math
from datetime import datetime
from pathlib import Path


class StampEngine:
    """
    Génère un tampon officiel composite qui remplace le simple QR Code brut.
    Le tampon intègre :
        - Un cercle officiel avec texte en arc
        - Le QR Code encodant les données de signature
        - Le nom du signataire et la date
    """

    def generate_stamp(
        self,
        qr_data: str,
        signataire_nom: str,
        date_str: str = None,
        color_hex: str = "#1a3a6e",
        size: int = 400
    ) -> bytes:
        """
        Génère un tampon officiel PNG en mémoire.

        Args:
            qr_data:       Données à encoder dans le QR Code
            signataire_nom: Nom du signataire (affiché sur le tampon)
            date_str:      Date de signature (auto si None)
            color_hex:     Couleur du tampon (bleu marine par défaut)
            size:          Taille en pixels du tampon généré

        Returns:
            bytes PNG du tampon généré
        """
        try:
            from PIL import Image, ImageDraw, ImageFont
            import qrcode as qrcode_lib
        except ImportError as e:
            raise ImportError(f"Pillow et/ou qrcode requis : {e}")

        if date_str is None:
            date_str = datetime.now().strftime("%d/%m/%Y %H:%M")

        # ---- 1. Générer l'image QR Code ----
        qr = qrcode_lib.QRCode(
            version=2,
            error_correction=qrcode_lib.constants.ERROR_CORRECT_M,
            box_size=6,
            border=2,
        )
        qr.add_data(qr_data)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color=color_hex, back_color="white").convert("RGBA")

        # ---- 2. Créer le canvas du tampon ----
        canvas = Image.new("RGBA", (size, size), (255, 255, 255, 0))
        draw = ImageDraw.Draw(canvas)

        # Couleur principale (convertir hex en RGB)
        r, g, b = int(color_hex[1:3], 16), int(color_hex[3:5], 16), int(color_hex[5:7], 16)
        main_color = (r, g, b, 255)
        light_color = (r, g, b, 80)

        center = size // 2
        outer_r = size // 2 - 5
        inner_r = size // 2 - 25

        # ---- 3. Dessiner les cercles ----
        # Cercle extérieur (anneau)
        draw.ellipse([5, 5, size - 5, size - 5], outline=main_color, width=6)
        # Cercle intérieur (double bordure)
        draw.ellipse([25, 25, size - 25, size - 25], outline=main_color, width=2)
        # Fond intérieur semi-transparent
        draw.ellipse([27, 27, size - 27, size - 27], fill=(r, g, b, 15))

        # ---- 4. Texte en arc (haut du cercle) ----
        arc_text = "MAROC DIGITAL TRUST • CERTIFIÉ •"
        self._draw_arc_text(draw, arc_text, center, center, outer_r - 12, 
                             main_color, start_angle=-135, total_angle=270)

        # ---- 5. Intégrer le QR Code au centre ----
        qr_size = int(size * 0.42)
        qr_img_resized = qr_img.resize((qr_size, qr_size), Image.LANCZOS)
        qr_x = center - qr_size // 2
        qr_y = center - qr_size // 2 - 10
        canvas.paste(qr_img_resized, (qr_x, qr_y), qr_img_resized)

        # ---- 6. Nom du signataire (bas du tampon) ----
        try:
            font_name = ImageFont.truetype("arial.ttf", int(size * 0.052))
            font_date = ImageFont.truetype("arial.ttf", int(size * 0.042))
        except OSError:
            font_name = ImageFont.load_default()
            font_date = font_name

        # Nom du signataire
        nom_short = signataire_nom[:20] + "..." if len(signataire_nom) > 20 else signataire_nom
        bbox_nom = draw.textbbox((0, 0), nom_short, font=font_name)
        nom_w = bbox_nom[2] - bbox_nom[0]
        draw.text(((size - nom_w) // 2, center + qr_size // 2 - 5), 
                  nom_short, fill=main_color, font=font_name)

        # Date
        bbox_date = draw.textbbox((0, 0), date_str, font=font_date)
        date_w = bbox_date[2] - bbox_date[0]
        draw.text(((size - date_w) // 2, center + qr_size // 2 + int(size * 0.058)), 
                  date_str, fill=(r, g, b, 200), font=font_date)

        # ---- 7. Exporter en PNG bytes ----
        output = io.BytesIO()
        canvas.save(output, format="PNG")
        return output.getvalue()

    def _draw_arc_text(self, draw, text: str, cx: int, cy: int, radius: int, 
                       color, start_angle: float = -130, total_angle: float = 260):
        """Dessine du texte le long d'un arc de cercle."""
        try:
            from PIL import ImageFont
            font = ImageFont.truetype("arial.ttf", 16)
        except OSError:
            from PIL import ImageFont
            font = ImageFont.load_default()

        n = len(text)
        if n == 0:
            return

        angle_step = total_angle / max(n - 1, 1)

        for i, char in enumerate(text):
            angle_deg = start_angle + i * angle_step
            angle_rad = math.radians(angle_deg)
            x = cx + radius * math.cos(angle_rad)
            y = cy + radius * math.sin(angle_rad)
            # Rotation du caractère (on utilise une image temporaire par caractère)
            try:
                from PIL import Image, ImageDraw, ImageFont
                char_img = Image.new("RGBA", (24, 24), (0, 0, 0, 0))
                char_draw = ImageDraw.Draw(char_img)
                char_draw.text((2, 2), char, fill=color, font=font)
                rotation = angle_deg + 90
                char_img = char_img.rotate(-rotation, expand=True, resample=Image.BICUBIC)
                draw._image.paste(char_img, (int(x) - char_img.width // 2, 
                                              int(y) - char_img.height // 2), char_img)
            except Exception:
                draw.text((x, y), char, fill=color, font=font)
