from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers, fields, validation
from pyhanko.pdf_utils import text
from pyhanko.pdf_utils.font import opentype
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime
from datetime import timezone
import io
from pathlib import Path

class PadesEngine:
    def __init__(self, kms_manager=None, username=None, password=None):
        import pathlib
        if isinstance(kms_manager, (str, pathlib.Path)):
            self.kms = None
            self.p12_path = pathlib.Path(kms_manager)
            self.password = username  # In legacy mode, second arg was password
            self.username = None
        else:
            self.kms = kms_manager
            self.username = username
            self.password = password
            # For legacy compatibility
            self.p12_path = Path("security_vault") / f"cert_{username}.p12" if username else None

    def ensure_p12_exists(self, user_nom):
        """Génère un certificat auto-signé PKCS#12 et le stocke via KMS."""
        if self.kms and self.username:
            try:
                self.kms.load_identity(self.username, self.password)
                return
            except Exception:
                pass # Proceed to generation

        # ── Validation du mot de passe ──
        if not self.password:
            raise ValueError(
                "Mot de passe requis pour la protection du certificat PKCS#12. "
                "Impossible de procéder sans mot de passe."
            )

        # 1. Générer clé RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # 2. Créer certificat
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"MA"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Rabat"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Cité Innovation"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Maroc Digital Trust"),
            x509.NameAttribute(NameOID.COMMON_NAME, user_nom),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(timezone.utc) + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        # 3. Sauvegarder en PKCS12
        safe_nom = user_nom if user_nom else "Unknown"
        p12_data = serialization.pkcs12.serialize_key_and_certificates(
            name=safe_nom.encode(),
            key=private_key,
            cert=cert,
            cas=None,
            encryption_algorithm=serialization.BestAvailableEncryption(self.password.encode())
        )
        
        if self.kms and self.username:
            self.kms.store_identity(self.username, p12_data, self.password)
        elif self.p12_path:
            with open(self.p12_path, "wb") as f:
                f.write(p12_data)

    def sign_pdf_pades(self, input_path, output_path):
        """Applique une signature PAdES avec support LTV (ISO 32000-2)."""
        # ── Validation du mot de passe ──
        if not self.password:
            raise ValueError(
                "Mot de passe requis pour la signature PAdES. "
                "Impossible de déchiffrer le certificat PKCS#12 sans mot de passe."
            )

        if self.kms and self.username:
            p12_data = self.kms.load_identity(self.username, self.password)
            signer = signers.SimpleSigner.load_pkcs12(
                io.BytesIO(p12_data), 
                passphrase=self.password.encode()
            )
        else:
            signer = signers.SimpleSigner.load_pkcs12(
                str(self.p12_path), 
                passphrase=self.password.encode()
            )

        with open(input_path, 'rb') as inf:
            w = IncrementalPdfFileWriter(inf)
            
            # Paramètres de la signature avec LTV
            # On active 'embed_validation_info' pour inclure OCSP/CRL (si disponibles)
            meta = signers.PdfSignatureMetadata(
                field_name='Signature_Officielle',
                reason='Certification Maroc Digital Trust (LTV-Enabled)',
                location='Rabat, Maroc',
                embed_validation_info=True,
                use_pades_lta=True # Long-term availability
            )

            # Configuration du contexte de validation (Trusted Roots)
            # En production, on chargerait les racines de Barid eSign ici
            vc = validation.ValidationContext(
                allow_fetching=True, # Permet d'aller chercher OCSP/CRL sur le web
            )

            with open(output_path, 'wb') as outf:
                signers.sign_pdf(
                    w, meta, signer=signer, output=outf,
                    validation_context=vc
                )
        return True
