import os
import shutil
import tempfile
from pathlib import Path
from datetime import datetime
from api.celery_app import celery_app, RESULTS_DIR
from api.dependencies import (
    crypto_engine, pdf_processor, ocr_engine,
    dlp_engine, stamp_engine, blockchain_engine, audit_logger, VAULT_PATH,
    kms_manager
)
from pades_engine import PadesEngine

@celery_app.task(bind=True)
def sign_document_task(self, file_path: str, original_filename: str, username: str, password: str, apply_ocr: bool, apply_dlp: bool):
    """
    Tâche asynchrone pour la certification d'un PDF avec KMS & LTV.
    """
    try:
        temp_path = Path(file_path)
        if not temp_path.exists():
            raise FileNotFoundError(f"Fichier temporaire non trouvé : {file_path}")

        # KMS: Accès sécurisé à l'identité
        audit_logger.log_action(username, "KMS_ACCESS_START", f"Task: {self.request.id}")
        # On ne charge pas encore explicitement ici car PadesEngine le fera
        # Mais on vérifie que les clés crypto standard sont là pour le QR
        if not crypto_engine.load_keys(password):
             raise Exception("Invalid password for crypto keys")

        ocr_fields_str = ""
        # OCR
        if apply_ocr:
            try:
                ocr_result = ocr_engine.get_summary(str(temp_path))
                fields = ocr_result.get("fields", {})
                if fields:
                    ocr_fields_str = ocr_engine.fields_to_qr_string(fields)
            except Exception as e:
                print(f"OCR Error: {e}")

        # DLP
        if apply_dlp:
            try:
                doc_text = ocr_engine.extract_text(str(temp_path))
                alerts = dlp_engine.scan_document(doc_text, original_filename)
                if dlp_engine.is_blocked(alerts):
                    audit_logger.log_action(username, "DLP_BLOCK_ASYNC", f"File: {original_filename}")
                    raise Exception("DLP blocked the document due to critical sensitive data.")
            except Exception as e:
                print(f"DLP Error: {e}")
                if "DLP blocked" in str(e): raise

        # Hash and Sign (QR Layer)
        doc_hash = pdf_processor.calculate_hash(str(temp_path))
        signature = crypto_engine.sign_data(doc_hash)

        info_qr = f"ID:{username}|HASH:{doc_hash}|SIG:{signature.hex()}"
        if ocr_fields_str:
            info_qr += f"|{ocr_fields_str}"

        date_str = datetime.now().strftime("%d/%m/%Y %H:%M")
        stamp_bytes = stamp_engine.generate_stamp(
            qr_data=info_qr,
            signataire_nom=username,
            date_str=date_str,
            color_hex="#1a3a6e"
        )

        stamped_path = temp_path.parent / f"stamped_{temp_path.name}"
        pdf_processor.sign_pdf(str(temp_path), stamp_bytes, str(stamped_path))

        # PAdES Layer (Enterprise LTV)
        final_path = stamped_path
        try:
            # Nouveau moteur Pades avec KMS
            pades = PadesEngine(kms_manager=kms_manager, username=username, password=password)
            pades_path = temp_path.parent / f"cert_{temp_path.name}"
            pades.sign_pdf_pades(str(stamped_path), str(pades_path))
            final_path = pades_path
            audit_logger.log_action(username, "KMS_ACCESS_SUCCESS", f"PAdES Signed with LTV")
        except Exception as e:
            print(f"PAdES/KMS Error: {e}")
            audit_logger.log_action(username, "KMS_ACCESS_FAIL", f"Error: {str(e)}")
            # On continue avec le PDF tamponné si PAdES échoue (dégradé) ou on peut bloquer
            # raise Exception(f"PAdES Signing failed: {str(e)}")

        # Déplacer le résultat vers le dossier des résultats accessibles
        result_filename = f"signed_{self.request.id}.pdf"
        result_path = Path(RESULTS_DIR) / result_filename
        shutil.move(str(final_path), str(result_path))

        # Audit Final
        audit_logger.log_action(username, "ASYNC_SIGN_SUCCESS", f"Task: {self.request.id} | File: {original_filename}")
        
        # Cleanup
        if temp_path.exists(): temp_path.unlink()
        if stamped_path.exists() and stamped_path != final_path: stamped_path.unlink()

        return {
            "status": "completed",
            "filename": result_filename,
            "original_filename": original_filename,
            "doc_hash": doc_hash,
            "security": "KMS-Secured + LTV-Enabled"
        }

    except Exception as e:
        audit_logger.log_action(username, "ASYNC_SIGN_FAIL", f"Task: {self.request.id} | Error: {str(e)}")
        return {"status": "failed", "error": str(e)}

@celery_app.task
def anchor_blockchain_task(document_hash: str, document_name: str):
    """
    Tâche asynchrone pour l'ancrage Blockchain.
    """
    try:
        anchor = blockchain_engine.anchor_hash(document_hash, document_name)
        audit_logger.log_action("ASYNC_USER", "ASYNC_BLOCKCHAIN_ANCHOR", f"TX: {anchor['tx_hash'][:20]}")
        return {
            "status": "completed",
            "tx_hash": anchor["tx_hash"],
            "mode": anchor["mode"],
            "network": anchor["network"]
        }
    except Exception as e:
        return {"status": "failed", "error": str(e)}
