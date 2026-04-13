import os
import shutil
import tempfile
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from api.schemas import VerifyResponse
from api.dependencies import (
    get_crypto_engine, get_pdf_processor, get_audit_logger, VAULT_PATH
)
from api.tasks import sign_document_task

router = APIRouter(
    prefix="/api/v1/document",
    tags=["Document Processing"]
)

@router.post("/sign")
async def sign_document(
    file: UploadFile = File(...),
    username: str = Form(...),
    password: str = Form(...),
    apply_ocr: bool = Form(True),
    apply_dlp: bool = Form(True),
    audit = Depends(get_audit_logger)
):
    """
    Démarre une tâche asynchrone de certification.
    Retourne un task_id pour suivre l'état d'avancement.
    """
    try:
        # Enregistrement temporaire pour le worker
        # On utilise le vault_path car il est partagé via volume entre API et Worker
        temp_dir = VAULT_PATH / "temp_uploads"
        temp_dir.mkdir(exist_ok=True)
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf", dir=temp_dir) as tmp:
            shutil.copyfileobj(file.file, tmp)
            temp_path = Path(tmp.name)

        # Lancer la tâche Celery
        task = sign_document_task.delay(
            str(temp_path),
            file.filename,
            username,
            password,
            apply_ocr,
            apply_dlp
        )

        audit.log_action(username, "API_SIGN_ASYNC_START", f"Task: {task.id} | File: {file.filename}")
        
        return {
            "message": "Certification task started in background",
            "task_id": task.id,
            "status_url": f"/api/v1/tasks/{task.id}"
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/verify", response_model=VerifyResponse)
async def verify_document(
    file: UploadFile = File(...),
    crypto = Depends(get_crypto_engine),
    pdf_processor = Depends(get_pdf_processor),
    audit = Depends(get_audit_logger)
):
    """
    Vérification synchrone (reste rapide).
    """
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            shutil.copyfileobj(file.file, tmp)
            temp_path = Path(tmp.name)

        data = pdf_processor.extract_qr_data(str(temp_path))
        crypto.verify_signature(data["SIG"], data["HASH"])
        
        Path(temp_path).unlink()
        audit.log_action("API_USER", "API_VERIFY_SUCCESS", f"File: {file.filename}")
        
        return VerifyResponse(
            authentic=True,
            message="Document is authentic and signature is valid.",
            details=data
        )
    except Exception as e:
        audit.log_action("API_USER", "API_VERIFY_FAIL", f"File: {file.filename} | Error: {str(e)}")
        return VerifyResponse(
            authentic=False,
            message=f"Verification failed: {str(e)}",
            details={}
        )
