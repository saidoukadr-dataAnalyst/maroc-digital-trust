from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse
from celery.result import AsyncResult
from api.celery_app import celery_app, RESULTS_DIR
from pathlib import Path

router = APIRouter(
    prefix="/api/v1/tasks",
    tags=["Task Management"]
)

@router.get("/{task_id}")
async def get_task_status(task_id: str):
    """
    Vérifie l'état d'avancement d'une tâche asynchrone.
    """
    task_result = AsyncResult(task_id, app=celery_app)
    
    response = {
        "task_id": task_id,
        "status": task_result.status,
        "result": task_result.result if task_result.ready() else None
    }
    return response

@router.get("/{task_id}/download")
async def download_task_result(task_id: str):
    """
    Télécharge le fichier PDF produit par une tâche réussie.
    """
    task_result = AsyncResult(task_id, app=celery_app)
    
    if not task_result.ready():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Task is not finished yet.")
    
    if task_result.status != "SUCCESS":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Task failed with status: {task_result.status}")
    
    result_data = task_result.result
    if isinstance(result_data, dict) and result_data.get("status") == "completed":
        filename = result_data.get("filename")
        file_path = Path(RESULTS_DIR) / filename
        
        if not file_path.exists():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Result file not found on server.")
            
        return FileResponse(
            path=file_path,
            filename=result_data.get("original_filename", "certified_document.pdf"),
            media_type="application/pdf"
        )
    
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Task did not produce a downloadable file.")
