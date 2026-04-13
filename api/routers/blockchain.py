from fastapi import APIRouter, Depends, HTTPException, status
from api.schemas import AnchorRequest, AnchorResponse, VerifyAnchorResponse
from api.dependencies import get_blockchain_engine, get_audit_logger
from blockchain_engine import BlockchainEngine
from audit_logger import AuditLogger

router = APIRouter(
    prefix="/api/v1/blockchain",
    tags=["Blockchain Integration"]
)

@router.post("/anchor", response_model=AnchorResponse)
def anchor_document(
    request: AnchorRequest,
    blockchain: BlockchainEngine = Depends(get_blockchain_engine),
    audit: AuditLogger = Depends(get_audit_logger)
):
    try:
        anchor = blockchain.anchor_hash(request.document_hash, request.document_name)
        audit.log_action("API_USER", "API_BLOCKCHAIN_ANCHOR", f"TX: {anchor['tx_hash'][:20]}")
        return AnchorResponse(
            success=True,
            tx_hash=anchor["tx_hash"],
            mode=anchor["mode"],
            network=anchor["network"]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Blockchain anchor failed: {str(e)}")


@router.get("/verify/{document_hash}", response_model=VerifyAnchorResponse)
def verify_anchor(
    document_hash: str,
    blockchain: BlockchainEngine = Depends(get_blockchain_engine)
):
    try:
        result = blockchain.verify_anchor(document_hash)
        if result["found"]:
            return VerifyAnchorResponse(
                found=True,
                message="Hash found on blockchain ledger",
                record=result["record"]
            )
        return VerifyAnchorResponse(
            found=False,
            message="Hash not found"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
