from pydantic import BaseModel
from typing import Optional, Dict, Any

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    message: str
    token: str
    user_info: Dict[str, Any]

class ErrorResponse(BaseModel):
    detail: str

class VerifyResponse(BaseModel):
    authentic: bool
    message: str
    details: Dict[str, Any]

class AnchorRequest(BaseModel):
    document_hash: str
    document_name: str

class AnchorResponse(BaseModel):
    success: bool
    tx_hash: str
    mode: str
    network: str

class VerifyAnchorResponse(BaseModel):
    found: bool
    message: str
    record: Optional[Dict[str, Any]] = None
