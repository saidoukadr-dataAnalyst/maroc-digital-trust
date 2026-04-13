from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from api.schemas import LoginRequest, LoginResponse
from api.dependencies import get_auth_manager
from auth_manager import AuthManager

router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication"]
)

@router.post("/login", response_model=LoginResponse)
def login(request: LoginRequest, auth: AuthManager = Depends(get_auth_manager)):
    if auth.login(request.username, request.password):
        # In a real app, generate a JWT token here.
        # For phase 1, we return a mock token and user info.
        return LoginResponse(
            message="Login successful",
            token="mock_jwt_token_12345",
            user_info=auth.current_user
        )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password"
    )
