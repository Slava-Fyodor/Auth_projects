from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from .database import get_db
from .models import User
from .security import verify_token, is_token_blacklisted
from typing import Optional

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_token_from_header(request: Request) -> Optional[str]:
    authorization = request.headers.get("Authorization")
    if not authorization:
        return None
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            return None
        return token
    except ValueError:
        return None


async def get_current_user(
        token: str = Depends(oauth2_scheme),
        db: Session = Depends(get_db)
) -> User:
    if is_token_blacklisted(token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been blacklisted",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = verify_token(token)
    email: str = payload.get("sub")
    if email is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def get_optional_current_user(
        request: Request,
        db: Session = Depends(get_db)
) -> Optional[User]:
    token = get_token_from_header(request)
    if not token:
        return None
    try:
        return await get_current_user(token, db)
    except HTTPException:
        return None