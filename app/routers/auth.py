from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta
from typing import List
from .. import models, schemas, security
from ..database import get_db, redis_client
from ..dependencies import get_current_user
from ..config import settings

router = APIRouter(prefix="/auth", tags=["auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def rate_limit(limit: int, window: int):
    def decorator(func):
        async def wrapper(request: Request, *args, **kwargs):
            client_ip = request.client.host
            key = f"rate_limit:{client_ip}:{func.__name__}"

            try:
                # 获取当前请求次数
                current = redis_client.get(key)
                if current is not None and int(current) >= limit:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail="Too many requests"
                    )

                    # 更新请求次数
                pipe = redis_client.pipeline()
                pipe.incr(key)
                pipe.expire(key, window)
                pipe.execute()

                return await func(request, *args, **kwargs)
            except redis_client.RedisError:
                # Redis错误时不影响主要功能
                return await func(request, *args, **kwargs)

        return wrapper

    return decorator


@router.post("/register", response_model=schemas.UserOut)
@rate_limit(limit=5, window=60)
async def register(
        request: Request,
        user: schemas.UserCreate,
        db: Session = Depends(get_db)
):
    try:
        # 检查邮箱是否已注册
        if db.query(models.User).filter(models.User.email == user.email).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )

            # 创建新用户
        db_user = models.User(
            email=user.email,
            hashed_password=security.get_password_hash(user.password)
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)

        # 生成访问令牌
        access_token = security.create_token(
            data={"sub": db_user.email},
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        )

        return {
            "id": db_user.id,
            "email": db_user.email,
            "created_at": db_user.created_at,
            "access_token": access_token
        }
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Database error occurred"
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post("/login", response_model=schemas.Token)
@rate_limit(limit=10, window=60)
async def login(
        request: Request,
        user: schemas.UserLogin,  # 使用专门的登录schema
        db: Session = Depends(get_db)
):
    try:
        db_user = db.query(models.User).filter(models.User.email == user.email).first()
        if not db_user or not security.verify_password(
                user.password,
                db_user.hashed_password
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

            # 记录登录历史
        login_history = models.LoginHistory(
            user_id=db_user.id,
            user_agent=request.headers.get("user-agent"),
            ip_address=request.client.host
        )
        db.add(login_history)

        # 生成令牌
        access_token = security.create_token(
            data={"sub": user.email},
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        refresh_token = security.create_token(
            data={"sub": user.email},
            expires_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        )

        # 提交事务
        db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post("/refresh", response_model=schemas.Token)
@rate_limit(limit=20, window=60)
async def refresh_token(
        request: Request,
        current_token: str = Depends(oauth2_scheme),
        db: Session = Depends(get_db)
):
    try:
        # 验证当前token是否在黑名单中
        if security.is_token_blacklisted(current_token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked"
            )

            # 验证token
        payload = security.verify_token(current_token)
        email = payload.get("sub")
        if not email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )

            # 检查用户是否存在
        user = db.query(models.User).filter(models.User.email == email).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found"
            )

            # 生成新token
        access_token = security.create_token(
            data={"sub": email},
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        refresh_token = security.create_token(
            data={"sub": email},
            expires_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        )

        # 将旧token加入黑名单
        security.blacklist_token(
            current_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.put("/user", response_model=schemas.UserOut)
@rate_limit(limit=5, window=60)
async def update_user(
        request: Request,
        user_update: schemas.UserUpdate,
        current_user: models.User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    try:
        if user_update.email and user_update.email != current_user.email:
            if db.query(models.User).filter(models.User.email == user_update.email).first():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already registered"
                )
            current_user.email = user_update.email

        if user_update.password:
            current_user.hashed_password = security.get_password_hash(user_update.password)

        current_user.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(current_user)

        return current_user
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get("/history", response_model=List[schemas.LoginHistoryOut])
@rate_limit(limit=20, window=60)
async def get_login_history(
        request: Request,
        skip: int = 0,
        limit: int = 10,
        current_user: models.User = Depends(get_current_user),
        db: Session = Depends(get_db)
):
    try:
        history = db.query(models.LoginHistory) \
            .filter(models.LoginHistory.user_id == current_user.id) \
            .order_by(models.LoginHistory.login_time.desc()) \
            .offset(skip) \
            .limit(limit) \
            .all()
        return history
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post("/logout")
@rate_limit(limit=10, window=60)
async def logout(
        request: Request,
        current_token: str = Depends(oauth2_scheme)
):
    try:
        # 将token加入黑名单
        security.blacklist_token(
            current_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        return {"detail": "Successfully logged out"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )