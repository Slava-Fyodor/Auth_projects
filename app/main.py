from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from datetime import datetime
from .routers import auth
from .database import Base, engine
import logging
from typing import Union
import uvicorn

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 创建FastAPI应用
app = FastAPI(
    title="Authentication Service",
    description="A secure authentication service with JWT tokens",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# CORS配置
origins = [
    "http://localhost",
    "http://localhost:8080",
    "http://localhost:3000",
    # 添加其他允许的源
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# 全局异常处理
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "timestamp": datetime.utcnow().isoformat()
        }
    )


# 请求日志中间件
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = datetime.utcnow()
    response = await call_next(request)
    end_time = datetime.utcnow()

    logger.info(
        f"Path: {request.url.path} "
        f"Method: {request.method} "
        f"Status: {response.status_code} "
        f"Duration: {(end_time - start_time).total_seconds():.3f}s"
    )
    return response


# 数据库初始化
def init_db():
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Error creating database tables: {e}")
        raise

    # 健康检查端点


@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": app.version
    }


# API版本端点
@app.get("/api/version")
async def get_version():
    return {
        "version": app.version,
        "timestamp": datetime.utcnow().isoformat()
    }


# 路由注册
app.include_router(
    auth.router,
    prefix="/api/auth",
    tags=["authentication"]
)


# 启动事件
@app.on_event("startup")
async def startup_event():
    logger.info("Starting up the application...")
    init_db()


# 关闭事件
@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down the application...")


# 主函数
def main():
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )


if __name__ == "__main__":
    main()