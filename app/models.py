from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Index
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # 关系
    login_history = relationship("LoginHistory", back_populates="user")

    # 索引
    __table_args__ = (
        Index('idx_user_email', email),
    )

class LoginHistory(Base):
    __tablename__ = "login_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    user_agent = Column(String)
    login_time = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    ip_address = Column(String)

    # 关系
    user = relationship("User", back_populates="login_history")

    # 索引
    __table_args__ = (
        Index('idx_login_history_user_id', user_id),
        Index('idx_login_history_login_time', login_time),
    )