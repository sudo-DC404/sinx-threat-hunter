"""
sinX Threat Hunter - User and Authentication Models
"""

from sqlalchemy import Column, Integer, String, Boolean, TIMESTAMP, JSON
from datetime import datetime
from ..core.database import Base


class User(Base):
    """User accounts with RBAC"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Authentication
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)

    # Profile
    full_name = Column(String(200))

    # Authorization
    role = Column(String(50), default="analyst", index=True)  # admin, analyst, viewer, api_user
    permissions = Column(JSON)  # Granular permissions

    # Status
    is_active = Column(Boolean, default=True, index=True)
    is_verified = Column(Boolean, default=False)

    # MFA
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(255))

    # API Access
    api_key = Column(String(255), unique=True, index=True)
    api_key_expires = Column(TIMESTAMP(timezone=True))

    # Metadata
    created_at = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)
    last_login = Column(TIMESTAMP(timezone=True))

    # Preferences
    preferences = Column(JSON, default={})

    def to_dict(self, include_sensitive=False):
        """Convert to dictionary for API responses"""
        data = {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "role": self.role,
            "permissions": self.permissions,
            "is_active": self.is_active,
            "is_verified": self.is_verified,
            "mfa_enabled": self.mfa_enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "preferences": self.preferences,
        }

        if include_sensitive:
            data["api_key"] = self.api_key
            data["api_key_expires"] = self.api_key_expires.isoformat() if self.api_key_expires else None

        return data
