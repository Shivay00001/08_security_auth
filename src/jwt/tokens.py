"""
JWT Token Management - Secure token generation and validation.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Optional
from uuid import uuid4

from jose import JWTError, jwt
from pydantic import BaseModel


class TokenConfig(BaseModel):
    """JWT configuration."""
    
    secret_key: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    issuer: str = "erp-system"
    audience: str = "erp-api"


@dataclass
class TokenPayload:
    """Decoded token payload."""
    
    sub: str
    exp: datetime
    iat: datetime
    jti: str
    token_type: str
    scopes: list[str]
    extra: Dict[str, Any]


class TokenService:
    """
    JWT token service for authentication.
    
    Handles creation, validation, and refresh of JWT tokens
    with security best practices.
    """
    
    def __init__(self, config: TokenConfig):
        """
        Initialize token service.
        
        Args:
            config: Token configuration
        """
        self.config = config
    
    def create_access_token(
        self,
        subject: str,
        scopes: Optional[list[str]] = None,
        extra_claims: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Create an access token.
        
        Args:
            subject: Token subject (usually user ID)
            scopes: Permission scopes
            extra_claims: Additional claims
            
        Returns:
            Encoded JWT access token
        """
        now = datetime.utcnow()
        expires = now + timedelta(minutes=self.config.access_token_expire_minutes)
        
        payload = {
            "sub": subject,
            "exp": expires,
            "iat": now,
            "jti": str(uuid4()),
            "type": "access",
            "iss": self.config.issuer,
            "aud": self.config.audience,
            "scopes": scopes or [],
            **(extra_claims or {}),
        }
        
        return jwt.encode(
            payload,
            self.config.secret_key,
            algorithm=self.config.algorithm,
        )
    
    def create_refresh_token(
        self,
        subject: str,
        extra_claims: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Create a refresh token.
        
        Args:
            subject: Token subject
            extra_claims: Additional claims
            
        Returns:
            Encoded JWT refresh token
        """
        now = datetime.utcnow()
        expires = now + timedelta(days=self.config.refresh_token_expire_days)
        
        payload = {
            "sub": subject,
            "exp": expires,
            "iat": now,
            "jti": str(uuid4()),
            "type": "refresh",
            "iss": self.config.issuer,
            "aud": self.config.audience,
            **(extra_claims or {}),
        }
        
        return jwt.encode(
            payload,
            self.config.secret_key,
            algorithm=self.config.algorithm,
        )
    
    def verify_token(
        self,
        token: str,
        expected_type: str = "access",
    ) -> TokenPayload:
        """
        Verify and decode a token.
        
        Args:
            token: JWT token to verify
            expected_type: Expected token type
            
        Returns:
            Decoded token payload
            
        Raises:
            ValueError: If token is invalid
        """
        try:
            payload = jwt.decode(
                token,
                self.config.secret_key,
                algorithms=[self.config.algorithm],
                audience=self.config.audience,
                issuer=self.config.issuer,
            )
        except JWTError as e:
            raise ValueError(f"Invalid token: {e}")
        
        if payload.get("type") != expected_type:
            raise ValueError(f"Invalid token type: expected {expected_type}")
        
        return TokenPayload(
            sub=payload["sub"],
            exp=datetime.fromtimestamp(payload["exp"]),
            iat=datetime.fromtimestamp(payload["iat"]),
            jti=payload["jti"],
            token_type=payload["type"],
            scopes=payload.get("scopes", []),
            extra={
                k: v for k, v in payload.items()
                if k not in {"sub", "exp", "iat", "jti", "type", "iss", "aud", "scopes"}
            },
        )
    
    def refresh_access_token(self, refresh_token: str) -> tuple[str, str]:
        """
        Refresh access token using refresh token.
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            Tuple of (new_access_token, new_refresh_token)
        """
        payload = self.verify_token(refresh_token, expected_type="refresh")
        
        new_access = self.create_access_token(
            subject=payload.sub,
            extra_claims=payload.extra,
        )
        
        new_refresh = self.create_refresh_token(
            subject=payload.sub,
            extra_claims=payload.extra,
        )
        
        return new_access, new_refresh
