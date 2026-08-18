===
import time
import hashlib
import hmac
from typing import Optional, Tuple, Set, Dict, Any
from dataclasses import dataclass, field

import jwt


@dataclass
class JWTConfig:
    secret_key: str
    algorithm: str = "HS256"
    access_token_lifetime: int = 900       # 15 min
    refresh_token_lifetime: int = 86400    # 24 h
    issuer: str = "securegate"


@dataclass
class RevocationStore:
    """In-memory revocation store. Swap for Redis/DB in production."""
    _revoked_access: Set[str] = field(default_factory=set)
    _revoked_refresh: Set[str] = field(default_factory=set)
    _refresh_family: Dict[str, str] = field(default_factory=dict)   # jti -> family_id
    _family_revoked: Set[str] = field(default_factory=set)

    def revoke_access(self, jti: str) -> None:
        self._revoked_access.add(jti)

    def is_access_revoked(self, jti: str) -> bool:
        return jti in self._revoked_access

    def revoke_refresh(self, jti: str) -> None:
        self._revoked_refresh.add(jti)
        family_id = self._refresh_family.get(jti)
        if family_id:
            self._family_revoked.add(family_id)

    def is_refresh_revoked(self, jti: str) -> bool:
        if jti in self._revoked_refresh:
            return True
        family_id = self._refresh_family.get(jti)
        if family_id and family_id in self._family_revoked:
            return True
        return False

    def register_refresh(self, jti: str, family_id: str) -> None:
        self._refresh_family[jti] = family_id


class JWTAuthMiddleware:
    def __init__(self, config: JWTConfig, store: Optional[RevocationStore] = None):
        self.config = config
        self.store = store or RevocationStore()

    def _generate_jti(self) -> str:
        return hashlib.sha256(
            hmac.new(self.config.secret_key.encode(), str(time.time_ns()).encode(), hashlib.sha256).digest()
        ).hexdigest()

    def issue_tokens(self, subject: str, roles: Optional[list] = None,
                     claims: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        now = int(time.time())
        access_jti = self._generate_jti()
        refresh_jti = self._generate_jti()
        family_id = self._generate_jti()

        payload = {
            "sub": subject,
            "iss": self.config.issuer,
            "iat": now,
            "roles": roles or [],
        }
        if claims:
            payload.update(claims)

        access_payload = {**payload, "jti": access_jti, "exp": now + self.config.access_token_lifetime, "type": "access"}
        refresh_payload = {**payload, "jti": refresh_jti, "exp": now + self.config.refresh_token_lifetime, "type": "refresh", "family": family_id}

        access_token = jwt.encode(access_payload, self.config.secret_key, algorithm=self.config.algorithm)
        refresh_token = jwt.encode(refresh_payload, self.config.secret_key, algorithm=self.config.algorithm)

        self.store.register_refresh(refresh_jti, family_id)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": self.config.access_token_lifetime,
            "token_type": "Bearer",
        }

    def validate_token(self, token: str, expected_type: str = "access") -> Dict[str, Any]:
        try:
            payload = jwt.decode(token, self.config.secret_key, algorithms=[self.config.algorithm], issuer=self.config.issuer)
        except jwt.ExpiredSignatureError:
            raise TokenError("Token has expired")
        except jwt.InvalidIssuerError:
            raise TokenError("Invalid issuer")
        except jwt.DecodeError:
            raise TokenError("Invalid token")

        if payload.get("type") != expected_type:
            raise TokenError(f"Expected {expected_type} token, got {payload.get('type')}")

        jti = payload.get("jti", "")
        if expected_type == "access" and self.store.is_access_revoked(jti):
            raise TokenError("Token has been revoked")
        if expected_type == "refresh" and self.store.is_refresh_revoked(jti):
            raise TokenError("Refresh token has been revoked")

        return payload

    def refresh_tokens(self, refresh_token: str, roles: Optional[list] = None) -> Dict[str, Any]:
        payload = self.validate_token(refresh_token, expected_type="refresh")

        family_id = payload.get("family", "")
        if family_id in self.store._family_revoked:
            raise TokenError("Token reuse detected — family revoked")

        # Revoke old refresh token
        old_jti = payload.get("jti", "")
        self.store.revoke_refresh(old_jti)

        # Issue new pair in the same family
        now = int(time.time())
        subject = payload["sub"]
        new_roles = roles or payload.get("roles", [])
        access_jti = self._generate_jti()
        refresh_jti = self._generate_jti()

        access_payload = {
            "sub": subject, "iss": self.config.issuer, "iat": now,
            "jti": access_jti, "exp": now + self.config.access_token_lifetime,
            "type": "access", "roles": new_roles,
        }
        refresh_payload = {
            "sub": subject, "iss": self.config.issuer, "iat": now,
            "jti": refresh_jti, "exp": now + self.config.refresh_token_lifetime,
            "type": "refresh", "roles": new_roles, "family": family_id,
        }

        access_token = jwt.encode(access_payload, self.config.secret_key, algorithm=self.config.algorithm)
        new_refresh_token = jwt.encode(refresh_payload, self.config.secret_key, algorithm=self.config.algorithm)

        self.store.register_refresh(refresh_jti, family_id)

        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "expires_in": self.config.access_token_lifetime,
            "token_type": "Bearer",
        }

    def revoke_token(self, token: str) -> None:
        try:
            payload = jwt.decode(token, self.config.secret_key, algorithms=[self.config.algorithm], options={"verify_exp": False})
        except jwt.DecodeError:
            raise TokenError("Invalid token")

        jti = payload.get("jti", "")
        token_type = payload.get("type", "")
        if token_type == "refresh":
            self.store.revoke_refresh(jti)
        else:
            self.store.revoke_access(jti)


class TokenError(Exception):
    pass
===