"""
AZZAZEL security/identity.py — Gestión de identidades, roles RBAC y tokens de acceso.
"""
from __future__ import annotations

import enum
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional

from core.crypto_engine import secure_compare


class Role(enum.Enum):
    """Roles de acceso y autorización dentro de AZZAZEL."""
    ADMIN = "admin"           # Control total del sistema y configuración
    OPERATOR = "operator"     # Control operativo de túneles, proxy y escaneo
    AUDITOR = "auditor"       # Solo lectura de métricas, logs y estado
    SERVICE = "service"       # Identidad máquina para Bridge y API


# Matriz de permisos por capacidad
ROLE_PERMISSIONS: dict[Role, set[str]] = {
    Role.ADMIN: {
        "vpn:control", "vpn:view",
        "proxy:control", "proxy:view",
        "bridge:pair", "bridge:view",
        "scanner:run", "scanner:view",
        "firewall:modify", "firewall:view",
        "config:read", "config:write",
        "logs:view", "metrics:view", "system:doctor",
    },
    Role.OPERATOR: {
        "vpn:control", "vpn:view",
        "proxy:control", "proxy:view",
        "bridge:pair", "bridge:view",
        "scanner:run", "scanner:view",
        "firewall:view",
        "config:read",
        "logs:view", "metrics:view", "system:doctor",
    },
    Role.AUDITOR: {
        "vpn:view", "proxy:view", "bridge:view",
        "scanner:view", "firewall:view",
        "logs:view", "metrics:view",
    },
    Role.SERVICE: {
        "bridge:pair", "bridge:view", "vpn:view", "metrics:view",
    },
}


@dataclass
class IdentityToken:
    """Token de acceso con rol, caducidad y hash seguro."""
    token_id: str
    token_hash: str
    role: Role
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    revoked: bool = False
    description: str = ""

    def is_valid(self) -> bool:
        """Verifica si el token sigue activo y no ha caducado."""
        if self.revoked:
            return False
        if self.expires_at is not None and time.time() > self.expires_at:
            return False
        return True


class IdentityManager:
    """Gestor centralizado de identidades, autenticación y autorización."""

    def __init__(self) -> None:
        self._tokens: dict[str, IdentityToken] = {}  # token_id -> IdentityToken

    @staticmethod
    def _hash_token(raw_token: str) -> str:
        """Calcula el hash SHA-256 del token para almacenamiento seguro."""
        return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    def create_token(
        self,
        role: Role,
        ttl_seconds: Optional[float] = None,
        description: str = "",
    ) -> tuple[str, IdentityToken]:
        """Genera un nuevo token criptográfico y lo registra.

        Returns:
            Tupla ``(raw_token_secret, IdentityToken)``.
        """
        raw_secret = f"azz_{role.value}_{secrets.token_urlsafe(32)}"
        token_id = secrets.token_hex(8)
        token_hash = self._hash_token(raw_secret)
        expires_at = (time.time() + ttl_seconds) if ttl_seconds else None

        record = IdentityToken(
            token_id=token_id,
            token_hash=token_hash,
            role=role,
            expires_at=expires_at,
            description=description,
        )
        self._tokens[token_id] = record
        return raw_secret, record

    def verify_token(self, raw_secret: str) -> Optional[IdentityToken]:
        """Autentica un token en tiempo constante y retorna su registro si es válido."""
        if not raw_secret:
            return None
        candidate_hash = self._hash_token(raw_secret)

        for record in self._tokens.values():
            if secure_compare(record.token_hash.encode(), candidate_hash.encode()):
                if record.is_valid():
                    return record
        return None

    def revoke_token(self, token_id: str) -> bool:
        """Revoca un token impidiendo cualquier uso posterior."""
        if token_id in self._tokens:
            self._tokens[token_id].revoked = True
            return True
        return False

    def is_authorized(self, token: IdentityToken, permission: str) -> bool:
        """Verifica si un token posee el permiso requerido."""
        if not token.is_valid():
            return False
        allowed = ROLE_PERMISSIONS.get(token.role, set())
        return permission in allowed

    def clean_expired(self) -> int:
        """Elimina tokens caducados o revocados de la memoria."""
        to_delete = [
            tid for tid, tok in self._tokens.items()
            if not tok.is_valid()
        ]
        for tid in to_delete:
            del self._tokens[tid]
        return len(to_delete)
