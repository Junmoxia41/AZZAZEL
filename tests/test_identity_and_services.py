"""
Pruebas unitarias para IdentityManager (RBAC, Tokens) y ServiceRegistry (Lifecycle).
"""
from __future__ import annotations

import time
import pytest

from core.service_registry import ServiceRegistry, ServiceState
from security.identity import IdentityManager, Role, ROLE_PERMISSIONS


def test_identity_manager_token_lifecycle():
    im = IdentityManager()

    # Creación de token con rol ADMIN
    raw_token, token_obj = im.create_token(Role.ADMIN, ttl_seconds=3600, description="Admin token test")
    assert raw_token.startswith("azz_admin_")
    assert token_obj.is_valid() is True

    # Verificación válida
    verified = im.verify_token(raw_token)
    assert verified is not None
    assert verified.token_id == token_obj.token_id
    assert verified.role == Role.ADMIN

    # Verificación con token incorrecto
    assert im.verify_token("azz_admin_invalidsecrettoken") is None
    assert im.verify_token("") is None

    # Verificación de permisos RBAC
    assert im.is_authorized(token_obj, "vpn:control") is True
    assert im.is_authorized(token_obj, "config:write") is True

    # Revocación de token
    assert im.revoke_token(token_obj.token_id) is True
    assert token_obj.is_valid() is False
    assert im.verify_token(raw_token) is None


def test_identity_manager_rbac_roles():
    im = IdentityManager()

    _, auditor_tok = im.create_token(Role.AUDITOR)
    _, operator_tok = im.create_token(Role.OPERATOR)

    # Auditor no puede controlar VPN pero sí ver logs
    assert im.is_authorized(auditor_tok, "vpn:control") is False
    assert im.is_authorized(auditor_tok, "logs:view") is True

    # Operator puede controlar VPN y proxy pero no modificar firewall
    assert im.is_authorized(operator_tok, "vpn:control") is True
    assert im.is_authorized(operator_tok, "proxy:control") is True
    assert im.is_authorized(operator_tok, "firewall:modify") is False


def test_identity_manager_expired_tokens():
    im = IdentityManager()
    raw_token, tok = im.create_token(Role.SERVICE, ttl_seconds=0.05)
    assert tok.is_valid() is True

    time.sleep(0.06)
    assert tok.is_valid() is False
    assert im.verify_token(raw_token) is None

    cleaned = im.clean_expired()
    assert cleaned >= 1


def test_service_registry_lifecycle():
    registry = ServiceRegistry()
    registry.reset()

    # Registro y estado inicial
    svc = registry.register("vpn_server", category="tunnel")
    assert svc.name == "vpn_server"
    assert svc.state == ServiceState.STOPPED
    assert svc.uptime == 0.0

    # Transición a RUNNING
    registry.set_state("vpn_server", ServiceState.RUNNING)
    assert svc.state == ServiceState.RUNNING
    assert svc.started_at is not None
    assert svc.uptime >= 0.0
    assert registry.is_healthy() is True

    # Transición a DEGRADED con error
    registry.set_state("vpn_server", ServiceState.DEGRADED, error="High packet loss")
    assert svc.state == ServiceState.DEGRADED
    assert svc.last_error == "High packet loss"
    assert svc.error_count == 1
    assert registry.is_healthy() is False

    # Transición a STOPPED
    registry.set_state("vpn_server", ServiceState.STOPPED)
    assert svc.state == ServiceState.STOPPED
    assert svc.started_at is None
