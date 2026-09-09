"""
AZZAZEL core/service_registry.py — Ciclo de vida y registro central de servicios.
"""
from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Any, Optional


class ServiceState(enum.Enum):
    """Estados del ciclo de vida de un subsistema o servicio en AZZAZEL."""
    STOPPED = "STOPPED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    DEGRADED = "DEGRADED"
    STOPPING = "STOPPING"
    FAILED = "FAILED"


@dataclass
class ServiceDescriptor:
    """Metadatos y estado operativo en tiempo real de un servicio."""
    name: str
    category: str = "core"
    state: ServiceState = ServiceState.STOPPED
    started_at: Optional[float] = None
    last_state_change: float = field(default_factory=time.time)
    error_count: int = 0
    last_error: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def uptime(self) -> float:
        """Tiempo de actividad acumulado en segundos si está en ejecución."""
        if self.state in (ServiceState.RUNNING, ServiceState.DEGRADED) and self.started_at:
            return time.time() - self.started_at
        return 0.0


class ServiceRegistry:
    """Registro singleton para la supervisión y ciclo de vida de subsistemas."""

    _instance: Optional[ServiceRegistry] = None

    def __new__(cls) -> ServiceRegistry:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._services = {}
        return cls._instance

    def __init__(self) -> None:
        if not hasattr(self, "_services"):
            self._services: dict[str, ServiceDescriptor] = {}

    def register(self, name: str, category: str = "general") -> ServiceDescriptor:
        """Registra un nuevo servicio en el supervisor."""
        if name not in self._services:
            self._services[name] = ServiceDescriptor(name=name, category=category)
        return self._services[name]

    def set_state(
        self,
        name: str,
        state: ServiceState,
        error: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        """Actualiza el estado operativo de un servicio."""
        svc = self.register(name)
        svc.state = state
        svc.last_state_change = time.time()

        if state == ServiceState.RUNNING and svc.started_at is None:
            svc.started_at = time.time()
        elif state in (ServiceState.STOPPED, ServiceState.FAILED):
            svc.started_at = None

        if error:
            svc.last_error = error
            svc.error_count += 1

        if details:
            svc.details.update(details)

    def get_service(self, name: str) -> Optional[ServiceDescriptor]:
        """Obtiene el descriptor de un servicio."""
        return self._services.get(name)

    def list_services(self) -> list[ServiceDescriptor]:
        """Lista todos los servicios registrados."""
        return list(self._services.values())

    def is_healthy(self) -> bool:
        """Determina si todos los servicios activos están en estado óptimo."""
        for svc in self._services.values():
            if svc.state in (ServiceState.FAILED, ServiceState.DEGRADED):
                return False
        return True

    def reset(self) -> None:
        """Limpia el registro de servicios."""
        self._services.clear()


# Instancia compartida global
SERVICES = ServiceRegistry()
