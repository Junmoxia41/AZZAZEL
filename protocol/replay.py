"""
AZZAZEL protocol/replay.py — Protección anti-replay con ventana deslizante.
"""
from __future__ import annotations

from protocol.constants import REPLAY_WINDOW_SIZE


class ReplayWindow:
    """Ventana anti-replay deslizante sobre contadores de secuencia monótonos (RFC 6479 inspired).

    Mantiene el contador máximo visto y un mapa de bits de los últimos ``size``
    paquetes para rechazar datagramas duplicados, retrasados fuera de ventana o manipulados.
    """

    def __init__(self, size: int = REPLAY_WINDOW_SIZE) -> None:
        if size <= 0:
            raise ValueError(f"El tamaño de la ventana de replay debe ser positivo: {size}")
        self.size: int = int(size)
        self.max_seen: int = -1
        self._bitmap: int = 0

    def check_and_record(self, counter: int) -> bool:
        """Verifica si el contador es admisible y actualiza el estado de la ventana.

        Args:
            counter: Entero no negativo de 64 bits con el contador de secuencia del frame.

        Returns:
            ``True`` si el frame es válido (no duplicado y dentro de la ventana),
            ``False`` si es un paquete duplicado o fuera de ventana (rechazado).
        """
        if counter < 0:
            return False

        if counter > self.max_seen:
            shift = counter - self.max_seen
            if shift >= self.size:
                self._bitmap = 1
            else:
                self._bitmap = (self._bitmap << shift) | 1
                self._bitmap &= (1 << self.size) - 1
            self.max_seen = counter
            return True

        delta = self.max_seen - counter
        if delta >= self.size:
            return False  # Fuera de la ventana (demasiado antiguo)

        bit = 1 << delta
        if self._bitmap & bit:
            return False  # Paquete duplicado (Replay Attack detectado)

        self._bitmap |= bit
        return True

    def reset(self) -> None:
        """Reinicia la ventana a su estado inicial."""
        self.max_seen = -1
        self._bitmap = 0
