"""
AZZAZEL core/config_manager.py — gestor de configuración central (Sprint 1 + Auditoría).

Proporciona:
- Esquema tipado mediante dataclasses con validación y defaults sensatos.
- Carga tolerante con auto-reparación y modo estricto opcional.
- Protección transparente de secretos en disco (:data:`SECRET_FIELDS`)
  mediante cifrado con :class:`core.crypto_engine.CryptoEngine` y AAD.
- Acceso por ruta punteada (``cm.get("vpn.server.listen_port")``).
- Guardado atómico con reemplazo sobre archivo temporal.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from pathlib import Path
import sys
from typing import Any, Mapping, Optional, Protocol, Sequence

_AZZAZEL_ROOT = Path(__file__).resolve().parent.parent
if str(_AZZAZEL_ROOT) not in sys.path:
    sys.path.insert(0, str(_AZZAZEL_ROOT))

from core.logger import get_logger

_log = get_logger("core.config")

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

__all__ = [
    "AzzazelConfig",
    "AppSection",
    "UiSection",
    "LoggingSection",
    "VpnSection",
    "VpnServerSection",
    "VpnClientSection",
    "VpnKeysSection",
    "ProxySection",
    "ProxyLocalSection",
    "ProxyUpstreamSection",
    "BridgeSection",
    "BridgeSecuritySection",
    "BridgeSharingSection",
    "NetworkSection",
    "FirewallSection",
    "ApiSection",
    "MonitoringSection",
    "ConfigManager",
    "ConfigValidationError",
    "SECRET_FIELDS",
    "ENCRYPTED_PREFIX",
]

ENCRYPTED_PREFIX: str = "ENC[AES-256-GCM]"

SECRET_FIELDS: tuple[str, ...] = (
    "vpn.keys.private_key",
    "vpn.keys.psk",
    "proxy.upstream.password",
    "bridge.security.pin",
    "api.auth_token",
    "bridge.tailscale.auth_key",
)

_YAML_HEADER: str = (
    "# =============================================================================\n"
    "# AZZAZEL VPN v1.0 — Archivo de Configuración Maestro\n"
    "# Generado automáticamente. Los secretos marcados con ENC[...] están cifrados\n"
    "# en reposo con AES-256-GCM mediante la clave de máquina (.azzazel.key).\n"
    "# =============================================================================\n\n"
)


class CryptoService(Protocol):
    """Protocolo mínimo que debe cumplir el motor de cifrado."""
    def encrypt_str(self, plaintext: str, aad: Optional[str] = None) -> str: ...
    def decrypt_str(self, token: str, aad: Optional[str] = None) -> str: ...


class ConfigValidationError(ValueError):
    """Se lanza en modo estricto si hay valores inválidos."""
    def __init__(self, errors: Sequence[str]) -> None:
        self.errors = list(errors)
        super().__init__(
            f"Configuración inválida ({len(errors)} error(es)):\n  - "
            + "\n  - ".join(errors)
        )


def is_encrypted_token(value: Any) -> bool:
    """Comprueba si un valor ya está empaquetado con el prefijo de cifrado."""
    return isinstance(value, str) and value.startswith(f"{ENCRYPTED_PREFIX}:")


# ---------------------------------------------------------------------------
# Esquema de Configuración
# ---------------------------------------------------------------------------

@dataclass
class AppDatabaseSection:
    path: str = "data/azzazel.db"


@dataclass
class AppSecuritySection:
    master_password_hash: str = ""
    require_password_on_boot: bool = False
    key_rotation_hours: int = 168
    encryption_algorithm: str = "AES-256-GCM"
    auto_lock_minutes: int = 30
    max_failed_attempts: int = 5


@dataclass
class UiSection:
    mode: str = "ask"
    theme: str = "cyber"
    font_family: str = "Cascadia Code"
    font_size: int = 13
    enable_animations: bool = True
    notifications_enabled: bool = True
    language: str = "es"
    animations: bool = True
    sound_effects: bool = False


@dataclass
class AppSection:
    version: str = "1.0.0"
    name: str = "AZZAZEL"
    mode: str = "server"
    ui: UiSection = field(default_factory=UiSection)
    security: AppSecuritySection = field(default_factory=AppSecuritySection)
    logging: LoggingSection = field(default_factory=lambda: LoggingSection())
    database: AppDatabaseSection = field(default_factory=AppDatabaseSection)


@dataclass
class LoggingSection:
    level: str = "INFO"
    file: str = "logs/azzazel.log"
    max_size_mb: int = 100
    backup_count: int = 5
    rotation: int = 5
    console_output: bool = True
    audit_log_enabled: bool = True
    audit_file: str = "logs/audit.log"

    def to_logger_config(self) -> Any:
        from core.logger import LoggerConfig
        return LoggerConfig(
            level=self.level,
            log_file=self.file,
            max_size_mb=self.max_size_mb,
            rotation=self.rotation,
            console_output=self.console_output,
        )


@dataclass
class VpnServerSection:
    listen_address: str = "0.0.0.0"
    listen_port: int = 51820
    network: str = "10.66.66.0/24"
    dns: str = "1.1.1.1, 8.8.8.8"
    max_clients: int = 5
    keepalive: int = 25

    @property
    def subnet(self) -> str:
        return self.network

    @subnet.setter
    def subnet(self, value: str) -> None:
        self.network = value

    @property
    def tunnel_subnet(self) -> str:
        return self.network

    @tunnel_subnet.setter
    def tunnel_subnet(self, value: str) -> None:
        self.network = value


@dataclass
class VpnClientSection:
    server_address: str = "127.0.0.1"
    server_port: int = 51820
    auto_connect: bool = False
    kill_switch: bool = True
    persistent_keepalive: int = 25
    split_tunnel: bool = False
    split_tunnel_apps: list[str] = field(default_factory=list)
    split_tunnel_domains: list[str] = field(default_factory=list)


@dataclass
class VpnKeysSection:
    private_key: str = ""
    public_key: str = ""
    psk: str = ""

    def get_psk(self) -> str:
        return self.psk or self.private_key


@dataclass
class VpnSection:
    enabled: bool = True
    protocol: str = "azz1"  # azz1 (protocolo propio nativo PFS) | wireguard | openvpn
    server: VpnServerSection = field(default_factory=VpnServerSection)
    client: VpnClientSection = field(default_factory=VpnClientSection)
    keys: VpnKeysSection = field(default_factory=VpnKeysSection)


@dataclass
class ProxyLocalSection:
    enabled: bool = True
    http_port: int = 8888
    socks5_port: int = 1080
    bind_address: str = "127.0.0.1"
    max_connections: int = 100
    cache_enabled: bool = True
    cache_size_mb: int = 500


@dataclass
class ProxyUpstreamSection:
    enabled: bool = False
    host: str = ""
    port: int = 8080
    auth_type: str = "basic"
    domain: str = ""
    username: str = ""
    password: str = ""
    ssl_verify: bool = True
    ca_cert: str = ""
    bypass: list[str] = field(
        default_factory=lambda: [
            "localhost", "127.0.0.1", "10.0.0.0/8",
            "172.16.0.0/12", "192.168.0.0/16",
        ]
    )
    pac_url: str = ""


@dataclass
class ProxySection:
    local: ProxyLocalSection = field(default_factory=ProxyLocalSection)
    upstream: ProxyUpstreamSection = field(default_factory=ProxyUpstreamSection)


@dataclass
class BridgeDirectSection:
    ddns_provider: str = ""
    ddns_hostname: str = ""
    ddns_username: str = ""
    ddns_password: str = ""
    port_forward: bool = True


@dataclass
class BridgeRelaySection:
    server: str = ""
    token: str = ""


@dataclass
class BridgeSecuritySection:
    pin: str = "666000"
    pin_enabled: bool = True
    pin_timeout_minutes: int = 15
    pin_expiry_hours: int = 24
    max_devices: int = 5
    allowed_devices: list[str] = field(default_factory=list)
    require_2fa: bool = False


@dataclass
class BridgeSharingSection:
    internet: bool = True
    files: bool = True
    clipboard: bool = False
    notifications: bool = False
    allow_localhost: bool = False
    allowed_destinations: list[str] = field(default_factory=lambda: ["*"])


@dataclass
class BridgeTailscaleSection:
    auth_key: str = ""
    hostname: str = "azzazel-server"
    ephemeral: bool = True


@dataclass
class BridgeHeartbeatSection:
    interval_seconds: int = 30
    timeout_seconds: int = 90
    auto_reconnect: bool = True
    max_retries: int = 10


@dataclass
class NetworkAntiSuspendSection:
    enabled: bool = True
    method: str = "prevent"
    wol_mac: str = ""


@dataclass
class BridgeSection:
    enabled: bool = False
    listen_port: int = 8765
    visibility: str = "tailscale"
    tailscale: BridgeTailscaleSection = field(default_factory=BridgeTailscaleSection)
    direct: BridgeDirectSection = field(default_factory=BridgeDirectSection)
    relay: BridgeRelaySection = field(default_factory=BridgeRelaySection)
    security: BridgeSecuritySection = field(default_factory=BridgeSecuritySection)
    anti_suspend: NetworkAntiSuspendSection = field(default_factory=NetworkAntiSuspendSection)
    heartbeat: BridgeHeartbeatSection = field(default_factory=BridgeHeartbeatSection)
    sharing: BridgeSharingSection = field(default_factory=BridgeSharingSection)

    @property
    def port(self) -> int:
        return self.listen_port

    @port.setter
    def port(self, value: int) -> None:
        self.listen_port = value


@dataclass
class NetworkInterfacesSection:
    preferred: str = "auto"


@dataclass
class NetworkDnsSection:
    custom_dns: list[str] = field(default_factory=list)
    dns_over_https: bool = False
    doh_provider: str = "cloudflare"
    doh_server: str = "https://cloudflare-dns.com/dns-query"


@dataclass
class NetworkSection:
    interfaces: NetworkInterfacesSection = field(default_factory=NetworkInterfacesSection)
    dns: NetworkDnsSection = field(default_factory=NetworkDnsSection)
    anti_suspend: NetworkAntiSuspendSection = field(
        default_factory=NetworkAntiSuspendSection
    )


@dataclass
class FirewallSection:
    enabled: bool = True
    default_policy: str = "allow"
    rules: list[str] = field(default_factory=list)
    geo_block: list[str] = field(default_factory=list)


@dataclass
class ApiSection:
    enabled: bool = True
    host: str = "127.0.0.1"  # Seguro local por defecto
    port: int = 9999
    auth_token: str = ""
    rate_limit: int = 100
    cors_origins: list[str] = field(
        default_factory=lambda: ["http://127.0.0.1:9999", "http://localhost:9999"]
    )


@dataclass
class AlertThresholdsSection:
    cpu_percent: int = 90
    memory_percent: int = 85
    disk_percent: int = 95
    bandwidth_mbps: int = 100


@dataclass
class MonitoringSection:
    enabled: bool = True
    traffic_logging: bool = True
    resource_monitoring: bool = True
    alert_thresholds: AlertThresholdsSection = field(
        default_factory=AlertThresholdsSection
    )


@dataclass
class AzzazelConfig:
    azzazel: AppSection = field(default_factory=AppSection)
    logging: LoggingSection = field(default_factory=LoggingSection)
    vpn: VpnSection = field(default_factory=VpnSection)
    proxy: ProxySection = field(default_factory=ProxySection)
    bridge: BridgeSection = field(default_factory=BridgeSection)
    network: NetworkSection = field(default_factory=NetworkSection)
    firewall: FirewallSection = field(default_factory=FirewallSection)
    api: ApiSection = field(default_factory=ApiSection)
    monitoring: MonitoringSection = field(default_factory=MonitoringSection)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Gestor de Configuración
# ---------------------------------------------------------------------------

class ConfigManager:
    """Gestor unificado de configuración y secretos cifrados."""

    def __init__(
        self,
        path: str | Path = "config.yaml",
        crypto: Optional[CryptoService] = None,
    ) -> None:
        self._path = Path(path)
        self._crypto = crypto
        self._config: Optional[AzzazelConfig] = None
        self._warnings: list[str] = []

    @property
    def path(self) -> Path:
        return self._path

    @property
    def config(self) -> AzzazelConfig:
        if self._config is None:
            return self.load_or_create()
        return self._config

    @property
    def last_warnings(self) -> list[str]:
        return list(self._warnings)

    def set_crypto(self, crypto: CryptoService) -> None:
        self._crypto = crypto

    def ensure_directories(self) -> None:
        """Crea los directorios esenciales de datos y logs si no existen."""
        base = self._path.parent if self._path else Path.cwd()
        for d in ("logs", "data", "certs", "plugins"):
            (base / d).mkdir(parents=True, exist_ok=True)

    def load_or_create(self, strict: bool = False) -> AzzazelConfig:
        if not self._path.exists():
            _log.info("'%s' no existe; se crea con valores por defecto.", self._path)
            self._config = AzzazelConfig()
            self.save()
            return self._config
        return self.load(strict=strict)

    def load(self, strict: bool = False) -> AzzazelConfig:
        self._require_yaml()
        self._warnings = []
        raw = self._read_yaml(self._path)

        config = AzzazelConfig()
        if raw:
            self._populate(config, raw, path="<root>")

        problems = self._validate_pairs(config)
        if strict and problems:
            raise ConfigValidationError([msg for _, msg in problems])
        self._auto_repair(config, problems)

        self._resolve_secrets(config)
        self._config = config
        _log.success(
            "Configuración cargada desde '%s' (%d secciones, %d avisos).",
            self._path, len(fields(AzzazelConfig)), len(self._warnings),
        )
        return config

    def save(self, config: Optional[AzzazelConfig] = None) -> None:
        self._require_yaml()
        config = config or self._config or AzzazelConfig()
        self._config = config

        data = config.as_dict()
        self._protect_secrets(data)

        body = yaml.dump(  # type: ignore[union-attr]
            data, default_flow_style=False, sort_keys=False, allow_unicode=True,
        )
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(self._path.suffix + ".tmp")
            tmp.write_text(_YAML_HEADER + body, encoding="utf-8")
            os.replace(tmp, self._path)
        except OSError as exc:
            _log.error("No se pudo guardar '%s': %s", self._path, exc)
            raise
        _log.info("Configuración guardada en '%s'.", self._path)

    def get(self, dotted: str, default: Any = None) -> Any:
        try:
            # Compatibilidad con alias
            if dotted in ("vpn.server.subnet", "vpn.server.tunnel_subnet"):
                dotted = "vpn.server.network"
            parent, leaf = self._walk(self.config, dotted)
            return getattr(parent, leaf)
        except (AttributeError, KeyError, TypeError):
            return default

    def set(self, dotted: str, value: Any) -> None:
        # Compatibilidad con alias
        if dotted in ("vpn.server.subnet", "vpn.server.tunnel_subnet"):
            dotted = "vpn.server.network"
        try:
            parent, leaf = self._walk(self.config, dotted)
            current = getattr(parent, leaf)
        except (AttributeError, TypeError) as exc:
            raise KeyError(f"Ruta de configuración desconocida: {dotted!r}") from exc

        coerced = self._coerce(value, current, dotted)
        setattr(parent, leaf, coerced)
        _log.debug("Config.set: %s = %r", dotted, coerced)

    # -- Internos --------------------------------------------------------

    @staticmethod
    def _require_yaml() -> None:
        if yaml is None:  # pragma: no cover
            raise RuntimeError(
                "PyYAML no está instalado. Ejecuta: pip install pyyaml"
            )

    def _read_yaml(self, path: Path) -> dict[str, Any]:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            _log.error("No se pudo leer '%s': %s", path, exc)
            raise
        try:
            data = yaml.safe_load(text)  # type: ignore[union-attr]
        except yaml.YAMLError as exc:  # type: ignore[union-attr]
            _log.error("YAML malformado en '%s': %s", path, exc)
            raise ConfigValidationError([f"YAML malformado: {exc}"]) from exc
        if data is None:
            self._warnings.append("Archivo vacío; se usan los valores por defecto.")
            return {}
        if not isinstance(data, Mapping):
            raise ConfigValidationError(
                ["La raíz del YAML debe ser un mapa de secciones."]
            )
        return dict(data)

    def _populate(self, obj: Any, data: Mapping[str, Any], path: str) -> None:
        known = {f.name for f in fields(obj)}
        for key, value in data.items():
            dotted = f"{path}.{key}" if path != "<root>" else key
            # Alias de compatibilidad
            target_key = key
            if key == "subnet" and hasattr(obj, "network"):
                target_key = "network"
            if target_key not in known:
                self._warnings.append(f"{dotted}: clave desconocida, ignorada.")
                continue
            current = getattr(obj, target_key)
            if is_dataclass(current):
                if isinstance(value, Mapping):
                    self._populate(current, value, dotted)
                else:
                    self._warnings.append(
                        f"{dotted}: se esperaba una sección, se recibió "
                        f"{type(value).__name__}; se mantiene el default."
                    )
            else:
                setattr(obj, target_key, self._coerce(value, current, dotted))

    def _coerce(self, value: Any, current: Any, dotted: str) -> Any:
        def warn(why: str) -> Any:
            self._warnings.append(f"{dotted}: {why}; se mantiene {current!r}.")
            return current

        if value is None:
            return current
        if isinstance(current, bool):
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                lowered = value.strip().lower()
                if lowered in ("true", "yes", "si", "sí", "1", "on"):
                    return True
                if lowered in ("false", "no", "0", "off"):
                    return False
            return warn(f"no es un booleano ({value!r})")
        if isinstance(current, int):
            try:
                return int(value)
            except (TypeError, ValueError):
                return warn(f"no es un entero ({value!r})")
        if isinstance(current, float):
            try:
                return float(value)
            except (TypeError, ValueError):
                return warn(f"no es un número ({value!r})")
        if isinstance(current, str):
            return value if isinstance(value, str) else str(value)
        if isinstance(current, list):
            if isinstance(value, list):
                return ["" if v is None else str(v) for v in value]
            return warn(f"no es una lista ({value!r})")
        return value

    def _validate_pairs(self, cfg: AzzazelConfig) -> list[tuple[Optional[str], str]]:
        problems: list[tuple[Optional[str], str]] = []

        def check_port(path: str, port: int) -> None:
            if not (1 <= port <= 65535):
                problems.append((path, f"{path}: puerto fuera de rango ({port})"))

        def check_percent(path: str, value: int) -> None:
            if not (0 <= value <= 100):
                problems.append((path, f"{path}: debe estar entre 0 y 100% ({value})"))

        if cfg.azzazel.ui.mode not in ("ask", "cli", "gui"):
            problems.append(
                ("azzazel.ui.mode",
                 f"azzazel.ui.mode: valor inválido {cfg.azzazel.ui.mode!r} "
                 f"(válidos: ask, cli, gui)")
            )
        if cfg.azzazel.mode not in ("server", "client", "bridge"):
            problems.append(
                ("azzazel.mode",
                 f"azzazel.mode: modo inválido {cfg.azzazel.mode!r} "
                 f"(válidos: server, client, bridge)")
            )
        if cfg.vpn.protocol not in ("azz1", "wireguard", "openvpn"):
            problems.append(
                ("vpn.protocol",
                 f"vpn.protocol: valor inválido {cfg.vpn.protocol!r} "
                 f"(válidos: azz1, wireguard, openvpn)")
            )

        check_port("vpn.server.listen_port", cfg.vpn.server.listen_port)
        check_port("vpn.client.server_port", cfg.vpn.client.server_port)
        check_port("proxy.local.http_port", cfg.proxy.local.http_port)
        check_port("proxy.local.socks5_port", cfg.proxy.local.socks5_port)
        check_port("proxy.upstream.port", cfg.proxy.upstream.port)
        check_port("api.port", cfg.api.port)

        if cfg.bridge.heartbeat.timeout_seconds <= cfg.bridge.heartbeat.interval_seconds:
            problems.append(
                ("bridge.heartbeat.timeout_seconds",
                 "bridge.heartbeat.timeout_seconds debe ser mayor que interval_seconds")
            )
        if cfg.bridge.security.max_devices < 1:
            problems.append(
                ("bridge.security.max_devices",
                 "bridge.security.max_devices debe ser >= 1")
            )
        return problems

    def _auto_repair(
        self, cfg: AzzazelConfig, problems: list[tuple[Optional[str], str]]
    ) -> None:
        defaults = AzzazelConfig()
        for path, message in problems:
            if path is None:
                self._warnings.append(message)
                _log.warning("Config: %s", message)
                continue
            try:
                parent, leaf = self._walk(defaults, path)
                default_value = getattr(parent, leaf)
                target, target_leaf = self._walk(cfg, path)
                setattr(target, target_leaf, default_value)
            except (AttributeError, TypeError):
                self._warnings.append(f"{message} [sin reparación posible]")
                _log.warning("Config: %s", message)
                continue
            fix_msg = f"{message} → restaurado a {default_value!r}."
            self._warnings.append(fix_msg)
            _log.warning("Config: %s", fix_msg)

    def _protect_secrets(self, data: dict[str, Any]) -> None:
        for dotted in SECRET_FIELDS:
            value = self._dig(data, dotted)
            if not isinstance(value, str) or not value:
                continue
            if is_encrypted_token(value):
                continue
            if self._crypto is None:
                self._warnings.append(
                    f"{dotted}: sin motor criptográfico; el secreto se guarda EN CLARO."
                )
                continue
            try:
                token = self._crypto.encrypt_str(value, aad=dotted)
            except TypeError:
                token = self._crypto.encrypt_str(value)
            except Exception as exc:  # noqa: BLE001
                _log.error("No se pudo cifrar %s: %s", dotted, exc)
                continue
            self._dig(data, dotted, set_value=f"{ENCRYPTED_PREFIX}:{token}")

    def _resolve_secrets(self, cfg: AzzazelConfig) -> None:
        for dotted in SECRET_FIELDS:
            try:
                parent, leaf = self._walk(cfg, dotted)
            except (AttributeError, TypeError):
                continue
            value = getattr(parent, leaf)
            if not is_encrypted_token(value):
                continue
            if self._crypto is None:
                self._warnings.append(
                    f"{dotted}: valor cifrado pero no hay motor criptográfico."
                )
                continue
            token = value[len(ENCRYPTED_PREFIX) + 1:]
            try:
                try:
                    decrypted = self._crypto.decrypt_str(token, aad=dotted)
                except Exception:
                    decrypted = self._crypto.decrypt_str(token)
                setattr(parent, leaf, decrypted)
            except Exception as exc:  # noqa: BLE001
                self._warnings.append(
                    f"{dotted}: no se pudo descifrar ({exc}); ¿clave maestra incorrecta?"
                )

    @staticmethod
    def _walk(obj: Any, dotted: str) -> tuple[Any, str]:
        parts = dotted.split(".")
        for part in parts[:-1]:
            obj = getattr(obj, part)
        return obj, parts[-1]

    @staticmethod
    def _dig(data: dict[str, Any], dotted: str, set_value: Any = None) -> Any:
        parts = dotted.split(".")
        cur = data
        for p in parts[:-1]:
            if not isinstance(cur, dict) or p not in cur:
                return None
            cur = cur[p]
        last = parts[-1]
        if set_value is not None and isinstance(cur, dict):
            cur[last] = set_value
            return set_value
        return cur.get(last) if isinstance(cur, dict) else None
