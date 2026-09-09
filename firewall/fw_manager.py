"""
AZZAZEL firewall/fw_manager.py — Firewall Manager (Sprint 7).

Gestor de reglas de firewall multiplataforma con **dry-run por defecto**
y renderizado de órdenes sintetizadas para el backend detectado:

- ``iptables`` (Linux/requires root) — ``INPUT``/``OUTPUT`` + políticas.
- ``netsh advfirewall`` (Windows/requires Administrador).

Componentes:

- :class:`FirewallRule` — regla validada con DSL compacto en texto
  (``"deny out tcp 3389"`` / ``"allow out udp 51820 to 10.0.0.5/32"``)
  que se persiste tal cual en ``firewall.rules`` (schema del Config).
- :func:`render_iptables` / :func:`render_netsh` — traducción exacta.
- :class:`FirewallManager` — colección ordenada, plan completo con
  política por defecto, persistencia y ``apply()`` protegido por
  verificación de privilegios (nunca ejecuta en dry-run).
- :func:`vpn_only_rules` — la fábrica del KILL SWITCH de red: mientras
  está activa solo fluye el tráfico hacia el endpoint VPN (¡y nada del
  resto, incluido el DNS externo, que rompería la privacidad!).

Honestidad de ejecución: aplicar reglas exige privilegios de
administrador; sin ellos ``apply()`` lanza un error accionable y en el
mientras el módulo funciona como planificador / kill-switch-declarador.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Optional, Sequence

_AZZAZEL_ROOT = Path(__file__).resolve().parent.parent
if str(_AZZAZEL_ROOT) not in sys.path:
    sys.path.insert(0, str(_AZZAZEL_ROOT))

from core.config_manager import ConfigManager
from core.logger import get_logger

_log = get_logger("firewall.manager")

__all__ = [
    "FirewallRule", "FirewallManager", "detect_backend",
    "render_iptables", "render_netsh", "vpn_only_rules",
]

ACTIONS: tuple[str, ...] = ("allow", "deny", "drop", "reject")
DIRECTIONS: tuple[str, ...] = ("in", "out")
PROTOCOLS: tuple[str, ...] = ("tcp", "udp", "any")
RULE_NAME_PREFIX = "AZZ"  # prefijo netsh → borrado selectivo seguro


# ---------------------------------------------------------------------------
# Regla + DSL en texto plano (persistible en firewall.rules: list[str])
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class FirewallRule:
    """Una regla declarada: acción dirección protocolo [puerto] [to destino].

    Attributes:
        action: ``allow`` | ``deny`` (alias de drop) | ``drop`` | ``reject``.
        direction: ``in`` | ``out`` (visto desde ESTA máquina).
        protocol: ``tcp`` | ``udp`` | ``any``.
        port: 1-65535 o ``None`` (= cualquiera).
        target: IP/CIDR remoto al que aplica o ``None`` (= cualquiera).
        comment: texto libre que viaja con la regla.
    """

    action: str
    direction: str
    protocol: str = "any"
    port: Optional[int] = None
    target: Optional[str] = None
    comment: str = ""

    def __post_init__(self) -> None:
        if self.action not in ACTIONS:
            raise ValueError(f"acción inválida: {self.action!r} "
                             f"(válidas: {', '.join(ACTIONS)}).")
        if self.direction not in DIRECTIONS:
            raise ValueError(f"dirección inválida: {self.direction!r} "
                             "(usa 'in' o 'out').")
        if self.protocol not in PROTOCOLS:
            raise ValueError(f"protocolo inválido: {self.protocol!r} "
                             f"(válidos: {', '.join(PROTOCOLS)}).")
        if self.port is not None and not (1 <= self.port <= 65535):
            raise ValueError(f"puerto inválido: {self.port} (1-65535 o "
                             "omítelo para 'cualquiera').")
        if self.target is not None:
            try:
                ipaddress.ip_network(self.target, strict=False)
            except ValueError as exc:
                raise ValueError(f"target inválido: {self.target!r} — "
                                 "usa IP o CIDR (p. ej. 10.0.0.5/32).") \
                    from exc

    # -- DSL ----------------------------------------------------------
    def to_line(self) -> str:
        """Serializa la regla al DSL canónico (para ``firewall.rules``)."""
        parts = [self.action, self.direction, self.protocol]
        if self.port is not None:
            parts.append(str(self.port))
        if self.target is not None:
            parts.extend(["to", self.target])
        text = " ".join(parts)
        return f"{text} # {self.comment}" if self.comment else text

    @classmethod
    def from_line(cls, line: str) -> "FirewallRule":
        """Parsa una línea del DSL; ``#`` marca el comentario final.

        Raises:
            ValueError: sintaxis ilegal con ejemplo válido en el mensaje.
        """
        body, _, comment = line.partition("#")
        tokens = shlex.split(body.strip())
        if len(tokens) < 3:
            raise ValueError(f"regla demasiado corta: {line!r}. Ejemplo: "
                             "\"allow out tcp 443 to 10.0.0.0/24 # web\".")
        action, direction = tokens[0], tokens[1]
        rest = tokens[2:]
        protocol, port, target = "any", None, None
        i = 0
        while i < len(rest):
            tok = rest[i]
            if tok in PROTOCOLS:
                protocol = tok
            elif tok == "to":
                if i + 1 >= len(rest):
                    raise ValueError(f"'to' sin destino en {line!r}.")
                target = rest[i + 1]
                i += 1
            elif tok.isdigit():
                port = int(tok)
            else:
                raise ValueError(f"token no reconocido {tok!r} en {line!r}. "
                                 "Ejemplo: \"deny in tcp 23 # telnet\".")
            i += 1
        return cls(action=action, direction=direction, protocol=protocol,
                   port=port, target=target, comment=comment.strip())


# ---------------------------------------------------------------------------
# Renderizadores de backend (strings; apply() es quien los ejecuta)
# ---------------------------------------------------------------------------
def detect_backend() -> str:
    """Backend nativo por SO: ``netsh`` en Windows, ``iptables`` en otro."""
    return "netsh" if os.name == "nt" else "iptables"


def render_iptables(rule: FirewallRule) -> list[str]:
    """Traducción exacta a una orden ``iptables`` (una fila de la cadena)."""
    chain = "INPUT" if rule.direction == "in" else "OUTPUT"
    cmd = ["iptables", "-A", chain]
    if rule.protocol != "any":
        cmd += ["-p", rule.protocol]
        if rule.port is not None:
            cmd += ["--dport", str(rule.port)]
    elif rule.port is not None:
        raise ValueError("port con protocol 'any' es ambiguo en iptables: "
                         "declara tcp o udp explícitamente.")
    if rule.target is not None:
        cmd += ["-d" if rule.direction == "out" else "-s", rule.target]
    jump = {"allow": "ACCEPT", "deny": "DROP", "drop": "DROP",
            "reject": "REJECT"}[rule.action]
    cmd += ["-j", jump]
    if rule.comment:
        cmd += ["-m", "comment", "--comment", rule.comment[:40]]
    return [" ".join(cmd)]


def render_netsh(rule: FirewallRule) -> list[str]:
    """Traducción a orden ``netsh advfirewall firewall add rule``."""
    name = f"{RULE_NAME_PREFIX}-{rule.direction}-{rule.action}-" \
           f"{rule.protocol}-{rule.port or 'all'}".replace(" ", "")
    cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
           f"name={name}", "dir=in" if rule.direction == "in" else "dir=out",
           f"action={'Allow' if rule.action == 'allow' else 'Block'}"]
    if rule.protocol != "any":
        cmd.append(f"protocol={rule.protocol.upper()}")
    if rule.port is not None:
        cmd.append(f"{'localport' if rule.direction == 'in' else 'remoteport'}"
                   f"={rule.port}")
    if rule.target is not None:
        cmd.append(f"remoteip={rule.target}")
    if rule.comment:
        cmd.append(f"description={rule.comment[:40]}")
    return [" ".join(cmd)]


def _render_policy_iptables(default_policy: str) -> list[str]:
    jump = "ACCEPT" if default_policy == "allow" else "DROP"
    return [f"iptables -P {chain} {jump}" for chain in ("INPUT", "OUTPUT")]


def _render_policy_netsh(default_policy: str) -> list[str]:
    inbound = "Allow" if default_policy == "allow" else "Block"
    return ["netsh advfirewall set allprofiles firewallpolicy "
            f"{inbound}inbound,Allowoutbound"]


def vpn_only_rules(endpoint_host: str, endpoint_port: int,
                   protocol: str = "udp") -> list[FirewallRule]:
    """El plan KILL-SWITCH: solo el endpoint VPN; el resto, cerrado.

    Args:
        endpoint_host: IP literal del servidor VPN (¡no DNS! resolver antes
            de activar; si no, el propio DNS queda bloqueado).
        endpoint_port: Puerto del endpoint.
        protocol: Transporte del túnel (``udp`` por defecto, ``tcp`` válido).

    Returns:
        Reglas ORDENADAS: 1) loopback libre, 2) túnel permitido,
        3) todo lo demás cae.
    """
    if protocol not in ("tcp", "udp"):
        raise ValueError(f"protocolo de túnel inválido: {protocol!r}")
    return [
        FirewallRule("allow", "out", "any", None, "127.0.0.0/8",
                     "AZZ-KS: loopback siempre vivo"),
        FirewallRule("allow", "in", "any", None, "127.0.0.0/8",
                     "AZZ-KS: loopback in"),
        FirewallRule("allow", "out", protocol, endpoint_port, endpoint_host,
                     "AZZ-KS: sólo el endpoint del túnel sale"),
        FirewallRule("allow", "in", protocol, endpoint_port, endpoint_host,
                     "AZZ-KS: respuestas del túnel entran"),
        FirewallRule("drop", "out", "any", None, None,
                     "AZZ-KS: TODO lo demás queda bloqueado "
                     "(incluye DNS externo: tráfico sin cifrar = oculto)"),
        FirewallRule("drop", "in", "any", None, None,
                     "AZZ-KS: sin servicios expuestos mientras KS activo"),
    ]


# ---------------------------------------------------------------------------
# Manager: colección + plan + persistencia + apply() protegido
# ---------------------------------------------------------------------------
class FirewallManager:
    """Colección ordenada de reglas con ejecución honesta.

    ``dry_run=True`` (por defecto) convierte ``apply()`` en un plan
    meramente impreso: NUNCA se toca la máquina. Para ejecutar se exige
    además privilegios (root o Administrador) — sin ellos se lanza un
    error accionable antes de intentar nada.
    """

    def __init__(self, backend: Optional[str] = None,
                 dry_run: bool = True,
                 default_policy: str = "allow") -> None:
        if default_policy not in ("allow", "deny"):
            raise ValueError(f"default_policy inválida: {default_policy!r} "
                             "(allow|deny).")
        self.backend = backend or detect_backend()
        self.dry_run = dry_run
        self.default_policy = default_policy
        self.rules: list[FirewallRule] = []

    # -- mutación -----------------------------------------------------
    def add_rule(self, rule: FirewallRule) -> None:
        """Añade una regla; rechaza duplicados por línea canónica."""
        line = rule.to_line()
        if any(r.to_line() == line for r in self.rules):
            raise ValueError(f"regla duplicada: {line!r}.")
        self.rules.append(rule)
        _log.info("Regla añadida (%s): %s", self.backend, line)

    # -- traducción / plan --------------------------------------------
    def render_plan(self) -> list[str]:
        """Plan completo: política por defecto + cada regla traducida."""
        policy = (_render_policy_netsh(self.default_policy)
                  if self.backend == "netsh"
                  else _render_policy_iptables(self.default_policy))
        lines: list[str] = [
            "# AZZAZEL FIREWALL PLAN (dry_run=%s, backend=%s)"
            % (self.dry_run, self.backend),
            "# ⚠ ANTI-LOCKOUT: revisa que tu canal de gestión (ssh/rdp) "
            "siga permitido antes de aplicar una política restrictiva.",
        ]
        lines.extend(policy)
        renderer = render_netsh if self.backend == "netsh" \
            else render_iptables
        for rule in self.rules:
            lines.extend(renderer(rule))
        return lines

    # -- persistencia --------------------------------------------------
    def save_to_config(self, cm: ConfigManager) -> None:
        """Persiste reglas en ``firewall.rules`` (schema list[str])."""
        cm.set("firewall.enabled", bool(self.rules))
        cm.set("firewall.default_policy", self.default_policy)
        cm.set("firewall.rules", [r.to_line() for r in self.rules])
        cm.save()
        _log.info("Política persistida en config (%d reglas, enabled=%s).",
                  len(self.rules), bool(self.rules))

    def load_from_config(self, cm: ConfigManager) -> int:
        """Carga reglas del Config (tolerantes: las ilegales avisan)."""
        defaults = cm.config.firewall.default_policy
        if defaults in ("allow", "deny"):
            self.default_policy = defaults
        loaded = 0
        for line in cm.config.firewall.rules:
            try:
                self.rules.append(FirewallRule.from_line(line))
                loaded += 1
            except ValueError as exc:
                _log.warning("Regla ilegal de config ignorada: %s", exc)
        _log.info("Cargadas %d reglas de firewall desde config (%s).",
                  loaded, self.backend)
        return loaded

    # -- ejecución -----------------------------------------------------
    def apply(self) -> list[tuple[str, int]]:
        """Ejecuta el plan (o lo imprime si ``dry_run``).

        Returns:
            Pares ``(comando, rc)`` por cada orden ejecutada (dry_run →
            rc fijo ``0`` marcado como simulado).

        Raises:
            RuntimeError: sin privilegios de administrador/root, con la
                indicación exacta para cada SO.
        """
        plan = self.render_plan()
        if self.dry_run:
            _log.info("DRY-RUN activo: plan de %d órdenes NO se ejecuta.",
                      len(plan))
        else:
            self._require_admin()
        results: list[tuple[str, int]] = []
        for line in plan:
            if line.startswith("#"):
                continue
            if self.dry_run:
                _log.info("[dry-run] %s", line)
                results.append((line, 0))
                continue
            _log.info("Ejecutando: %s", line)
            cmd_args = shlex.split(line, posix=(os.name != "nt"))
            proc = subprocess.run(
                cmd_args, capture_output=True, text=True, check=False,
                shell=False)
            if proc.returncode != 0:
                _log.error("Falló (%s): %s — %s", proc.returncode, line,
                           (proc.stderr or "").strip()[:160])
            results.append((line, proc.returncode))
        _log.info("apply() finalizado: %d órdenes tratadas (dry_run=%s).",
                  len(results), self.dry_run)
        return results

    @staticmethod
    def _require_admin() -> None:
        """Verifica privilegios; error accionable si faltan."""
        if os.name == "nt":
            try:
                import ctypes
                admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:  # pragma: no cover - protección extrema
                admin = False
            if not admin:
                raise RuntimeError(
                    "Windows sin elevación: ejecuta la terminal como "
                    "ADMINISTRADOR para aplicar reglas (o mantén dry_run).")
        else:
            if os.geteuid() != 0:
                raise RuntimeError(
                    "Sin root: necesitas sudo / CAP_NET_ADMIN para"
                    " tocar iptables (o mantén dry_run=True).")


# =====================================================================
# Pruebas autónomas: python -m firewall.fw_manager
# =====================================================================
if __name__ == "__main__":
    import tempfile
    from pathlib import Path

    print("╔══ firewall/fw_manager.py — demo Sprint 7: Firewall Manager ══╗\n")

    # A) DSL round-trip + validación estricta
    valid = [
        "deny out tcp 3389",
        "allow out udp 51820 to 10.0.0.5/32 # vpn endpoint",
        "reject in tcp 23",
        "allow out any",
        "allow in any #  # comment con doble almohadilla",
    ]
    for line in valid:
        rule = FirewallRule.from_line(line)
        assert FirewallRule.from_line(rule.to_line()) == rule, line
    illegal = [
        "block out tcp 80",      # acción inexistente
        "allow up tcp 80",       # dirección inválida
        "allow out icmp 80",     # protocolo fuera de elenco
        "allow out tcp 99999",   # puerto fuera de rango
        "allow out tcp 80 to 999.0.0.1/32",  # target inválido
        "allow out",             # demasiado corta
        "allow out tcp wtf",     # token ilegal
        "allow out tcp 80 to",   # to sin destino
    ]
    for bad in illegal:
        try:
            FirewallRule.from_line(bad)
            raise AssertionError(f"aceptó regla ilegal: {bad!r}")
        except ValueError:
            pass
    print(f"  ✔ DSL: {len(valid)} válidas × round-trip, "
          f"{len(illegal)} ilegales rechazadas con guía")

    # B) render iptables EXACTO
    rule1 = FirewallRule("deny", "out", "tcp", 3389)
    assert render_iptables(rule1) == ["iptables -A OUTPUT -p tcp "
                                      "--dport 3389 -j DROP"]
    rule2 = FirewallRule("allow", "out", "udp", 51820, "10.0.0.5/32",
                         "endpoint")
    expect = "iptables -A OUTPUT -p udp --dport 51820 -d 10.0.0.5/32 " \
             "-j ACCEPT -m comment --comment endpoint"
    assert render_iptables(rule2) == [expect], render_iptables(rule2)
    rule3 = FirewallRule("drop", "in", "any")
    assert render_iptables(rule3) == ["iptables -A INPUT -j DROP"]
    try:
        render_iptables(FirewallRule("allow", "out", "any", 80))
        raise AssertionError("port con 'any' aceptado en iptables")
    except ValueError:
        pass
    print("  ✔ render_iptables: órdenes exactas + port/any = error guía")

    # C) render netsh exacto (backend simulado, os.name intacto)
    mgr_nt = FirewallManager(backend="netsh", dry_run=True)
    expect_nt = ("netsh advfirewall firewall add rule "
                 "name=AZZ-out-allow-udp-51820 dir=out action=Allow "
                 "protocol=UDP remoteport=51820 remoteip=10.0.0.5/32 "
                 "description=endpoint")
    assert render_netsh(rule2) == [expect_nt], render_netsh(rule2)
    expect_nt3 = ("netsh advfirewall firewall add rule "
                  "name=AZZ-in-drop-any-all dir=in action=Block")
    assert render_netsh(rule3) == [expect_nt3]
    assert mgr_nt.backend == "netsh"
    print("  ✔ render_netsh: órdenes Windows exactas (port dir-aware)")

    # D) kill-switch: vpn_only_rules completo
    ks = vpn_only_rules("192.0.2.10", 51820)
    plan = [r.to_line() for r in ks]
    assert plan[0].startswith("allow out any to 127.0.0.0/8")
    assert "allow out udp 51820 to 192.0.2.10" in plan[2]
    assert "DNS externo" in plan[4] and "drop out any" in plan[4]
    assert plan[-1].startswith("drop in any")
    try:
        vpn_only_rules("h", 1, protocol="icmp")
        raise AssertionError
    except ValueError:
        pass
    print("  ✔ vpn_only_rules: solo túnel vivo, DNS externo bloqueado")

    # E) persistencia config (schema list[str]) + dry-run apply
    tmp = Path(tempfile.mkdtemp(prefix="azz-fw-"))
    cm = ConfigManager(tmp / "cfg.yaml")
    cm.load_or_create()
    mgr = FirewallManager(backend="iptables", dry_run=True)
    for line in ("allow out tcp 443", "deny out tcp 3389"):
        mgr.add_rule(FirewallRule.from_line(line))
    mgr.save_to_config(cm)
    raw_yaml = (tmp / "cfg.yaml").read_text()
    assert "allow out tcp 443" in raw_yaml and "firewall:" in raw_yaml
    mgr2 = FirewallManager(backend="iptables", dry_run=True)
    assert mgr2.load_from_config(cm) == 2 and mgr2.rules[0].port == 443
    results = mgr2.apply()
    assert all(rc == 0 for _, rc in results) and len(results) == 4
    print("  ✔ config round-trip: rules persistidos en cfg + dry-run "
          "apply sin tocar máquina")

    # F) apply REAL sin privilegios → error accionable
    mgr_exec = FirewallManager(backend="iptables", dry_run=False)
    mgr_exec.add_rule(rule1)
    if os.name == "nt":  # pragma: no cover - este sandbox es Linux
        print("  · windows: _require_admin vía IsUserAnAdmin")
    else:
        if os.geteuid() != 0:
            try:
                mgr_exec.apply()
                raise AssertionError("apply() ejecutó sin root")
            except RuntimeError as exc:
                assert "root" in str(exc) or "sudo" in str(exc)
        else:
            print("  · (soy root: se omite la verificación negativa)")
    print("  ✔ apply() sin privilegios → RuntimeError accionable")

    # G) plan completo + política + duplicados
    mgr3 = FirewallManager(backend="iptables", dry_run=True,
                           default_policy="deny")
    dup = FirewallRule("allow", "out", "tcp", 443)
    mgr3.add_rule(dup)
    try:
        mgr3.add_rule(dup)
        raise AssertionError("duplicado aceptado")
    except ValueError:
        pass
    plan_lines = mgr3.render_plan()
    assert plan_lines[2] == "iptables -P INPUT DROP"
    assert plan_lines[3] == "iptables -P OUTPUT DROP"
    assert "ANTI-LOCKOUT" in plan_lines[1]
    net_plan = FirewallManager(backend="netsh", dry_run=True,
                               default_policy="deny").render_plan()
    assert "Blockinbound" in net_plan[2]
    print("  ✔ render_plan: política por defecto + banner anti-lockout + "
          "duplicados rechazados")
    print("\n╔══ DEMO COMPLETA: Firewall Manager 7/7 baterías ✔ ══╗")
