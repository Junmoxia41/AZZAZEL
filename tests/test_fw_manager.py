"""
AZZAZEL tests/test_fw_manager.py — Batería de pruebas de Firewall DSL, iptables, netsh y kill-switch.
"""
import pytest
from firewall.fw_manager import (
    FirewallRule,
    FirewallManager,
    render_iptables,
    render_netsh,
    vpn_only_rules,
)
from core.config_manager import ConfigManager


def test_firewall_rule_dsl_roundtrip():
    line = "allow in tcp 51820 # VPN WireGuard Server"
    rule = FirewallRule.from_line(line)
    assert rule.action == "allow"
    assert rule.direction == "in"
    assert rule.protocol == "tcp"
    assert rule.port == 51820
    assert rule.comment == "VPN WireGuard Server"

    # Exportar a DSL
    exported = rule.to_line()
    assert "allow in tcp 51820" in exported


def test_firewall_rule_validation():
    with pytest.raises(ValueError):
        FirewallRule.from_line("invalid_action in tcp 80")

    with pytest.raises(ValueError):
        FirewallRule.from_line("allow invalid_dir tcp 80")

    with pytest.raises(ValueError):
        FirewallRule.from_line("allow in tcp 999999")  # Puerto inválido


def test_render_iptables_and_netsh():
    rule = FirewallRule("allow", "in", "tcp", 22)
    iptables_cmds = render_iptables(rule)
    assert any("iptables" in cmd and "--dport 22" in cmd for cmd in iptables_cmds)

    netsh_cmds = render_netsh(rule)
    assert any("netsh advfirewall" in cmd and "localport=22" in cmd for cmd in netsh_cmds)


def test_vpn_only_rules_kill_switch_plan():
    rules = vpn_only_rules("51.254.120.4", 51820, "udp")
    assert len(rules) >= 4  # Reglas de loopback, túnel endpoint y drop del resto
    assert any(r.port == 51820 for r in rules)
    assert any(r.action == "drop" for r in rules)


def test_firewall_manager_dry_run_apply(temp_config_manager: ConfigManager):
    cm = temp_config_manager
    fm = FirewallManager(backend="iptables", dry_run=True)
    fm.add_rule(FirewallRule("allow", "in", "tcp", 8080))
    fm.save_to_config(cm)

    # Verificar que se guardó en config
    assert len(cm.config.firewall.rules) >= 1

    # Apply en modo dry_run no lanza excepción ni requiere root
    res = fm.apply()
    assert len(res) > 0
    assert all(rc == 0 for _, rc in res)
