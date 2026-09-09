"""
Pruebas unitarias para network/upnp.py (UPnPPortMapper).
"""
from __future__ import annotations

from unittest.mock import patch, MagicMock
from network.upnp import UPnPPortMapper


def test_upnp_port_mapper_init():
    mapper = UPnPPortMapper(timeout=1.0)
    assert mapper.timeout == 1.0
    assert mapper.control_url is None
    assert mapper.service_type is None


def test_upnp_detect_local_ip():
    mapper = UPnPPortMapper()
    mapper._detect_local_ip()
    assert mapper.local_ip is not None
    assert mapper.local_ip != ""


def test_upnp_parse_igd_xml_mock():
    mapper = UPnPPortMapper()
    sample_xml = b"""<?xml version="1.0"?>
    <root xmlns="urn:schemas-upnp-org:device-1-0">
        <device>
            <serviceList>
                <service>
                    <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                    <controlURL>/ctl/IPConn</controlURL>
                </service>
            </serviceList>
        </device>
    </root>"""

    mock_resp = MagicMock()
    mock_resp.read.return_value = sample_xml
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        ok = mapper._parse_igd_xml("http://192.168.1.1:1900/igd.xml")
        assert ok is True
        assert mapper.service_type == "urn:schemas-upnp-org:service:WANIPConnection:1"
        assert mapper.control_url == "http://192.168.1.1:1900/ctl/IPConn"
