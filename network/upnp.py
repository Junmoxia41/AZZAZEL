"""
AZZAZEL network/upnp.py — Auto-apertura de puertos en router mediante UPnP / SSDP (Zero-Config).
"""
from __future__ import annotations

import re
import socket
import urllib.request
import xml.etree.ElementTree as ET
from typing import Optional

from core.logger import get_logger

_log = get_logger("network.upnp")

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
SSDP_MX = 2
SSDP_ST = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"

SSDP_PAYLOAD = (
    f"M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
    f'MAN: "ssdp:discover"\r\n'
    f"MX: {SSDP_MX}\r\n"
    f"ST: {SSDP_ST}\r\n"
    f"\r\n"
).encode("utf-8")


class UPnPPortMapper:
    """Descubre el router de la casa y abre puertos automáticamente sin entrar a la web del router."""

    def __init__(self, timeout: float = 3.0) -> None:
        self.timeout = timeout
        self.control_url: Optional[str] = None
        self.service_type: Optional[str] = None
        self.external_ip: Optional[str] = None
        self.local_ip: Optional[str] = None

    def discover(self) -> bool:
        """Envía solicitud multicast SSDP para localizar el router UPnP."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(self.timeout)

        location_url = None
        try:
            sock.sendto(SSDP_PAYLOAD, (SSDP_ADDR, SSDP_PORT))
            while True:
                data, _ = sock.recvfrom(2048)
                resp = data.decode("utf-8", errors="ignore")
                for line in resp.splitlines():
                    if line.lower().startswith("location:"):
                        location_url = line.split(":", 1)[1].strip()
                        break
                if location_url:
                    break
        except Exception:
            pass
        finally:
            sock.close()

        if not location_url:
            _log.debug("No se recibió respuesta SSDP del router.")
            return False

        return self._parse_igd_xml(location_url)

    def _parse_igd_xml(self, xml_url: str) -> bool:
        """Descarga el XML descriptivo del router para obtener la URL de control de puertos."""
        try:
            req = urllib.request.Request(xml_url, headers={"User-Agent": "AZZAZEL-UPnP"})
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                xml_data = response.read()

            root = ET.fromstring(xml_data)
            # Buscar servicios WANIPConnection o WANPPPConnection
            for service in root.iter("{urn:schemas-upnp-org:device-1-0}service"):
                st_elem = service.find("{urn:schemas-upnp-org:device-1-0}serviceType")
                cu_elem = service.find("{urn:schemas-upnp-org:device-1-0}controlURL")
                if st_elem is not None and cu_elem is not None:
                    st_text = st_elem.text or ""
                    if "WANIPConnection" in st_text or "WANPPPConnection" in st_text:
                        self.service_type = st_text
                        cu_text = cu_elem.text or ""
                        if cu_text.startswith("http"):
                            self.control_url = cu_text
                        else:
                            base = "/".join(xml_url.split("/")[:3])
                            self.control_url = base + ("" if cu_text.startswith("/") else "/") + cu_text
                        self._detect_local_ip()
                        return True
        except Exception as exc:
            _log.debug("Error procesando XML de UPnP: %s", exc)
        return False

    def _detect_local_ip(self) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                self.local_ip = s.getsockname()[0]
        except Exception:
            self.local_ip = "127.0.0.1"

    def get_external_ip(self) -> Optional[str]:
        """Consulta al router cuál es la IP pública externa."""
        if not self.control_url or not self.service_type:
            return None

        soap_body = (
            f'<?xml version="1.0"?>'
            f'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            f'<s:Body>'
            f'<u:GetExternalIPAddress xmlns:u="{self.service_type}"/>'
            f'</s:Body>'
            f'</s:Envelope>'
        )

        headers = {
            "SOAPAction": f'"{self.service_type}#GetExternalIPAddress"',
            "Content-Type": 'text/xml; charset="utf-8"',
        }

        try:
            req = urllib.request.Request(self.control_url, data=soap_body.encode("utf-8"), headers=headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                tree = ET.fromstring(resp.read())
                elem = tree.find(".//NewExternalIPAddress")
                if elem is not None and elem.text:
                    self.external_ip = elem.text.strip()
                    return self.external_ip
        except Exception:
            pass
        return None

    def add_port_mapping(self, port: int, protocol: str = "TCP", description: str = "AZZAZEL VPN") -> bool:
        """Solicita al router abrir y redirigir el puerto automáticamente hacia este PC."""
        if not self.control_url or not self.service_type:
            if not self.discover():
                return False

        proto = protocol.upper()
        local_ip = self.local_ip or "127.0.0.1"

        soap_body = (
            f'<?xml version="1.0"?>'
            f'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            f'<s:Body>'
            f'<u:AddPortMapping xmlns:u="{self.service_type}">'
            f'<NewRemoteHost></NewRemoteHost>'
            f'<NewExternalPort>{port}</NewExternalPort>'
            f'<NewProtocol>{proto}</NewProtocol>'
            f'<NewInternalPort>{port}</NewInternalPort>'
            f'<NewInternalClient>{local_ip}</NewInternalClient>'
            f'<NewEnabled>1</NewEnabled>'
            f'<NewPortMappingDescription>{description}</NewPortMappingDescription>'
            f'<NewLeaseDuration>0</NewLeaseDuration>'
            f'</u:AddPortMapping>'
            f'</s:Body>'
            f'</s:Envelope>'
        )

        headers = {
            "SOAPAction": f'"{self.service_type}#AddPortMapping"',
            "Content-Type": 'text/xml; charset="utf-8"',
        }

        try:
            req = urllib.request.Request(self.control_url, data=soap_body.encode("utf-8"), headers=headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status in (200, 204):
                    _log.success("Puerto %d/%s abierto automáticamente en el router vía UPnP.", port, proto)
                    return True
        except Exception as exc:
            _log.debug("Fallo al mapear puerto vía UPnP: %s", exc)
        return False
