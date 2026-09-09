"""
AZZAZEL tests/test_upstream_proxy.py — Batería de pruebas de UpstreamProxyClient.
"""
import asyncio
import socket
import threading
import pytest
from proxy.upstream_proxy import (
    UpstreamProxyClient,
    UpstreamError,
    ProxyAuthError,
)


@pytest.mark.anyio
async def test_upstream_proxy_http_connect():
    # Echo destination
    echo_srv = await asyncio.start_server(
        lambda r, w: (w.write(b"DEST_REACHED"), w.close()),
        "127.0.0.1", 0
    )
    dest_port = echo_srv.sockets[0].getsockname()[1]

    # Proxy HTTP CONNECT server
    async def fake_proxy(reader, writer):
        req = await reader.read(1024)
        if b"CONNECT" in req:
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            r2, w2 = await asyncio.open_connection("127.0.0.1", dest_port)
            chunk = await r2.read(64)
            writer.write(chunk)
            await writer.drain()
            w2.close()
        writer.close()

    proxy_srv = await asyncio.start_server(fake_proxy, "127.0.0.1", 0)
    proxy_port = proxy_srv.sockets[0].getsockname()[1]

    async with echo_srv, proxy_srv:
        client = UpstreamProxyClient(
            host="127.0.0.1",
            port=proxy_port,
            auth_type="basic",
            username="testuser",
            password="testpass",
        )
        reader, writer = await client.open_connect_tunnel("127.0.0.1", dest_port)
        data = await reader.read(64)
        writer.close()
        assert data == b"DEST_REACHED"


@pytest.mark.anyio
async def test_upstream_proxy_auth_failure():
    async def fake_407_proxy(reader, writer):
        await reader.read(1024)
        writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n")
        await writer.drain()
        writer.close()

    proxy_srv = await asyncio.start_server(fake_407_proxy, "127.0.0.1", 0)
    proxy_port = proxy_srv.sockets[0].getsockname()[1]

    async with proxy_srv:
        client = UpstreamProxyClient(
            host="127.0.0.1",
            port=proxy_port,
            auth_type="basic",
            username="testuser",
            password="badpassword",
        )
        with pytest.raises((ProxyAuthError, UpstreamError)):
            await client.open_connect_tunnel("127.0.0.1", 80)
