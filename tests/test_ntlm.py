"""
AZZAZEL tests/test_ntlm.py — Batería de pruebas de NTLMv2 nativo y MD4.
"""
from security.ntlm import (
    MD4,
    hmac_md5,
    split_credentials,
    build_type1,
    parse_type2,
    build_type3,
    NtlmChallenge,
)


def test_md4_test_vectors():
    # Vectores RFC 1320
    assert MD4(b"").hexdigest() == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert MD4(b"a").hexdigest() == "bde52cb31de33e46245e05fbdbd6fb24"
    assert MD4(b"abc").hexdigest() == "a448017aaf21d8525fc10ae87aa6729d"
    assert MD4(b"message digest").hexdigest() == "d9130a8164549fe818874806e1c7014b"


def test_hmac_md5():
    # Vector RFC 2202 test case 1
    key = b"\x0b" * 16
    data = b"Hi There"
    digest = hmac_md5(key, data).hex()
    assert digest == "9294727a3638bb1c13f48ef8158bfc9d"


def test_split_credentials():
    d, u = split_credentials("CORP\\alice")
    assert d == "CORP" and u == "alice"

    d, u = split_credentials("bob")
    assert d == "" and u == "bob"


def test_ntlm_type1_build():
    t1 = build_type1(domain="CORP", workstation="DEV01")
    assert isinstance(t1, bytes)
    assert t1.startswith(b"NTLMSSP\x00\x01\x00\x00\x00")


def test_ntlm_type2_parse_and_type3_build():
    # Crear un Type 2 sintético válido
    server_challenge = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    flags = 0x00028205
    raw_t2 = (
        b"NTLMSSP\x00\x02\x00\x00\x00"
        + b"\x00\x00\x00\x00\x30\x00\x00\x00"  # TargetName len 0
        + flags.to_bytes(4, "little")
        + server_challenge
        + b"\x00" * 8  # Context
        + b"\x00\x00\x00\x00\x30\x00\x00\x00"  # TargetInfo len 0
    )
    parsed_chal = parse_type2(raw_t2)
    assert parsed_chal.server_challenge == server_challenge

    # Generar Type 3
    t3 = build_type3(
        user="alice",
        password="Password123!",
        challenge=parsed_chal,
        domain="CORP",
    )
    assert isinstance(t3, bytes)
    assert t3.startswith(b"NTLMSSP\x00\x03\x00\x00\x00")
