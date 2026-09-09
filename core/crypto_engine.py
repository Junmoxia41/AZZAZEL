#!/usr/bin/env python3
"""
AZZAZEL VPN — core/crypto_engine.py
===================================

Motor criptográfico del proyecto. Protege las credenciales del
``config.yaml`` (proxy corporativo, tokens, claves privadas) y expone
la API que reutilizan los módulos vpn/tunnel/bridge.

Diseño criptográfico (decisiones tomadas y por qué):

- **AES-256-GCM** (``cryptography.hazmat.primitives.ciphers.aead``):
  cifrado autenticado (AEAD). El *tag* GCM actúa como MAC: cualquier
  token manipulado se rechaza con :class:`InvalidToken` antes de
  descifrar nada. Confidencialidad + integridad en una primitiva
  estándar, revisada y veloz (AES-NI).
- **Nonce aleatorio de 96 bits por cifrado** (regla de oro de GCM:
  jamás reusar nonce con la misma clave). Se antepone al token —
  no es secreto, solo debe ser único.
- **Scrypt como KDF** para derivar la clave maestra desde una
  contraseña humana (parámetros RFC 7914: N=2^14, r=8, p=1). La clave
  resultante queda cacheada en la instancia: el coste de derivación se
  paga una sola vez por proceso.
- **Clave de máquina** para el modo daemon sin interacción: 32 bytes
  aleatorios en ``data/.azzazel.key`` con permisos ``0600``.
- **AAD (Associated Data)** opcional en toda la API: ata el texto
  cifrado a su contexto (p. ej. ``aad="proxy.upstream.password"``), de
  modo que un token no sea válido si se mueve de campo o de archivo.

Formato del token textual (el que verás en config.yaml tras
``ENC[AES-256-GCM]:``)::

    urlsafe_b64( nonce(12B) ‖ ciphertext ‖ tag(16B) )

Uso básico::

    from core.crypto_engine import CryptoEngine

    engine = CryptoEngine.for_machine("data")          # daemon / PC
    token = engine.encrypt_str("S3cr3to!")
    assert engine.decrypt_str(token) == "S3cr3to!"

    engine_cli = CryptoEngine.for_password(             # wizard --setup
        "mi-clave-maestra",
        salt=CryptoEngine.load_salt("data/.azzazel.salt"),
    )

Integración con la configuración (ya implementada en el paso 4)::

    cm = ConfigManager("config.yaml", crypto=CryptoEngine.for_machine("data"))

Demo autocontenida::

    python core/crypto_engine.py
"""

from __future__ import annotations

import base64
import binascii
import hmac
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Optional, Union

# Permite ejecutar este archivo directamente como script (demo standalone).
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.logger import get_logger

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    _CRYPTO_OK = True
except ImportError:  # pragma: no cover
    _CRYPTO_OK = False

__all__ = [
    "KEY_SIZE",
    "NONCE_SIZE",
    "SALT_SIZE",
    "CryptoError",
    "InvalidToken",
    "KeyManagementError",
    "CryptoEngine",
    "generate_key",
    "random_token",
    "generate_pin",
    "secure_compare",
    "derive_key_scrypt",
]

_log = get_logger("core.crypto")

# ---------------------------------------------------------------------------
# Constantes criptográficas
# ---------------------------------------------------------------------------
KEY_SIZE: int = 32        # AES-256
NONCE_SIZE: int = 12      # 96 bits, tamaño recomendado para GCM
SALT_SIZE: int = 16       # 128 bits para el KDF
TAG_SIZE: int = 16        # tag GCM (lo gestiona internamente AESGCM)
# Blob mínimo válido: nonce + tag (un plaintext vacío cifra a 0 bytes de
# ciphertext, por eso NO se suma 1; verificado por la batería de tests).
MIN_TOKEN_BYTES: int = NONCE_SIZE + TAG_SIZE

# Parámetros Scrypt (RFC 7914, perfil "interactivo": ~0.1-0.3 s por derivación)
_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1

MACHINE_KEY_FILENAME = ".azzazel.key"
SALT_FILENAME = ".azzazel.salt"


# ---------------------------------------------------------------------------
# Excepciones
# ---------------------------------------------------------------------------
class CryptoError(Exception):
    """Error base del motor criptográfico."""


class InvalidToken(CryptoError):
    """Token malformado, manipulado o con clave/AAD incorrectos."""


class KeyManagementError(CryptoError):
    """Problema con el material de claves (fichero, permisos, longitud)."""


# ---------------------------------------------------------------------------
# Utilidades de nivel módulo
# ---------------------------------------------------------------------------
def _require_crypto() -> None:
    if not _CRYPTO_OK:  # pragma: no cover
        raise CryptoError(
            "Falta la dependencia 'cryptography'. "
            "Ejecuta: pip install cryptography"
        )


def generate_key(length: int = KEY_SIZE) -> bytes:
    """Genera una clave simétrica aleatoria de 256 bits (CSPRNG)."""
    return secrets.token_bytes(length)


def random_token(nbytes: int = 32) -> str:
    """Token aleatorio URL-safe (útil para API tokens, ids de sesión)."""
    return secrets.token_urlsafe(max(1, nbytes))


def generate_pin(length: int = 6) -> str:
    """PIN numérico aleatorio CSPRNG (emparejamiento de dispositivos)."""
    length = max(4, min(length, 12))
    return "".join(secrets.choice("0123456789") for _ in range(length))


def secure_compare(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    """Comparación en tiempo constante (anti timing attacks).

    Usar para verificar PINs, tokens y hashes; nunca ``==`` (el tiempo
    de ``==`` filtra hasta qué punto la entrada coincide).
    """
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hmac.compare_digest(a, b)


def derive_key_scrypt(
    password: Union[str, bytes],
    salt: bytes,
    *,
    n: int = _SCRYPT_N,
    r: int = _SCRYPT_R,
    p: int = _SCRYPT_P,
) -> bytes:
    """Deriva una clave de 256 bits desde una contraseña con Scrypt.

    Args:
        password: Contraseña humana.
        salt: Sal aleatoria de :data:`SALT_SIZE` bytes (única por usuario).
        n/r/p: Parámetros de coste Scrypt.

    Returns:
        Clave binaria de 32 bytes lista para AES-256.
    """
    _require_crypto()
    if isinstance(password, str):
        password = password.encode("utf-8")
    kdf = Scrypt(salt=salt, length=KEY_SIZE, n=n, r=r, p=p)
    return kdf.derive(password)


# ---------------------------------------------------------------------------
# Motor principal
# ---------------------------------------------------------------------------
class CryptoEngine:
    """Motor AEAD AES-256-GCM con gestión de claves integrada.

    Implementa el protocolo ``CryptoService`` que consume
    :class:`core.config_manager.ConfigManager` (``encrypt_str`` /
    ``decrypt_str``), y añade APIs de bytes y archivos para el resto de
    módulos (túneles, transferencia de archivos, bridge).

    No instanciar directamente salvo en tests: usar las factorías
    :meth:`for_machine` (daemon, clave en disco) o :meth:`for_password`
    (interactivo, KDF desde contraseña maestra).
    """

    def __init__(self, key: bytes) -> None:
        """Inicializa el motor con una clave cruda de 256 bits.

        Args:
            key: Exactamente :data:`KEY_SIZE` bytes aleatorios.

        Raises:
            KeyManagementError: Longitud de clave incorrecta.
        """
        _require_crypto()
        if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_SIZE:
            raise KeyManagementError(
                f"La clave debe tener {KEY_SIZE} bytes "
                f"(recibidos: {len(key) if isinstance(key, (bytes, bytearray)) else 'n/a'})"
            )
        self._aesgcm = AESGCM(bytes(key))
        self.salt: Optional[bytes] = None  # la fijan las factorías

    # -- Utilidades estáticas expuestas en la clase ------------------------

    @staticmethod
    def generate_pin(length: int = 6) -> str:
        """Genera un PIN numérico seguro de ``length`` dígitos."""
        return generate_pin(length)

    @staticmethod
    def random_token(length: int = 16) -> str:
        """Genera un token aleatorio URL-safe."""
        return random_token(length)

    @staticmethod
    def secure_compare(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
        """Comparación en tiempo constante contra ataques de timing."""
        return secure_compare(a, b)

    @staticmethod
    def generate_key(length: int = KEY_SIZE) -> bytes:
        """Genera una clave aleatoria de ``length`` bytes."""
        return generate_key(length)

    # -- Factorías ---------------------------------------------------------

    @classmethod
    def for_machine(cls, key_dir: str | Path = "data") -> "CryptoEngine":
        """Motor con clave de máquina persistente (modo daemon).

        Carga ``<key_dir>/.azzazel.key``; si no existe, la genera con
        permisos ``0600``. Si los permisos son más permisivos de lo
        debido (POSIX), emite un warning de seguridad.

        Args:
            key_dir: Directorio de datos donde vive la clave.

        Raises:
            KeyManagementError: Clave existente corrupta/ilegible.
        """
        key_path = Path(key_dir) / MACHINE_KEY_FILENAME
        key = cls._load_or_create_key_file(key_path)
        engine = cls(key)
        _log.debug("CryptoEngine inicializado con clave de máquina (%s).",
                   key_path)
        return engine

    @classmethod
    def for_password(
        cls,
        password: Union[str, bytes],
        salt: Optional[bytes] = None,
    ) -> "CryptoEngine":
        """Motor con clave derivada de una contraseña maestra.

        Args:
            password: Contraseña humana.
            salt: Sal de :data:`SALT_SIZE` bytes. Si es ``None`` se
                genera una nueva (persistirla con :meth:`save_salt` o
                los datos cifrados serán irrecuperables).

        Returns:
            Motor listo, con ``.salt`` fijado para su persistencia.
        """
        if salt is None:
            salt = secrets.token_bytes(SALT_SIZE)
        if len(salt) < SALT_SIZE:
            raise KeyManagementError(
                f"Sal demasiado corta: {len(salt)}B (mínimo {SALT_SIZE}B)."
            )
        started = time.monotonic()
        key = derive_key_scrypt(password, salt)
        elapsed_ms = (time.monotonic() - started) * 1000
        _log.debug("Derivación Scrypt completada en %.0f ms.", elapsed_ms)
        engine = cls(key)
        engine.salt = salt
        return engine

    # -- Persistencia de sal ------------------------------------------------

    @staticmethod
    def save_salt(path: str | Path, salt: bytes) -> Path:
        """Guarda la sal del KDF (no es secreta, pero debe persistir)."""
        key_path = Path(path)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_bytes(salt)
        _restrict_permissions(key_path)
        return key_path

    @staticmethod
    def load_salt(path: str | Path) -> bytes:
        """Carga una sal previamente guardada con :meth:`save_salt`."""
        key_path = Path(path)
        try:
            salt = key_path.read_bytes()
        except OSError as exc:
            raise KeyManagementError(
                f"No se pudo leer la sal de '{key_path}': {exc}"
            ) from exc
        if len(salt) < SALT_SIZE:
            raise KeyManagementError(
                f"Sal corrupta en '{key_path}' ({len(salt)}B)."
            )
        return salt

    # -- API de bytes --------------------------------------------------------

    def encrypt_bytes(self, data: bytes, aad: Optional[bytes] = None) -> bytes:
        """Cifra bytes → ``nonce ‖ ciphertext ‖ tag``.

        Args:
            data: Datos en claro.
            aad: Datos asociados (contexto autenticado, no cifrado).

        Returns:
            Blob binario opaco, ~28 bytes más largo que la entrada.
        """
        nonce = secrets.token_bytes(NONCE_SIZE)
        ciphertext = self._aesgcm.encrypt(nonce, data, aad)
        return nonce + ciphertext

    def decrypt_bytes(self, blob: bytes, aad: Optional[bytes] = None) -> bytes:
        """Descifra un blob producido por :meth:`encrypt_bytes`.

        Raises:
            InvalidToken: Blob corto, tag inválido (manipulación) o
                AAD/clave incorrectos.
        """
        if len(blob) < MIN_TOKEN_BYTES:
            raise InvalidToken(
                f"Blob demasiado corto ({len(blob)}B; mínimo {MIN_TOKEN_BYTES}B)."
            )
        nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
        try:
            return self._aesgcm.decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise InvalidToken(
                "Autenticación fallida: blob manipulado o clave/AAD incorrectos."
            ) from exc

    # -- API de strings (contrato CryptoService de config_manager) ----------

    def encrypt_str(self, plaintext: str, aad: Optional[str] = None) -> str:
        """Cifra una cadena → token texto URL-safe (para config.yaml)."""
        aad_b = aad.encode("utf-8") if aad is not None else None
        blob = self.encrypt_bytes(plaintext.encode("utf-8"), aad=aad_b)
        return base64.urlsafe_b64encode(blob).decode("ascii")

    def decrypt_str(self, token: str, aad: Optional[str] = None) -> str:
        """Descifra un token de :meth:`encrypt_str`.

        Raises:
            InvalidToken: Token no-base64, corto, manipulado o AAD/clave
                incorrectos.
            UnicodeDecodeError: El contenido descifrado no es UTF-8.
        """
        try:
            blob = base64.urlsafe_b64decode(token.encode("ascii"))
        except (binascii.Error, UnicodeEncodeError) as exc:
            raise InvalidToken("Token no es base64-url válido.") from exc
        aad_b = aad.encode("utf-8") if aad is not None else None
        return self.decrypt_bytes(blob, aad=aad_b).decode("utf-8")

    # -- API de archivos ------------------------------------------------------

    def encrypt_file(
        self,
        src: str | Path,
        dst: Optional[str | Path] = None,
        aad: Optional[str] = None,
    ) -> Path:
        """Cifra un archivo completo (sec. encrypt <file> de la CLI).

        Args:
            src: Archivo origen en claro.
            dst: Destino (por defecto ``<src>.azz``).
            aad: Contexto autenticado opcional.

        Returns:
            Ruta del archivo cifrado.
        """
        src_p, dst_p = Path(src), Path(dst) if dst else Path(f"{src}.azz")
        plaintext = src_p.read_bytes()
        aad_b = aad.encode("utf-8") if aad else None
        dst_p.write_bytes(self.encrypt_bytes(plaintext, aad=aad_b))
        _restrict_permissions(dst_p)
        _log.info("Archivo cifrado: %s → %s (%d B).",
                  src_p, dst_p, len(plaintext))
        return dst_p

    def decrypt_file(
        self,
        src: str | Path,
        dst: Optional[str | Path] = None,
        aad: Optional[str] = None,
    ) -> Path:
        """Descifra un archivo de :meth:`encrypt_file`.

        Raises:
            InvalidToken: Archivo manipulado o clave/AAD incorrectos.
        """
        src_p = Path(src)
        dst_p = Path(dst) if dst else src_p.with_suffix("")
        blob = src_p.read_bytes()
        aad_b = aad.encode("utf-8") if aad else None
        plaintext = self.decrypt_bytes(blob, aad=aad_b)
        dst_p.write_bytes(plaintext)
        _log.info("Archivo descifrado: %s → %s.", src_p, dst_p)
        return dst_p

    # -- Rotación de clave de máquina ------------------------------------------

    def rotate_machine_key(
        self, key_dir: str | Path = "data"
    ) -> "CryptoEngine":
        """Genera una NUEVA clave de máquina y devuelve el nuevo motor.

        La clave anterior se respalda como ``.azzazel.key.old.<ts>``
        (0600) por si hay datos pendientes de migrar. Los tokens
        cifrados antes de rotar dejan de ser descifrables: el flujo
        correcto es descifrar todo con el motor viejo, rotar y volver a
        cifrar (``ConfigManager.save`` lo hace automáticamente si
        mantiene los secretos en memoria).
        """
        key_path = Path(key_dir) / MACHINE_KEY_FILENAME
        if key_path.exists():
            backup = key_path.with_name(
                f"{key_path.name}.old.{int(time.time())}"
            )
            try:
                os.replace(key_path, backup)
                _restrict_permissions(backup)
                _log.info("Clave anterior respaldada en %s.", backup)
            except OSError as exc:
                raise KeyManagementError(
                    f"No se pudo respaldar la clave anterior: {exc}"
                ) from exc
        return CryptoEngine.for_machine(key_dir)

    # -- Internos ---------------------------------------------------------------

    @staticmethod
    def _load_or_create_key_file(key_path: Path) -> bytes:
        """Carga la clave de máquina (hex) o la crea con 0600."""
        if key_path.exists():
            _warn_if_permissive(key_path)
            try:
                key = bytes.fromhex(key_path.read_text().strip())
            except (OSError, ValueError) as exc:
                raise KeyManagementError(
                    f"Clave de máquina corrupta en '{key_path}': {exc}. "
                    f"Rescátala o bórrala para regenerar (perderás los "
                    f"secretos cifrados con ella)."
                ) from exc
            if len(key) != KEY_SIZE:
                raise KeyManagementError(
                    f"Clave de máquina inválida: {len(key)}B "
                    f"(esperados {KEY_SIZE}B)."
                )
            return key

        key = generate_key()
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_text(key.hex(), encoding="ascii")
        _restrict_permissions(key_path)
        _log.info("Clave de máquina generada en %s (0600).", key_path)
        return key


# ---------------------------------------------------------------------------
# Permisos (POSIX estricto; Windows best-effort)
# ---------------------------------------------------------------------------
def _restrict_permissions(path: Path, mode: int = 0o600) -> None:
    """Aplica permisos restrictivos al archivo (rw solo para el dueño)."""
    try:
        os.chmod(path, mode)
    except OSError as exc:  # Windows y FS exóticos: avisar, no fallar
        _log.warning("No se pudieron fijar permisos %o en %s: %s",
                     mode, path, exc)


def _warn_if_permissive(path: Path) -> None:
    """Avisa si el archivo de claves es legible por otros (POSIX)."""
    if os.name != "posix":
        return
    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        return
    if mode & 0o077:
        _log.warning(
            "SEGURIDAD: %s tiene permisos %o; debería ser 600. "
            "Corrige con: chmod 600 %s", path, mode, path,
        )


# ---------------------------------------------------------------------------
# Demo standalone
# ---------------------------------------------------------------------------
def _demo() -> None:
    """Tour del motor: roundtrip, AAD, archivos, máquina vs password."""
    import tempfile

    tmp = Path(tempfile.mkdtemp(prefix="azz_crypto_demo_"))
    print("─ 1. Motor de máquina (persistente, 0600) ─")
    engine = CryptoEngine.for_machine(tmp)
    token = engine.encrypt_str("N0s3qu3n0$")
    print(f"    token = {token[:48]}…")
    assert engine.decrypt_str(token) == "N0s3qu3n0$"
    # La clave persiste: un motor nuevo (otro "proceso") descifra igual.
    assert CryptoEngine.for_machine(tmp).decrypt_str(token) == "N0s3qu3n0$"
    print("    ✔ roundtrip estable entre instancias (clave persistida)")

    print("─ 2. Motor por contraseña (Scrypt) ─")
    salt_bytes = secrets.token_bytes(SALT_SIZE)
    e1 = CryptoEngine.for_password("mi-clave-maestra", salt=salt_bytes)
    t2 = e1.encrypt_str("api-token-del-bridge")
    e2 = CryptoEngine.for_password("mi-clave-maestra", salt=salt_bytes)
    print(f"    ✔ misma password+misma sal → descifra: {e2.decrypt_str(t2)}")
    try:
        CryptoEngine.for_password("password-incorrecta",
                                  salt=salt_bytes).decrypt_str(t2)
    except InvalidToken:
        print("    ✔ password incorrecta → InvalidToken (fallo cerrado)")

    print("─ 3. AAD: el token queda atado a su contexto ─")
    t3 = engine.encrypt_str("secreto", aad="proxy.upstream.password")
    try:
        engine.decrypt_str(t3, aad="otro.campo")
    except InvalidToken:
        print("    ✔ mover el token a otro campo → InvalidToken")

    print("─ 4. Archivos ─")
    secret_file = tmp / "notas.txt"
    secret_file.write_text("Puertos: 51820/udp, 9999/tcp", encoding="utf-8")
    enc = engine.encrypt_file(secret_file)
    back = engine.decrypt_file(enc, dst=tmp / "notas_ok.txt")
    print(f"    ✔ {enc.name} → {back.name} idéntico: "
          f"{back.read_text() == secret_file.read_text()}")

    print("─ 5. Utilidades ─")
    print(f"    generate_pin()  → {generate_pin()}  "
          f"(compare seguro: {secure_compare('847291', '847291')})")
    print(f"    random_token()  → {random_token(12)}")
    print("─ demo OK ─")


if __name__ == "__main__":
    _demo()
