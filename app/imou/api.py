"""Async Imou Life cloud client recovered from the Android application."""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import re
import secrets
import ssl
import string
import time
from base64 import b64decode, b64encode
from binascii import Error as BinasciiError
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Mapping, MutableMapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from functools import lru_cache
from hashlib import md5, sha256
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4
from xml.etree import ElementTree

from .const import (
    APP_ID,
    APP_VERSION,
    ENTRY_HOST,
    PC_ENTRY_HOST,
    PC_ENTRY_HOST_FALLBACK,
    PROJECT_ID,
    PROTOCOL_VERSION,
    PTZ_MOVE_API,
    PTZ_MOVE_REVISION,
    PTZ_NO_AUTHORITY_CODES,
    PTZ_STEP_DURATION_MS,
    SIGNATURE_REVISION,
)
from .models import (
    ImouDevice,
    _api_identifier,
    as_bool,
    device_from_api,
    stream_entry_host,
)

_LOGGER = logging.getLogger(__name__)

SUCCESS_CODES = frozenset({1000, 10000})
AUTH_ERROR_CODES = frozenset({401, 403, 1003, 2001, 2002, 2005, 2007, 2101})
QR_LOGIN_REQUIRED_CODE = 12114
TWO_STEP_REQUIRED_CODES = frozenset({12112, 12116})
IMAGE_CAPTCHA_CODES = frozenset({2026, 2032, 9000, 10007, 12110})
GEETEST_CAPTCHA_CODES = frozenset({2033, QR_LOGIN_REQUIRED_CODE})
CAPTCHA_CHALLENGE_CODES = IMAGE_CAPTCHA_CODES | GEETEST_CAPTCHA_CODES
CAPTCHA_REJECTED_CODE = 11010
LOGIN_REJECTED_CODE = 22001
PROPERTY_CONTROL_FALLBACK_CODES = frozenset({11001, 1201, 40999})
SERVICE_CONTROL_FALLBACK_CODES = frozenset({11001})
CAPTCHA_REVISION = SIGNATURE_REVISION
TWO_STEP_REVISION = SIGNATURE_REVISION
TWO_STEP_PROPAGATION_DELAYS = (1.0, 2.0, 4.0, 8.0, 15.0)
CAPTCHA_CONTENT_TYPE = "application/json; charset=utf-8"
GEETEST_CLIENT_VERSION = "1.8.11"
GEETEST_CLIENT_TYPE = "android"
GEETEST_PACKAGE_NAME = "com.mm.android.smartlifeiot"
GEETEST_APP_VERSION = "10.1.6"
GEETEST_BUILD = "500542"
GEETEST_ACCOUNT_KEY = "F9TtRyv7X89nM0vp2EKOjdKLFnjlrN9rENCRYPTKEY"
PUSH_APP_KEY = "456409247234"
PUSH_SYSTEM_TYPE = "1"
PUSH_TIME_FORMAT = "yyyy-MM-dd HH:mm:ss"
MAX_API_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_IMAGE_BYTES = 5 * 1024 * 1024
NONCE_ALPHABET = string.ascii_letters + string.digits
JSON_CONTENT_TYPE = "application/json"
GET_LOGIN_QR_REVISION = "138591"
QUERY_LOGIN_QR_REVISION = "137573"
GET_TOKEN_REVISION = "185606"
LOGIN_REVISION = "198828"
LATEST_ALARM_REVISION = "193687"
LEGACY_LATEST_ALARM_REVISION = "3421"
IOT_CONTROL_TIMEOUT_MS = 10000
IOT_STREAM_TIMEOUT_MS = 20000
# How long a live mode whose links did not play is tried last.
LIVE_MODE_REJECT_TTL = 600.0
IOT_CONTROL_QOS = 1
OEM_CONFIG_PREFIX = "CFGENC"
OEM_CONFIG_KEY = b"1234567890abcdef1234567890abcdef"
OEM_CONFIG_NONCE = b"lc-nonce-v12"
OEM_CONFIG_PATH = Path(__file__).with_name("resources") / "oem_config_server.xml"
PC_APP_ID = "easy4ipbasepc"
PC_APP_VERSION = "5.18.9"
PC_PROTOCOL_VERSION = "V9.7.0"
PC_CREDENTIAL_KEY_SOURCE = b"DAHUAKEY"
PC_CREDENTIAL_IV = b"0a52uuEvqlOLc5TO"
PC_ACCESS_KEY_CIPHERTEXT = "di5QIaPmqzsJj8bHZGBpEltbA5DB2r2qHp3nGIGm+A0="
PC_SECRET_KEY_CIPHERTEXT = (
    "NYIxvivnzi+4lktdrD2+pqp5I9X5elYJDzFx+47AhHjF5SKU5Gm16UQSFCaWuYFI"
)
_DEFAULT_LANGUAGE_COUNTRIES = {
    "ar": "SA",
    "cs": "CZ",
    "da": "DK",
    "de": "DE",
    "en": "US",
    "es": "ES",
    "fi": "FI",
    "fil": "PH",
    "fr": "FR",
    "id": "ID",
    "it": "IT",
    "ja": "JP",
    "ko": "KR",
    "nb": "NO",
    "nl": "NL",
    "pl": "PL",
    "pt": "BR",
    "ru": "RU",
    "sv": "SE",
    "th": "TH",
    "tr": "TR",
    "uk": "UA",
    "vi": "VN",
    "zh": "CN",
}

_IOT_CONTROL_APIS = {
    "GetProperties": "GetIotProperties",
    "SetProperties": "SetIotProperties",
    "SetService": "SetIotService",
}
_NON_REPLAYABLE_APIS = frozenset(
    {
        PTZ_MOVE_API,
        "iot.control.SetProperties",
        "iot.control.SetIotProperties",
        "iot.control.SetService",
        "iot.control.SetIotService",
        "iot.smart.SetProperties",
        "iot.smart.SetService",
        "user.push.SetClientPushConfig",
        "user.account.GrantingCredit",
        "common.validcode.GetValidCode",
        "common.validcode.CheckGeeTest4",
        "common.validcode.CheckImageValidCode",
    }
)
_LIVE_RESPONSE_KEYS = frozenset(
    {
        "flvurl",
        "hlsurl",
        "liveurl",
        "resource",
        "rtspurl",
        "streamurl",
        "tlsresource",
        "ipv6resource",
        "ipv6tlsresource",
        "quicresource",
        "quictlsresource",
        "internalresource",
        "url",
    }
)
_STREAM_SERVICE_NAME = "cm_getRealTransferStreamUrl"
_STREAM_SERVICE_REF = "96500"
_STREAM_INPUT_REFS = {
    "assistStream": "96501",
    "audioType": "96502",
    "design": "96503",
    "encrypt": "96504",
    "imageSize": "96505",
    "owner": "96506",
    "ownerType": "96507",
    "skipAuth": "96508",
    "streamId": "96509",
    "timeLimit": "96510",
    "type": "96511",
    "videoLimit": "96512",
    "windowNum": "96513",
    "mixNum": "96514",
    "openId": "96515",
    "subUid": "96516",
    "quic": "96517",
    "bindDid": "96518",
    "bindPid": "96519",
    "bindCid": "96520",
}
_STREAM_OUTPUT_REFS = {
    "96521": "resource",
    "96522": "internalResource",
    "96523": "tlsResource",
    "96524": "region",
    "96525": "quicResource",
    "96526": "quicInternalResource",
    "96527": "ipv6Resource",
    "96528": "ipv6TlsResource",
    "96529": "ipv6QuicResource",
}

MqttRequestCallback = Callable[
    [str, Mapping[str, Any], int], Awaitable[Mapping[str, Any]]
]


class ImouApiError(Exception):
    """Base Imou API exception."""

    def __init__(self, message: str, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code


class ImouAuthError(ImouApiError):
    """Authentication failed or expired."""


class ImouCredentialError(ImouAuthError):
    """GetToken accepted the request but rejected account/password."""

    def __init__(self, fail_num: Any) -> None:
        failure_count = _response_code(fail_num)
        if failure_count is not None and failure_count < 0:
            failure_count = None
        self.failure_count = failure_count
        detail = (
            f" (failNum={failure_count})" if failure_count is not None else ""
        )
        super().__init__(f"Account/password rejected{detail}", LOGIN_REJECTED_CODE)


class ImouQrLoginRequired(ImouAuthError):
    """The password login requires authorization from Imou Life."""


class ImouTwoStepVerificationRequired(ImouAuthError):
    """The account requires a one-time code before this terminal can log in."""


class ImouCaptchaRequired(ImouQrLoginRequired):
    """The password login requires a fresh visual CAPTCHA challenge."""

    def __init__(
        self,
        message: str,
        code: int,
        challenge: ImouCaptchaChallenge,
    ) -> None:
        super().__init__(message, code)
        self.challenge = challenge


class ImouConnectionError(ImouApiError):
    """The cloud could not be reached or returned invalid transport data."""


class ImouMqttUnavailable(ImouConnectionError):
    """The APK-compatible Imou MQTT transport is not currently available."""


class _ImouLegacyEndpointUnavailable(ImouApiError):
    """The legacy device-list endpoint is not served by this regional host."""


_LEGACY_DEVICE_LIST_API = "things.model.DeviceListPageGet"
_LEGACY_DISCOVERY_RETRY_SECONDS = 3600
_LEGACY_DISCOVERY_CACHE_SIZE = 16


@dataclass(slots=True)
class ImouCredentials:
    """Current signing credentials."""

    username: str = field(repr=False)
    secret: str = field(repr=False)
    sha256_secret: str = field(repr=False)
    session_id: str | None = field(default=None, repr=False)


@dataclass(slots=True, frozen=True)
class ImouMqttConfig:
    """MQTT connection values returned by Imou Login."""

    ssl_address: str
    tcp_address: str
    client_id: str
    identity: str
    secret: str
    client_ua: str
    clock_offset: float


@dataclass(slots=True, frozen=True)
class ImouCaptchaChallenge:
    """CAPTCHA parameters returned by Imou before account login."""

    mode: str
    usage: str = "Login"
    captcha_id: str = field(default="", repr=False)
    captcha_server: str = field(default="", repr=False)
    verify_token: str = field(default="", repr=False)
    captcha_metadata: str = field(default="", repr=False)
    base_url: str = field(default="", repr=False)
    client_ua: str = field(default="", repr=False)
    web_challenge: str = field(default_factory=lambda: str(uuid4()), repr=False)
    image: str = field(default="", repr=False)
    code_id: str = field(default="", repr=False)

    @property
    def is_image(self) -> bool:
        """Return whether this is the four-character image CAPTCHA."""
        return self.mode.casefold() in {"image", "imagevalidcode", "image_valid_code"}


@dataclass(slots=True, frozen=True)
class ImouQrLogin:
    """QR image and opaque code used to authorize this add-on."""

    image: str = field(repr=False)
    login_code: str = field(repr=False)
    status: str = "unscan"


@dataclass(slots=True, frozen=True)
class ImouQrLoginResult:
    """Current QR authorization status returned by Imou."""

    status: str
    username: str = field(default="", repr=False)
    token: str = field(default="", repr=False)
    session_id: str = field(default="", repr=False)
    entry_url: str = field(default="", repr=False)
    support_pc_auto_login: bool | None = None

    @property
    def credentials_ready(self) -> bool:
        """Return whether QueryLoginQRCode supplied complete token credentials."""
        return bool(self.username and self.token and self.session_id)


def compact_json(value: Any) -> str:
    """Serialize exactly as the Android SDK signs it."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def content_md5(body: bytes) -> str:
    """Return the standard Base64 MD5 used by x-pcs."""
    return b64encode(md5(body).digest()).decode("ascii")


def content_sha256(body: bytes) -> str:
    """Return the Base64 SHA-256 used by current x-pcs clients."""
    return b64encode(sha256(body).digest()).decode("ascii")


def normalize_login_account(account: str) -> tuple[str, str]:
    """Normalize an Imou account and infer the dialing code when safe."""
    normalized = account.strip().replace(" ", "")
    international_prefix = next(
        (prefix for prefix in ("+84", "0084", "84") if normalized.startswith(prefix)),
        "",
    )
    if international_prefix:
        national_number = normalized[len(international_prefix) :].lstrip("0")
        if len(national_number) == 9 and national_number.isdigit():
            return f"0{national_number}", "84"
    if (
        len(normalized) == 10
        and normalized.isdigit()
        and normalized.startswith(("03", "05", "07", "08", "09"))
    ):
        return normalized, "84"
    return normalized, ""


def _build_account_credentials(account: str, password: str) -> ImouCredentials:
    """Apply both password hashing stages used by Imou Life and its SDK."""
    password_md5 = md5(password.encode()).hexdigest()
    password_sha256 = sha256(password.encode()).hexdigest()
    return ImouCredentials(
        f"account\\{account}",
        md5(password_md5.encode()).hexdigest(),
        sha256(password_sha256.encode()).hexdigest(),
    )


def encrypt_captcha_account(account: str, *, iv: bytes | None = None) -> str:
    """Encrypt an account exactly like Imou Life's secure-v1 provider."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as err:
        raise ImouConnectionError("Cryptography support is missing") from err
    nonce = os.urandom(12) if iv is None else iv
    if len(nonce) != 12:
        raise ValueError("CAPTCHA AES-GCM IV must contain 12 bytes")
    key = sha256(GEETEST_ACCOUNT_KEY.encode()).digest()
    ciphertext = AESGCM(key).encrypt(nonce, account.encode(), None)
    return b64encode(nonce + ciphertext).decode("ascii")


def encrypt_two_step_account(account: str, *, iv: bytes | None = None) -> str:
    """Encrypt GrantingCredit accounts like the APK secure-v1 provider."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as err:
        raise ImouConnectionError("Cryptography support is missing") from err
    nonce = os.urandom(12) if iv is None else iv
    if len(nonce) != 12:
        raise ValueError("Two-step AES-GCM IV must contain 12 bytes")
    key = sha256(GEETEST_ACCOUNT_KEY.encode()).digest()
    ciphertext = AESGCM(key).encrypt(nonce, account.encode(), None)
    return b64encode(nonce + ciphertext).decode("ascii")


def _mapping_from_json_value(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if not isinstance(value, str) or not value.strip().startswith(("{", "[")):
        return None
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        return None
    return decoded if isinstance(decoded, Mapping) else None


def _mapping_text(value: Mapping[str, Any], *keys: str) -> str:
    normalized = {str(key).casefold(): item for key, item in value.items()}
    for key in keys:
        item = normalized.get(key.casefold())
        if item not in (None, ""):
            return str(item).strip()
    return ""


@lru_cache(maxsize=1)
def _load_default_app_credentials() -> ImouCredentials:
    """Recover the APK's default request credentials from its OEM config."""
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as err:
        raise ImouConnectionError("Cryptography support is missing") from err
    try:
        encrypted = OEM_CONFIG_PATH.read_text(encoding="utf-8").strip()
        if not encrypted.startswith(OEM_CONFIG_PREFIX):
            raise ValueError("missing encrypted OEM config prefix")
        plaintext = AESGCM(OEM_CONFIG_KEY).decrypt(
            OEM_CONFIG_NONCE,
            b64decode(encrypted[len(OEM_CONFIG_PREFIX) :], validate=True),
            None,
        )
        root = ElementTree.fromstring(plaintext)
    except (
        OSError,
        ValueError,
        BinasciiError,
        InvalidTag,
        ElementTree.ParseError,
    ) as err:
        raise ImouConnectionError(
            "Could not load Imou application credentials"
        ) from err

    values: dict[str, str] = {}
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        if tag in {"AK", "SK"} and element.text:
            values[tag] = element.text.strip()
    access_key = values.get("AK", "")
    secret_key = values.get("SK", "")
    if not access_key or not secret_key:
        raise ImouConnectionError("Imou application credentials are incomplete")
    return ImouCredentials(
        username=f"default\\{access_key}",
        secret=md5(secret_key.encode()).hexdigest(),
        sha256_secret=sha256(secret_key.encode()).hexdigest(),
    )


def _decrypt_pc_credential(ciphertext: str) -> str:
    """Decrypt an app credential embedded by the official Imou PC client."""
    try:
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        encrypted = b64decode(ciphertext, validate=True)
        key = md5(PC_CREDENTIAL_KEY_SOURCE).hexdigest().encode()
        decryptor = Cipher(
            algorithms.AES(key),
            modes.CBC(PC_CREDENTIAL_IV),
        ).decryptor()
        padded = decryptor.update(encrypted) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
        value = plaintext.decode("ascii")
    except (BinasciiError, ImportError, UnicodeDecodeError, ValueError) as err:
        raise ImouConnectionError("Could not load Imou PC app credentials") from err
    if not value or any(character.isspace() for character in value):
        raise ImouConnectionError("Imou PC app credentials are incomplete")
    return value


@lru_cache(maxsize=1)
def _load_pc_app_credentials() -> ImouCredentials:
    """Load signing credentials used by the official Imou Life PC client."""
    access_key = _decrypt_pc_credential(PC_ACCESS_KEY_CIPHERTEXT)
    secret_key = _decrypt_pc_credential(PC_SECRET_KEY_CIPHERTEXT)
    return ImouCredentials(
        username=f"default\\{access_key}",
        secret=md5(secret_key.encode()).hexdigest(),
        sha256_secret=sha256(secret_key.encode()).hexdigest(),
    )


def build_client_ua(
    terminal_id: str,
    language: str = "en_US",
    *,
    client_type: str = "phone",
    client_os: str = "Android",
    client_ov: str = "13",
    terminal_model: str = "Home Assistant",
    terminal_brand: str = "Home Assistant",
    terminal_name: str = "Home Assistant",
    country: str = "",
    ttid: str | None = None,
    dark_mode: str = "light",
) -> str:
    """Build the ordered Android client-UA emitted by Imou Life's HTTP SDK."""
    language = normalize_language(language)
    client_version = APP_VERSION if APP_VERSION.startswith("V") else f"V{APP_VERSION}"
    normalized_client_ov = client_ov.strip()
    if normalized_client_ov and not normalized_client_ov.casefold().startswith(
        client_os.casefold()
    ):
        normalized_client_ov = f"{client_os} {normalized_client_ov}"
    payload = OrderedDict(
        (
            ("clientType", client_type),
            ("clientVersion", client_version),
            ("clientOV", normalized_client_ov),
            ("clientOS", client_os),
            ("terminalModel", terminal_model),
            ("terminalId", terminal_id),
            ("appid", APP_ID),
            ("project", PROJECT_ID),
            ("language", language),
            ("clientProtocolVersion", PROTOCOL_VERSION),
            ("timezoneOffset", str(_local_timezone_offset())),
            ("terminalBrand", terminal_brand),
            ("ttid", ttid or md5(f"ttid:{terminal_id}".encode()).hexdigest()),
        )
    )
    if terminal_name:
        payload["terminalName"] = terminal_name
    if country:
        payload["country"] = country.upper()
    payload["darkMode"] = dark_mode
    return b64encode(compact_json(payload).encode()).decode("ascii")


def build_pc_client_ua(
    terminal_id: str,
    language: str = "en_US",
    *,
    user_id: Any | None = None,
) -> str:
    """Build the client-UA used by the official Imou Life PC application."""
    language = normalize_language(language)
    pc_language = language.replace("-", "_").split("_", 1)[0] or "en"
    payload = OrderedDict(
        (
            ("clientType", "pc"),
            ("clientVersion", PC_APP_VERSION),
            ("clientOV", "10"),
            ("clientOS", "Windows"),
            ("terminalId", terminal_id),
            ("terminalModel", "Home Assistant Bridge"),
            ("appid", PC_APP_ID),
            ("project", PROJECT_ID),
            ("language", pc_language),
            ("clientProtocolVersion", PC_PROTOCOL_VERSION),
            ("timezoneOffset", str(_local_timezone_offset())),
        )
    )
    if user_id not in (None, ""):
        payload["userId"] = user_id
    return b64encode(compact_json(payload).encode()).decode("ascii")


def build_mqtt_client_ua(
    terminal_id: str,
    user_id: Any,
    language: str = "en_US",
) -> str:
    """Build the extended Base64 client-UA used by the Android MQTT loader."""
    language = normalize_language(language)
    payload = OrderedDict(
        (
            ("clientType", "phone"),
            ("clientVersion", APP_VERSION),
            ("clientOV", "13"),
            ("clientOS", "Android"),
            ("terminalModel", "Home Assistant"),
            ("terminalId", terminal_id),
            ("appid", APP_ID),
            ("project", PROJECT_ID),
            ("language", language),
            ("clientProtocolVersion", PROTOCOL_VERSION),
            ("ttid", md5(f"ttid:{terminal_id}".encode()).hexdigest()),
            ("userId", user_id),
            ("timezoneOffset", str(_local_timezone_offset())),
            ("terminalBrand", "Home Assistant"),
        )
    )
    return b64encode(compact_json(payload).encode()).decode("ascii")


def _local_timezone_offset() -> int:
    offset = datetime.now().astimezone().utcoffset()
    return int(offset.total_seconds()) if offset is not None else -time.timezone


def normalize_language(language: str) -> str:
    """Return the language_COUNTRY format emitted by the Android APK."""
    parts = [part for part in str(language or "").replace("-", "_").split("_") if part]
    if not parts:
        return "en_US"
    language_code = parts[0].casefold()
    if not language_code.isalpha() or len(language_code) not in {2, 3}:
        return "en_US"
    country = next(
        (
            part.upper()
            for part in reversed(parts[1:])
            if len(part) == 2 and part.isalpha()
        ),
        "",
    )
    if not country and language_code == "zh":
        scripts = {part.casefold() for part in parts[1:]}
        if "hant" in scripts:
            country = "TW"
        elif "hans" in scripts:
            country = "CN"
    country = country or _DEFAULT_LANGUAGE_COUNTRIES.get(language_code, "")
    return f"{language_code}_{country}" if country else "en_US"


def _client_country(language: str, area_code: str) -> str:
    """Return the APK client-UA country without exposing the login account."""
    if area_code == "84":
        return "VN"
    parts = normalize_language(language).split("_")
    if len(parts) > 1 and len(parts[-1]) == 2 and parts[-1].isalpha():
        return parts[-1].upper()
    return ""


def build_canonical_string(
    method: str,
    path: str,
    body_md5: str,
    content_type: str,
    revision: str,
    client_ua: str,
    date: str,
    nonce: str,
    username: str,
    session_id: str | None = None,
) -> str:
    """Build the exact newline-delimited x-pcs signing input."""
    canonical = (
        f"{method}\n{path}\n{body_md5}\n{content_type}\n"
        f"x-pcs-apiver:{revision}\n"
        f"x-pcs-client-ua:{client_ua}\n"
        f"x-pcs-date:{date}\n"
        f"x-pcs-nonce:{nonce}\n"
    )
    if session_id is not None:
        canonical += f"x-pcs-session-id:{session_id}\n"
    return canonical + f"x-pcs-username:{username}\n"


def sign_canonical(canonical: str, secret: str) -> str:
    """Sign a canonical request with HMAC-SHA256 and Base64."""
    digest = hmac.new(secret.encode(), canonical.encode(), "sha256").digest()
    return b64encode(digest).decode("ascii")


def _encode_iot_value(value: Any) -> Any:
    """Match the APK interceptor's thing-model value encoding."""
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, Mapping):
        return {str(key): _encode_iot_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_encode_iot_value(item) for item in value]
    return value


def _contains_live_url(value: Any, depth: int = 0) -> bool:
    """Return whether an API response contains a recognized live URL field."""
    if depth > 4:
        return False
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized_key = "".join(
                character
                for character in str(key).casefold()
                if character.isalnum()
            )
            if (
                normalized_key in _LIVE_RESPONSE_KEYS
                and isinstance(item, str)
                and item.strip()
            ):
                return True
            if isinstance(item, (Mapping, list, tuple)) and _contains_live_url(
                item, depth + 1
            ):
                return True
        return False
    if isinstance(value, (list, tuple)):
        return any(_contains_live_url(item, depth + 1) for item in value)
    return False


def _stream_url_is_playable(value: Any) -> bool:
    """Reject Imou's private RTSV transport URLs for Home Assistant."""
    if not isinstance(value, str):
        return False
    candidate = value.strip()
    if not candidate:
        return False
    parsed = urlparse(candidate)
    marker = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".casefold()
    if any(part in marker for part in ("rtsv1", "rtsv2", "lchttp")):
        return False
    return parsed.scheme.casefold() in {
        "http",
        "https",
        "rtmp",
        "rtmps",
        "rtsp",
        "rtsps",
    } and bool(parsed.netloc)


def _contains_playable_live_url(value: Any, depth: int = 0) -> bool:
    """Return whether a response contains a standard HA-compatible stream URL."""
    if depth > 5:
        return False
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized_key = "".join(
                character
                for character in str(key).casefold()
                if character.isalnum()
            )
            if (
                normalized_key in _LIVE_RESPONSE_KEYS
                and _stream_url_is_playable(item)
            ):
                return True
            if isinstance(item, (Mapping, list, tuple)) and _contains_playable_live_url(
                item, depth + 1
            ):
                return True
        return False
    if isinstance(value, (list, tuple)):
        return any(_contains_playable_live_url(item, depth + 1) for item in value)
    return False


def _numeric_channel_id(channel_id: str | int | None) -> int | None:
    """Match the APK wrapper's integer channelId serialization."""
    if channel_id in (None, ""):
        return None
    try:
        return int(str(channel_id).strip())
    except (TypeError, ValueError):
        return None


def _normalize_stream_service_value(
    value: Any,
    *,
    depth: int = 0,
) -> Any:
    if depth > 6:
        return value
    if isinstance(value, Mapping):
        normalized: dict[Any, Any] = {}
        for key, child in value.items():
            normalized_key: Any = _STREAM_OUTPUT_REFS.get(str(key), key)
            normalized[normalized_key] = _normalize_stream_service_value(
                child, depth=depth + 1
            )
        return normalized
    if isinstance(value, list):
        return [
            _normalize_stream_service_value(child, depth=depth + 1)
            for child in value[:128]
        ]
    if isinstance(value, tuple):
        return tuple(
            _normalize_stream_service_value(child, depth=depth + 1)
            for child in value[:128]
        )
    if isinstance(value, str):
        candidate = value.strip()
        if candidate.startswith(("{", "[")):
            try:
                decoded = json.loads(candidate)
            except json.JSONDecodeError:
                pass
            else:
                return _normalize_stream_service_value(decoded, depth=depth + 1)
    return value


def _normalize_stream_service_result(result: Mapping[str, Any]) -> dict[str, Any]:
    normalized = _normalize_stream_service_value(result)
    if not isinstance(normalized, dict):
        return dict(result)
    output_data = normalized.get("outputData")
    if isinstance(output_data, Mapping):
        for key, value in output_data.items():
            normalized.setdefault(key, value)
    return normalized


async def _read_bounded(content: Any, max_bytes: int) -> bytes:
    if max_bytes < 0:
        raise ValueError("max_bytes must not be negative")
    buffer = bytearray()
    while len(buffer) <= max_bytes:
        chunk = await content.read(min(64 * 1024, max_bytes + 1 - len(buffer)))
        if not chunk:
            break
        buffer.extend(chunk)
    return bytes(buffer)


def _response_code(value: Any) -> int | None:
    if isinstance(value, str):
        if len(value) > 32 or not re.fullmatch(r"[+-]?[0-9]{1,10}", value.strip()):
            return None
        value = int(value)
    if (
        isinstance(value, int)
        and not isinstance(value, bool)
        and -(2**31) <= value < 2**31
    ):
        return value
    return None


def _safe_error_detail(value: Any) -> str:
    """Return a short, single-line server message safe to log."""
    if not isinstance(value, str):
        return ""
    text = " ".join(value.split()).casefold()
    return text if text in {"", "no authority", "has no auth"} else "<redacted>"


@lru_cache(maxsize=1)
def _load_device_ssl_context() -> ssl.SSLContext:
    """Build a TLS context that also trusts Imou's private CA chain."""
    context = ssl.create_default_context()
    certificate_dir = Path(__file__).with_name("certificates")
    if certificate_dir.is_dir():
        for certificate in sorted(certificate_dir.glob("*.crt")):
            try:
                context.load_verify_locations(cafile=str(certificate))
            except ssl.SSLError:
                _LOGGER.debug("Could not load Imou CA %s", certificate.name)
    return context


async def _async_device_ssl_context() -> ssl.SSLContext:
    return await asyncio.to_thread(_load_device_ssl_context)


class ImouApiClient:
    """Bounded asynchronous client for the private Imou Life SaaS API."""

    def __init__(
        self,
        session: Any,
        account: str,
        password: str,
        terminal_id: str,
        *,
        request_timeout: float = 15,
        max_concurrent_requests: int = 4,
        language: str = "en_US",
    ) -> None:
        self._session = session
        self.account = account
        self._login_account, self._area_code = normalize_login_account(account)
        self._password = password.strip()
        self.terminal_id = terminal_id
        self.request_timeout = request_timeout
        self._semaphore = asyncio.Semaphore(max_concurrent_requests)
        self._login_lock = asyncio.Lock()
        self._base_url = self._normalize_base_url(ENTRY_HOST)
        self._qr_base_url = self._normalize_base_url(PC_ENTRY_HOST)
        self._credentials: ImouCredentials | None = None
        self._language = normalize_language(language)
        self._account_client_ua = build_client_ua(
            terminal_id,
            self._language,
            country=_client_country(self._language, self._area_code),
        )
        self._qr_client_ua = build_pc_client_ua(terminal_id, self._language)
        self._client_ua = self._account_client_ua
        self._using_pc_client = False
        self._clock_offset = 0.0
        self._auth_generation = 0
        self._logged_in = False
        self._mqtt_identity = ""
        self._mqtt_secret = ""
        self._mqtt_request: MqttRequestCallback | None = None
        self.user_info: dict[str, Any] = {}
        self._live_cache: dict[
            tuple[str, str, str, str], tuple[float, dict[str, Any]]
        ] = {}
        self._live_modes: dict[tuple[str, str, str, str], str] = {}
        self._live_diagnostics: dict[tuple[str, str, str, str], str] = {}
        self._live_rejected: dict[tuple[str, str, str, str], dict[str, float]] = {}
        self._latest_alarm_status = "not_requested"
        self._iot_control_modes: dict[tuple[str, str, str], str] = {}
        self._family_ids: tuple[str, ...] = ()
        self._family_cache_expires = 0.0
        self._legacy_discovery_retry_after: dict[str, float] = {}
        self._legacy_discovery_lock = asyncio.Lock()

    @staticmethod
    def _normalize_base_url(value: str) -> str:
        value = value.strip().rstrip("/")
        if not value.startswith(("http://", "https://")):
            value = f"https://{value}"
        try:
            parsed = urlparse(value)
            valid = bool(parsed.hostname)
        except ValueError:
            valid = False
        if not valid:
            raise ImouConnectionError("Invalid Imou entry URL") from None
        return value

    @property
    def authenticated(self) -> bool:
        """Return whether the full GetToken and Login flow completed."""
        return self._logged_in

    @property
    def auth_generation(self) -> int:
        """Return a counter that changes after every successful login."""
        return self._auth_generation

    @property
    def clock_offset(self) -> float:
        """Return the last measured Imou server clock offset in seconds."""
        return self._clock_offset

    def mqtt_config(self) -> ImouMqttConfig | None:
        """Return the recovered main MQTT configuration when Login supplied it."""
        mqtt_server = self.user_info.get("mqttServer")
        if not isinstance(mqtt_server, Mapping):
            return None
        ssl_address = str(mqtt_server.get("sslAddr") or "").strip()
        tcp_address = str(mqtt_server.get("tcpAddr") or "").strip()
        if not ssl_address and not tcp_address:
            return None
        if not self._mqtt_identity or not self._mqtt_secret:
            return None
        return ImouMqttConfig(
            ssl_address=ssl_address,
            tcp_address=tcp_address,
            client_id=f"{PROJECT_ID}{self.terminal_id}",
            identity=f"uuid\\{self._mqtt_identity}",
            secret=self._mqtt_secret,
            client_ua=(
                build_pc_client_ua(
                    self.terminal_id,
                    self._language,
                    user_id=self.user_info.get("userId", ""),
                )
                if self._using_pc_client
                else build_mqtt_client_ua(
                    self.terminal_id,
                    self.user_info.get("userId", ""),
                    self._language,
                )
            ),
            clock_offset=self._clock_offset,
        )

    def set_mqtt_request(self, callback: MqttRequestCallback | None) -> None:
        """Attach the live APK-compatible MQTT request transport."""
        self._mqtt_request = callback

    def _mark_legacy_discovery_unavailable(
        self, base_url: str
    ) -> _ImouLegacyEndpointUnavailable:
        now = time.monotonic()
        cache = self._legacy_discovery_retry_after
        cache[base_url] = now + _LEGACY_DISCOVERY_RETRY_SECONDS
        while len(cache) > _LEGACY_DISCOVERY_CACHE_SIZE:
            oldest = min(cache.items(), key=lambda item: item[1])[0]
            del cache[oldest]
        _LOGGER.debug(
            "Imou legacy device list unavailable api=%s host=%s "
            "retry_after_seconds=%s",
            _LEGACY_DEVICE_LIST_API,
            urlparse(base_url).hostname or base_url,
            _LEGACY_DISCOVERY_RETRY_SECONDS,
        )
        return _ImouLegacyEndpointUnavailable(
            "Imou legacy device list endpoint unavailable", 404
        )

    async def async_set_client_push_config(
        self,
        mqtt_client_id: str,
        *,
        client_push_id: str = "",
        enabled: bool = True,
    ) -> None:
        """Register this client so Imou pushes alarms over the MQTT channel."""
        if not mqtt_client_id:
            raise ValueError("MQTT push id is required")
        await self._request_with_retries(
            "user.push.SetClientPushConfig",
            SIGNATURE_REVISION,
            {
                "appKey": PUSH_APP_KEY,
                "clientPushId": client_push_id,
                "language": self._language,
                "mode": 0,
                "mqttPushId": mqtt_client_id,
                "sound": "",
                "systemPushType": PUSH_SYSTEM_TYPE,
                "timeFormat": PUSH_TIME_FORMAT,
                "timezoneOffset": _local_timezone_offset(),
                "pushStatus": "on" if enabled else "off",
            },
        )

    @classmethod
    def _captcha_challenge_from_data(
        cls,
        data: Any,
        code: int,
        *,
        usage: str,
        base_url: str,
        client_ua: str,
    ) -> ImouCaptchaChallenge:
        candidates: list[Mapping[str, Any]] = []

        def collect(value: Any, depth: int = 0) -> None:
            if depth > 3:
                return
            mapping = _mapping_from_json_value(value)
            if mapping is None:
                return
            candidates.append(mapping)
            normalized = {str(key).casefold(): item for key, item in mapping.items()}
            for key in ("captchadata", "captcha", "data"):
                nested = normalized.get(key)
                if nested is not None and nested is not value:
                    collect(nested, depth + 1)

        collect(data)

        def first(*keys: str) -> str:
            for candidate in candidates:
                value = _mapping_text(candidate, *keys)
                if value:
                    return value
            return ""

        mode = first("captchaMode", "captcha_mode", "mode")
        if not mode:
            mode = "geetest4" if code in GEETEST_CAPTCHA_CODES else "image"
        normalized_mode = mode.strip().casefold().replace("-", "").replace("_", "")
        if normalized_mode in {"geetest", "geetest4", "geelab", "gt4"}:
            mode = "geetest4"
        elif code in IMAGE_CAPTCHA_CODES or normalized_mode in {
            "image",
            "imagevalidcode",
        }:
            mode = "image"
        return ImouCaptchaChallenge(
            mode=mode,
            usage=usage,
            captcha_id=first("captchaId", "captcha_id"),
            captcha_server=first(
                "captchaServer",
                "captcha_server",
                "apiServer",
                "api_server",
            ),
            verify_token=first("verifyToken", "verify_token"),
            captcha_metadata=first("captchaMetaData", "captcha_metadata"),
            base_url=base_url,
            client_ua=client_ua,
        )

    def _captcha_usage_for_request(self, api_name: str, code: int) -> str:
        if api_name == "common.validcode.GetValidCode":
            if code in IMAGE_CAPTCHA_CODES:
                return (
                    "GetValidCodeToPhone"
                    if self._area_code
                    else "GetValidCodeToEmail"
                )
            return "GrantingCredit"
        if api_name == "user.account.GrantingCredit":
            return "GrantingCredit"
        return "Login"

    @staticmethod
    def _captcha_request_value(
        result: Mapping[str, Any],
        *keys: str,
        maximum: int,
    ) -> str:
        value = _mapping_text(result, *keys)
        if not value or len(value) > maximum:
            raise ValueError(f"Invalid CAPTCHA field: {keys[0]}")
        return value

    async def async_prepare_captcha(
        self, challenge: ImouCaptchaChallenge
    ) -> ImouCaptchaChallenge:
        """Load the image payload when Imou selected its legacy image CAPTCHA."""
        if not challenge.is_image:
            if not challenge.captcha_id or not challenge.captcha_server:
                raise ImouConnectionError(
                    "Imou did not return a complete GeeTest challenge"
                )
            if not challenge.verify_token:
                raise ImouConnectionError("Imou did not return a CAPTCHA verify token")
            return challenge
        response = await self._request_with_retries(
            "common.validcode.GetImageValidCode",
            CAPTCHA_REVISION,
            {"width": 150, "height": 50},
            content_type=CAPTCHA_CONTENT_TYPE,
            credentials=_load_default_app_credentials(),
            base_url=challenge.base_url or self._normalize_base_url(ENTRY_HOST),
            client_ua=self._account_client_ua,
        )
        code_id = _mapping_text(response, "codeId", "code_id")
        image = _mapping_text(response, "image")
        if not code_id or not image:
            raise ImouConnectionError("Imou returned an incomplete image CAPTCHA")
        return replace(
            challenge,
            mode="image",
            code_id=code_id,
            image=image,
            web_challenge=str(uuid4()),
        )

    async def async_validate_geetest(
        self,
        challenge: ImouCaptchaChallenge,
        result: Mapping[str, Any],
    ) -> None:
        """Validate the GeeTest4 result using the APK's default app signer."""
        if challenge.is_image:
            raise ValueError("The active CAPTCHA is not GeeTest4")
        lot_number = self._captcha_request_value(
            result, "lot_number", "lotNumber", maximum=2048
        )
        captcha_output = self._captcha_request_value(
            result, "captcha_output", "captchaOutput", maximum=16384
        )
        pass_token = self._captcha_request_value(
            result, "pass_token", "passToken", maximum=4096
        )
        gen_time = self._captcha_request_value(
            result, "gen_time", "genTime", maximum=128
        )
        captcha_id = self._captcha_request_value(
            result, "captcha_id", "captchaId", maximum=512
        )
        if challenge.captcha_id and captcha_id != challenge.captcha_id:
            raise ValueError("CAPTCHA result does not match the active challenge")
        await self._request_with_retries(
            "common.validcode.CheckGeeTest4",
            CAPTCHA_REVISION,
            {
                "lotNumber": lot_number,
                "captchaOutput": captcha_output,
                "passToken": pass_token,
                "genTime": gen_time,
                "account": encrypt_captcha_account(self._login_account),
                "usage": challenge.usage,
                "captchaId": captcha_id,
                "captchaMetaData": "",
                "verifyToken": challenge.verify_token,
                "isEncrypt": True,
            },
            content_type=CAPTCHA_CONTENT_TYPE,
            credentials=_load_default_app_credentials(),
            base_url=challenge.base_url or self._normalize_base_url(ENTRY_HOST),
            client_ua=self._account_client_ua,
        )

    async def async_validate_image_captcha(
        self,
        challenge: ImouCaptchaChallenge,
        code: str,
    ) -> None:
        """Validate the APK's four-character image CAPTCHA."""
        normalized_code = code.strip()
        if not challenge.is_image or not challenge.code_id:
            raise ValueError("The active CAPTCHA is not an image CAPTCHA")
        if len(normalized_code) != 4 or not normalized_code.isalnum():
            raise ValueError("CAPTCHA code must contain four letters or digits")
        await self._request_with_retries(
            "common.validcode.CheckImageValidCode",
            CAPTCHA_REVISION,
            {
                "codeId": challenge.code_id,
                "code": normalized_code,
                "usage": challenge.usage,
                "captchaMetaData": "",
                "captchaId": challenge.captcha_id,
                "verifyToken": challenge.verify_token,
            },
            content_type=CAPTCHA_CONTENT_TYPE,
            credentials=_load_default_app_credentials(),
            base_url=challenge.base_url or self._normalize_base_url(ENTRY_HOST),
            client_ua=self._account_client_ua,
        )

    async def async_request_two_step_code(self) -> dict[str, Any]:
        """Send the GrantingCredit one-time code used to trust this terminal."""
        account_type = "phone" if self._area_code else "email"
        return await self._request_with_retries(
            "common.validcode.GetValidCode",
            TWO_STEP_REVISION,
            {
                "type": account_type,
                "account": encrypt_two_step_account(self._login_account),
                "country": "VN" if self._area_code == "84" else "",
                "usage": "GrantingCredit",
                "areaCode": self._area_code,
                "extraSendOptions": [],
                "isUserSelected": False,
                "isEncrypt": True,
            },
            content_type=CAPTCHA_CONTENT_TYPE,
            credentials=_load_default_app_credentials(),
            base_url=self._base_url,
            client_ua=self._account_client_ua,
        )

    async def async_grant_two_step_code(self, code: str) -> None:
        """Verify the six-digit GrantingCredit code for this account."""
        normalized_code = code.strip()
        if len(normalized_code) != 6 or not normalized_code.isdigit():
            raise ValueError("Verification code must contain six digits")
        account_type = "phone" if self._area_code else "email"
        await self._request_with_retries(
            "user.account.GrantingCredit",
            TWO_STEP_REVISION,
            {
                "type": account_type,
                "validCode": normalized_code,
                "areaCode": self._area_code,
                "account": encrypt_two_step_account(self._login_account),
                "isEncrypt": True,
            },
            content_type=CAPTCHA_CONTENT_TYPE,
            credentials=_load_default_app_credentials(),
            base_url=self._base_url,
            client_ua=self._account_client_ua,
        )

    async def async_authenticate_after_two_step(self) -> None:
        """Retry login while the granted terminal permission propagates."""
        for attempt in range(len(TWO_STEP_PROPAGATION_DELAYS) + 1):
            try:
                await self.async_authenticate(force=True, use_pc_client=False)
                return
            except ImouTwoStepVerificationRequired:
                if attempt == len(TWO_STEP_PROPAGATION_DELAYS):
                    raise
                delay = TWO_STEP_PROPAGATION_DELAYS[attempt]
                _LOGGER.info(
                    "Imou terminal authorization is still propagating "
                    "attempt=%s retry_in=%s",
                    attempt + 1,
                    delay,
                )
                await asyncio.sleep(delay)

    async def async_authenticate(
        self,
        *,
        force: bool = False,
        expected_generation: int | None = None,
        expected_qr_required: bool = False,
        use_pc_client: bool | None = None,
    ) -> None:
        """Perform GetToken then Login, serializing concurrent relogins."""
        async with self._login_lock:
            if self.authenticated and (
                not force
                or expected_generation is not None
                and expected_generation != self._auth_generation
            ):
                return
            selected_pc_client = (
                self._using_pc_client if use_pc_client is None else use_pc_client
            )
            self._logged_in = False
            self._using_pc_client = selected_pc_client
            self._client_ua = (
                self._qr_client_ua if selected_pc_client else self._account_client_ua
            )
            self._credentials = _build_account_credentials(
                self._login_account,
                self._password,
            )
            auth_base_urls = (
                tuple(
                    dict.fromkeys(
                        (
                            self._qr_base_url,
                            self._normalize_base_url(PC_ENTRY_HOST),
                            self._normalize_base_url(PC_ENTRY_HOST_FALLBACK),
                        )
                    )
                )
                if selected_pc_client
                else (self._normalize_base_url(ENTRY_HOST),)
            )
            self._base_url = auth_base_urls[0]
            if not force:
                _LOGGER.info(
                    "Imou account login profile selected client=%s host=%s",
                    "pc" if selected_pc_client else "phone",
                    urlparse(self._base_url).hostname or "unknown",
                )
            last_connection_error: ImouConnectionError | None = None
            for auth_base_url in auth_base_urls:
                self._base_url = auth_base_url
                if selected_pc_client:
                    self._qr_base_url = auth_base_url
                try:
                    token_data = await self._request_with_retries(
                        "user.account.GetToken",
                        GET_TOKEN_REVISION,
                        {
                            "areaCode": self._area_code,
                            "gpsInfo": {"latitude": 0.0, "longitude": 0.0},
                        },
                        expected_error_codes=(
                            frozenset({QR_LOGIN_REQUIRED_CODE})
                            if expected_qr_required
                            else frozenset()
                        ),
                    )
                except ImouConnectionError as error:
                    last_connection_error = error
                    continue
                break
            else:
                raise last_connection_error or ImouConnectionError(
                    "Could not reach Imou account host"
                )
            if token_data.get("failNum") not in (None, ""):
                error = ImouCredentialError(token_data["failNum"])
                _LOGGER.warning(
                    "Imou GetToken rejected account/password fail_num=%s",
                    error.failure_count
                    if error.failure_count is not None
                    else "unknown",
                )
                raise error
            if selected_pc_client:
                _LOGGER.info(
                    "Imou PC terminal GetToken accepted host=%s",
                    urlparse(self._base_url).hostname or "unknown",
                )
            await self._finish_token_login(token_data)

    async def async_create_qr_login(
        self,
        *,
        width: int = 300,
        height: int = 300,
    ) -> ImouQrLogin:
        """Create an official Imou Life QR authorization request."""
        qr_hosts = (PC_ENTRY_HOST, PC_ENTRY_HOST_FALLBACK)
        last_error: ImouConnectionError | None = None
        for host in qr_hosts:
            qr_base_url = self._normalize_base_url(host)
            try:
                result = await self._request_with_retries(
                    "user.account.GetLoginQRCode",
                    GET_LOGIN_QR_REVISION,
                    {"height": height, "width": width},
                    credentials=_load_pc_app_credentials(),
                    base_url=qr_base_url,
                    client_ua=self._qr_client_ua,
                )
            except ImouConnectionError as error:
                last_error = error
                continue
            self._qr_base_url = qr_base_url
            break
        else:
            raise last_error or ImouConnectionError("Could not reach Imou PC QR host")
        image = str(result.get("QRCodeImage") or "")
        login_code = str(result.get("loginCode") or "")
        if not image or not login_code:
            raise ImouApiError("QR login response was incomplete")
        _LOGGER.info(
            "Imou PC QR profile selected version=%s protocol=%s host=%s",
            PC_APP_VERSION,
            PC_PROTOCOL_VERSION,
            urlparse(self._qr_base_url).hostname or "unknown",
        )
        return ImouQrLogin(image=image, login_code=login_code)

    async def async_query_qr_login(
        self,
        login_code: str,
        *,
        recover_across_hosts: bool = False,
    ) -> ImouQrLoginResult:
        """Query whether the Imou Life mobile app authorized a QR code."""
        if not login_code:
            raise ValueError("QR login code is missing")
        query_base_url = self._qr_base_url
        try:
            result = await self._query_qr_payload(login_code, query_base_url)
        except ImouApiError as error:
            if not recover_across_hosts or error.code != 11001:
                raise
            recovered = await self._recover_qr_payload(
                login_code,
                excluded_urls={query_base_url},
            )
            if recovered is None:
                raise
            query_base_url, result = recovered
        qr_result = self._qr_login_result(result)
        if recover_across_hosts and qr_result.status == "expire":
            recovered = await self._recover_qr_payload(
                login_code,
                excluded_urls={query_base_url},
            )
            if recovered is not None:
                recovered_url, recovered_result = recovered
                recovered_qr_result = self._qr_login_result(recovered_result)
                if recovered_qr_result.status != "expire":
                    query_base_url = recovered_url
                    result = recovered_result
                    qr_result = recovered_qr_result
        if query_base_url != self._qr_base_url and qr_result.status != "expire":
            self._qr_base_url = query_base_url
            _LOGGER.info(
                "Imou QR recovery host selected host=%s status=%s",
                urlparse(query_base_url).hostname or "unknown",
                qr_result.status
                if qr_result.status in {"login", "expire", "cancel", "waiting", "unscan", "scan"}
                else "<redacted>",
            )
        regional_attempted = False
        regional_error_code: int | None = None
        regional_header_names = ""
        regional_auth_sources = ""
        if qr_result.status == "login" and not qr_result.credentials_ready:
            regional_url = self._regional_qr_url(qr_result.entry_url)
            if regional_url is not None:
                regional_attempted = True
                try:
                    regional_data = await self._request_with_retries(
                        "user.account.QueryLoginQRCode",
                        QUERY_LOGIN_QR_REVISION,
                        {"loginCode": login_code},
                        credentials=_load_pc_app_credentials(),
                        base_url=regional_url,
                        client_ua=self._qr_client_ua,
                        capture_response_auth=True,
                    )
                except ImouApiError as error:
                    if error.code == 429:
                        raise
                    regional_error_code = error.code
                    _LOGGER.debug(
                        "Imou regional QR query rejected code=%s host=%s",
                        error.code,
                        urlparse(regional_url).hostname or "unknown",
                    )
                else:
                    regional_header_names = self._safe_response_metadata(
                        regional_data, "_responseHeaderNames"
                    )
                    regional_auth_sources = self._safe_response_metadata(
                        regional_data, "_responseAuthSources"
                    )
                    qr_result = self._merge_qr_login_results(
                        qr_result,
                        self._qr_login_result(regional_data),
                    )
        if qr_result.status == "login" and not qr_result.credentials_ready:
            _LOGGER.info(
                "Imou QR login approved without credentials keys=%s token_keys=%s "
                "support_pc_auto_login=%s entry_host=%s response_headers=%s "
                "response_auth_sources=%s regional_attempted=%s "
                "regional_error_code=%s regional_response_headers=%s "
                "regional_response_auth_sources=%s",
                self._safe_mapping_keys(result),
                self._safe_mapping_keys(self._qr_token_data(result)),
                qr_result.support_pc_auto_login,
                urlparse(qr_result.entry_url).hostname or "missing",
                self._safe_response_metadata(result, "_responseHeaderNames"),
                self._safe_response_metadata(result, "_responseAuthSources"),
                regional_attempted,
                regional_error_code,
                regional_header_names,
                regional_auth_sources,
            )
        return qr_result

    async def _query_qr_payload(
        self,
        login_code: str,
        base_url: str,
    ) -> dict[str, Any]:
        return await self._request_with_retries(
            "user.account.QueryLoginQRCode",
            QUERY_LOGIN_QR_REVISION,
            {"loginCode": login_code},
            credentials=_load_pc_app_credentials(),
            base_url=base_url,
            client_ua=self._qr_client_ua,
            capture_response_auth=True,
        )

    async def _recover_qr_payload(
        self,
        login_code: str,
        *,
        excluded_urls: set[str],
    ) -> tuple[str, dict[str, Any]] | None:
        fallback: tuple[str, dict[str, Any]] | None = None
        for host in (PC_ENTRY_HOST, PC_ENTRY_HOST_FALLBACK, ENTRY_HOST):
            base_url = self._normalize_base_url(host)
            if base_url in excluded_urls:
                continue
            try:
                result = await self._query_qr_payload(login_code, base_url)
            except ImouApiError as error:
                if error.code == 429:
                    raise
                if error.code == 11001:
                    continue
                _LOGGER.debug(
                    "Imou QR recovery query rejected code=%s host=%s",
                    error.code,
                    urlparse(base_url).hostname or "unknown",
                )
                continue
            status = self._qr_login_result(result).status
            if status == "login":
                return base_url, result
            if status != "expire" and fallback is None:
                fallback = (base_url, result)
        return fallback

    def _regional_qr_url(self, entry_url: str) -> str | None:
        if not entry_url:
            return None
        regional_url = self._normalize_base_url(entry_url)
        global_url = self._qr_base_url
        if not urlparse(regional_url).hostname or regional_url == global_url:
            return None
        return regional_url

    @classmethod
    def _qr_login_result(cls, result: Mapping[str, Any]) -> ImouQrLoginResult:
        token_data = cls._qr_token_data(result)
        status = str(result.get("status") or token_data.get("status") or "")
        status = status.strip().casefold()
        username = str(token_data.get("username") or token_data.get("userName") or "")
        token = str(
            token_data.get("token")
            or token_data.get("accessToken")
            or token_data.get("userToken")
            or ""
        )
        session_id = str(
            token_data.get("sessionId") or token_data.get("sessionID") or ""
        )
        entry_url = str(
            token_data.get("entryUrlV2") or token_data.get("entryUrl") or ""
        )
        if (username and token and session_id) or status in {
            "approved",
            "authorized",
            "confirmed",
            "success",
        }:
            status = "login"
        elif status in {"expired", "timeout", "timedout"}:
            status = "expire"
        elif status == "cancelled":
            status = "cancel"
        elif not status:
            status = "waiting"
        support_pc_auto_login = cls._optional_bool(
            token_data.get("supportPcAutoLogin", result.get("supportPcAutoLogin"))
        )
        return ImouQrLoginResult(
            status=status,
            username=username,
            token=token,
            session_id=session_id,
            entry_url=entry_url,
            support_pc_auto_login=support_pc_auto_login,
        )

    @staticmethod
    def _merge_qr_login_results(
        primary: ImouQrLoginResult,
        secondary: ImouQrLoginResult,
    ) -> ImouQrLoginResult:
        status = (
            "login"
            if "login" in {primary.status, secondary.status}
            else secondary.status
        )
        return ImouQrLoginResult(
            status=status,
            username=secondary.username or primary.username,
            token=secondary.token or primary.token,
            session_id=secondary.session_id or primary.session_id,
            entry_url=secondary.entry_url or primary.entry_url,
            support_pc_auto_login=(
                secondary.support_pc_auto_login
                if secondary.support_pc_auto_login is not None
                else primary.support_pc_auto_login
            ),
        )

    @staticmethod
    def _optional_bool(value: Any) -> bool | None:
        if isinstance(value, bool):
            return value
        if isinstance(value, int) and value in {0, 1}:
            return bool(value)
        if isinstance(value, str):
            normalized = value.strip().casefold()
            if normalized in {"true", "1", "yes"}:
                return True
            if normalized in {"false", "0", "no"}:
                return False
        return None

    async def async_complete_qr_login(self, result: ImouQrLoginResult) -> None:
        """Finish login using QR credentials or the approved account flow."""
        if result.status != "login":
            raise ImouAuthError("QR authorization is not complete")
        if not result.credentials_ready:
            await self.async_authenticate(force=True, use_pc_client=True)
            return
        async with self._login_lock:
            self._logged_in = False
            self._using_pc_client = True
            self._client_ua = self._qr_client_ua
            await self._finish_token_login(
                {
                    "username": result.username,
                    "token": result.token,
                    "sessionId": result.session_id,
                    "entryUrlV2": result.entry_url,
                }
            )

    async def _finish_token_login(self, token_data: Mapping[str, Any]) -> None:
        username = str(token_data.get("username") or "")
        token = str(token_data.get("token") or "")
        session_id = str(token_data.get("sessionId") or "")
        if not username or not token or not session_id:
            raise ImouAuthError("Token response did not contain login credentials")
        if token_data.get("entryUrlV2"):
            self._base_url = self._normalize_base_url(str(token_data["entryUrlV2"]))
        self._credentials = ImouCredentials(
            f"uuid\\{username}",
            md5(token.encode()).hexdigest(),
            sha256(token.encode()).hexdigest(),
            session_id,
        )
        self._mqtt_identity = username
        self._mqtt_secret = token
        login_data = await self._request_with_retries(
            "user.account.Login",
            LOGIN_REVISION,
            {
                "avatarDigestType": "SHA256",
                "timezoneOffset": _local_timezone_offset(),
            },
        )
        if login_data.get("entryUrlV2"):
            self._base_url = self._normalize_base_url(str(login_data["entryUrlV2"]))
        self.user_info = dict(login_data)
        self._live_cache.clear()
        self._live_modes.clear()
        self._live_diagnostics.clear()
        self._live_rejected.clear()
        self._latest_alarm_status = "not_requested"
        self._iot_control_modes.clear()
        self._auth_generation += 1
        self._logged_in = True

    @staticmethod
    def _qr_token_data(result: Mapping[str, Any]) -> Mapping[str, Any]:
        candidates = [result]
        candidates.extend(
            value for value in result.values() if isinstance(value, Mapping)
        )

        def score(candidate: Mapping[str, Any]) -> int:
            key_groups = (
                ("username", "userName"),
                ("token", "accessToken", "userToken"),
                ("sessionId", "sessionID", "sessionid"),
            )
            return sum(
                any(candidate.get(key) not in (None, "") for key in keys)
                for keys in key_groups
            )

        return max(candidates, key=score)

    @staticmethod
    def _safe_mapping_keys(value: Mapping[str, Any]) -> str:
        allowed = {
            "status", "username", "userName", "token", "accessToken", "userToken",
            "sessionId", "sessionID", "sessionid", "entryUrlV2", "entryUrl",
            "supportPcAutoLogin", "creditTerminal", "isSingleCredit", "data",
            "captchaMode", "captchaData", "captchaId", "captchaServer",
            "verifyToken", "captchaMetaData", "_responseHeaderNames",
            "_responseAuthSources",
        }
        names = sorted(key for key in value if key in allowed)
        if len(names) != len(value):
            names.append("<redacted>")
        return ",".join(names)

    @staticmethod
    def _safe_response_metadata(value: Mapping[str, Any], key: str) -> str:
        metadata = value.get(key)
        if not isinstance(metadata, (list, tuple)):
            return "none"
        fields = {
            "x-pcs-token", "x-token", "token", "x-pcs-session-id", "x-session-id",
            "session-id", "x-pcs-entry-url-v2", "x-entry-url-v2", "entry-url-v2",
            "x-pcs-username", "x-username", "username",
        }
        allowed = (
            fields | {"content-type", "content-length", "date", "x-pcs-date", "server"}
            if key == "_responseHeaderNames"
            else {f"header:{name}" for name in fields}
            | {
                f"cookie:{name}" for name in (
                    "token", "accesstoken", "access_token", "sessionid",
                    "session_id", "username", "entryurlv2",
                )
            }
        )
        names = set()
        for item in metadata:
            if isinstance(item, str) and item.casefold() in allowed:
                names.add(item.casefold())
            else:
                names.add("<redacted>")
        return ",".join(sorted(names)) or "none"

    @staticmethod
    def _safe_boolean_flags(value: Any) -> str:
        if not isinstance(value, Mapping):
            return "none"
        flags = []
        for key in ("creditTerminal", "isSingleCredit", "supportPcAutoLogin"):
            item = value.get(key)
            if isinstance(item, bool):
                flags.append(f"{key}={str(item).lower()}")
            elif isinstance(item, int) and item in {0, 1}:
                flags.append(f"{key}={item}")
        return ",".join(flags) or "none"

    async def async_request(
        self, api_name: str, revision: str, data: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Call a signed API, relogging once if the token expired."""
        if not self.authenticated:
            await self.async_authenticate()
        generation = self._auth_generation
        try:
            return await self._request_with_retries(api_name, revision, data)
        except ImouTwoStepVerificationRequired:
            raise
        except ImouQrLoginRequired:
            raise
        except ImouAuthError:
            await self.async_authenticate(force=True, expected_generation=generation)
            return await self._request_with_retries(api_name, revision, data)

    async def _request_with_retries(
        self,
        api_name: str,
        revision: str,
        data: Mapping[str, Any],
        *,
        content_type: str = JSON_CONTENT_TYPE,
        credentials: ImouCredentials | None = None,
        base_url: str | None = None,
        client_ua: str | None = None,
        capture_response_auth: bool = False,
        expected_error_codes: frozenset[int] = frozenset(),
        ssl_context: ssl.SSLContext | None = None,
    ) -> dict[str, Any]:
        last_error: ImouConnectionError | None = None
        attempts = 1 if api_name in _NON_REPLAYABLE_APIS else 3
        for attempt in range(attempts):
            try:
                return await self._request_once(
                    api_name,
                    revision,
                    data,
                    content_type=content_type,
                    credentials=credentials,
                    base_url=base_url,
                    client_ua=client_ua,
                    capture_response_auth=capture_response_auth,
                    expected_error_codes=expected_error_codes,
                    ssl_context=ssl_context,
                )
            except ImouConnectionError as err:
                last_error = err
                if attempt + 1 == attempts:
                    break
                await asyncio.sleep(0.5 * (2**attempt))
        raise last_error or ImouConnectionError("Imou request failed")

    async def _request_once(
        self,
        api_name: str,
        revision: str,
        data: Mapping[str, Any],
        *,
        content_type: str = JSON_CONTENT_TYPE,
        credentials: ImouCredentials | None = None,
        base_url: str | None = None,
        client_ua: str | None = None,
        capture_response_auth: bool = False,
        expected_error_codes: frozenset[int] = frozenset(),
        ssl_context: ssl.SSLContext | None = None,
    ) -> dict[str, Any]:
        signing_credentials = credentials or self._credentials
        if signing_credentials is None:
            raise ImouAuthError("No signing credentials")
        request_base_url = base_url or self._base_url
        try:
            destination = urlparse(request_base_url)
            secure_destination = (
                destination.scheme == "https"
                and bool(destination.hostname)
                and not any(character.isspace() for character in request_base_url)
                and destination.port != 0
                and destination.username is None
                and not destination.query
                and not destination.fragment
            )
        except ValueError:
            secure_destination = False
        if not secure_destination:
            raise ImouApiError(
                "Signed Imou requests require a valid HTTPS destination"
            ) from None
        if (
            api_name == _LEGACY_DEVICE_LIST_API
            and time.monotonic()
            < self._legacy_discovery_retry_after.get(request_base_url, 0.0)
        ):
            _LOGGER.debug(
                "Imou legacy device list skipped api=%s host=%s",
                _LEGACY_DEVICE_LIST_API,
                urlparse(request_base_url).hostname or request_base_url,
            )
            raise _ImouLegacyEndpointUnavailable(
                "Imou legacy device list endpoint unavailable", 404
            )
        effective_revision = revision or SIGNATURE_REVISION
        effective_client_ua = client_ua or self._client_ua
        legacy_first_page = (
            api_name == _LEGACY_DEVICE_LIST_API
            and isinstance(data, Mapping)
            and data.get("pageId") == 0
        )
        method = "POST"
        path = f"/pcs/v1/{api_name}"
        body = compact_json({"data": data}).encode()
        body_md5 = content_md5(body)
        body_sha256 = content_sha256(body)
        nonce = "".join(secrets.choice(NONCE_ALPHABET) for _ in range(32))
        date = datetime.fromtimestamp(time.time() + self._clock_offset, UTC).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        canonical = build_canonical_string(
            method,
            path,
            body_md5,
            content_type,
            effective_revision,
            effective_client_ua,
            date,
            nonce,
            signing_credentials.username,
            signing_credentials.session_id,
        )
        headers = {
            "Content-Type": content_type,
            "Content-MD5": body_md5,
            "Content-SHA256": body_sha256,
            "x-pcs-username": signing_credentials.username,
            "x-pcs-apiver": effective_revision,
            "x-pcs-nonce": nonce,
            "x-pcs-date": date,
            "x-pcs-signature": sign_canonical(canonical, signing_credentials.secret),
            "x-pcs-client-ua": effective_client_ua,
            "x-pcs-request-id": uuid4().hex,
        }
        sha256_canonical = build_canonical_string(
            method,
            path,
            body_sha256,
            content_type,
            effective_revision,
            effective_client_ua,
            date,
            nonce,
            signing_credentials.username,
            signing_credentials.session_id,
        )
        headers["x-pcs-signature-sha256"] = sign_canonical(
            sha256_canonical, signing_credentials.sha256_secret
        )
        if signing_credentials.session_id is not None:
            headers["x-pcs-session-id"] = signing_credentials.session_id
        url = f"{request_base_url}{path}"
        try:
            async with (
                self._semaphore,
                self._session.post(
                    url,
                    data=body,
                    headers=headers,
                    timeout=self.request_timeout,
                    allow_redirects=False,
                    **({"ssl": ssl_context} if ssl_context is not None else {}),
                ) as response,
            ):
                received_at = time.time()
                status = response.status
                if (
                    not isinstance(status, int)
                    or isinstance(status, bool)
                    or not 200 <= status <= 599
                ):
                    raise ImouConnectionError("Invalid Imou cloud HTTP status")
                server_date = response.headers.get("x-pcs-date")
                if isinstance(server_date, str):
                    try:
                        server_time = datetime.strptime(
                            server_date, "%Y-%m-%dT%H:%M:%SZ"
                        ).replace(tzinfo=UTC)
                        offset = server_time.timestamp() - received_at
                        if abs(offset) < 86400:
                            self._clock_offset = offset
                    except (ValueError, OverflowError, OSError):
                        pass
                if 300 <= status < 400:
                    raise ImouApiError("Imou cloud redirect rejected", status)
                if status == 429:
                    raise ImouApiError("Imou cloud rate limit exceeded", status)
                if status == 408:
                    raise ImouApiError("Imou cloud HTTP 408", status)
                try:
                    raw = await _read_bounded(response.content, MAX_API_RESPONSE_BYTES)
                except Exception:
                    if status in {401, 403}:
                        raise ImouAuthError("Authentication failed", status) from None
                    raise
                response_header_names = (
                    tuple(str(name).casefold() for name in response.headers)
                    if capture_response_auth
                    else ()
                )
                response_auth, response_auth_sources = (
                    self._extract_response_auth(response)
                    if capture_response_auth
                    else ({}, ())
                )
        except ImouApiError:
            raise
        except Exception:
            raise ImouConnectionError("Request to Imou cloud failed") from None
        if status >= 500:
            raise ImouConnectionError(f"Imou cloud HTTP {status}", status)
        if len(raw) > MAX_API_RESPONSE_BYTES:
            if status in {401, 403}:
                raise ImouAuthError("Authentication failed", status)
            raise ImouConnectionError("Imou cloud response exceeded size limit")
        legacy_unavailable = (
            status == 404 and api_name == _LEGACY_DEVICE_LIST_API
        )
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, ValueError, RecursionError):
            payload = None
        if not isinstance(payload, Mapping):
            payload = {}
        numeric_code = _response_code(payload.get("code"))
        if (
            numeric_code is not None
            and numeric_code not in SUCCESS_CODES
            and numeric_code not in expected_error_codes
        ):
            is_property_rejection = numeric_code == 10003 and api_name in {
                "iot.control.GetIotProperties",
                "iot.control.GetProperties",
            }
            is_unavailable_legacy = (
                status == 404 and api_name == _LEGACY_DEVICE_LIST_API
            )
            is_ptz_no_authority = (
                api_name == PTZ_MOVE_API and numeric_code in PTZ_NO_AUTHORITY_CODES
            )
            log_level = (
                logging.DEBUG
                if is_property_rejection
                or is_unavailable_legacy
                or is_ptz_no_authority
                else logging.WARNING
            )
            _LOGGER.log(
                log_level,
                "Imou API rejected request api=%s code=%s http_status=%s "
                "revision=%s content_type=%s host=%s auth_type=%s "
                "client_profile=%s detail=%s",
                api_name,
                numeric_code,
                status,
                headers["x-pcs-apiver"],
                content_type,
                urlparse(request_base_url).hostname or "unknown",
                self._credential_type(signing_credentials),
                "pc" if effective_client_ua == self._qr_client_ua else "phone",
                _safe_error_detail(payload.get("desc"))
                if api_name == PTZ_MOVE_API
                else "",
            )
        result = payload.get("data")
        if 200 <= status < 300 and numeric_code == 429:
            raise ImouApiError("Imou cloud rate limit exceeded", numeric_code)
        if numeric_code in CAPTCHA_CHALLENGE_CODES:
            raise ImouCaptchaRequired(
                "Visual verification required",
                numeric_code,
                self._captcha_challenge_from_data(
                    result,
                    numeric_code,
                    usage=self._captcha_usage_for_request(api_name, numeric_code),
                    base_url=request_base_url,
                    client_ua=effective_client_ua,
                ),
            )
        if numeric_code in TWO_STEP_REQUIRED_CODES:
            response_keys = (
                self._safe_mapping_keys(result)
                if isinstance(result, Mapping)
                else "none"
            )
            _LOGGER.warning(
                "Imou terminal verification required response_keys=%s "
                "response_flags=%s",
                response_keys or "none",
                self._safe_boolean_flags(result),
            )
            raise ImouTwoStepVerificationRequired(
                "Two-step verification required", numeric_code
            )
        if status in {401, 403} or (
            numeric_code is not None
            and numeric_code not in SUCCESS_CODES
            and self._looks_like_auth_error(numeric_code, payload)
        ):
            raise ImouAuthError(
                "Authentication failed",
                numeric_code
                if numeric_code is not None and numeric_code not in SUCCESS_CODES
                else status,
            )
        if legacy_unavailable:
            if legacy_first_page:
                raise self._mark_legacy_discovery_unavailable(request_base_url)
            raise _ImouLegacyEndpointUnavailable(
                "Imou legacy device list endpoint unavailable", 404
            )
        if not 200 <= status < 300:
            raise ImouApiError(f"Imou cloud HTTP {status}", status)
        if numeric_code is None:
            raise ImouConnectionError(
                f"Invalid response from Imou cloud (HTTP {status})"
            ) from None
        if numeric_code not in SUCCESS_CODES:
            raise ImouApiError(f"API error {numeric_code}", numeric_code)
        if result is not None and not isinstance(result, Mapping):
            raise ImouConnectionError("Invalid Imou cloud response data")
        response_data = dict(result) if isinstance(result, Mapping) else {}
        if capture_response_auth:
            for key, value in response_auth.items():
                if response_data.get(key) in (None, ""):
                    response_data[key] = value
            response_data["_responseHeaderNames"] = response_header_names
            response_data["_responseAuthSources"] = response_auth_sources
        return response_data

    @classmethod
    def _extract_response_auth(
        cls, response: Any
    ) -> tuple[dict[str, str], tuple[str, ...]]:
        auth: dict[str, str] = {}
        sources: list[str] = []
        header_fields = {
            "x-pcs-token": "token",
            "x-token": "token",
            "token": "token",
            "x-pcs-session-id": "sessionId",
            "x-session-id": "sessionId",
            "session-id": "sessionId",
            "x-pcs-entry-url-v2": "entryUrlV2",
            "x-entry-url-v2": "entryUrlV2",
            "entry-url-v2": "entryUrlV2",
        }
        for name, value in response.headers.items():
            normalized_name = str(name).strip().casefold()
            field = header_fields.get(normalized_name)
            text = str(value).strip()
            if field and text and field not in auth:
                auth[field] = text
                sources.append(f"header:{normalized_name}")
            elif normalized_name in {"x-pcs-username", "x-username", "username"}:
                username = cls._response_username(
                    text,
                    prefixed=normalized_name == "x-pcs-username",
                )
                if username and "username" not in auth:
                    auth["username"] = username
                    sources.append(f"header:{normalized_name}")
        cookie_fields = {
            "token": "token",
            "accesstoken": "token",
            "access_token": "token",
            "sessionid": "sessionId",
            "session_id": "sessionId",
            "username": "username",
            "entryurlv2": "entryUrlV2",
        }
        cookies = getattr(response, "cookies", {})
        for name, morsel in cookies.items():
            normalized_name = str(name).strip().casefold()
            field = cookie_fields.get(normalized_name)
            value = str(getattr(morsel, "value", morsel)).strip()
            if field == "username":
                value = cls._response_username(value, prefixed=False)
            if field and value and field not in auth:
                auth[field] = value
                sources.append(f"cookie:{normalized_name}")
        return auth, tuple(sources)

    @staticmethod
    def _response_username(value: str, *, prefixed: bool) -> str:
        if value.startswith("token/"):
            return value.removeprefix("token/")
        if value.startswith("uuid\\"):
            return value.removeprefix("uuid\\")
        if prefixed:
            return ""
        return value

    @staticmethod
    def _credential_type(credentials: ImouCredentials) -> str:
        if credentials.username.startswith("default\\"):
            return "default"
        if credentials.session_id is not None:
            return "token"
        return "account"

    @staticmethod
    def _looks_like_auth_error(code: int, payload: Mapping[str, Any]) -> bool:
        if code in AUTH_ERROR_CODES:
            return True
        description = payload.get("desc")
        if not isinstance(description, str):
            return False
        description = description.lower()
        return any(
            word in description
            for word in ("token expired", "session expired", "unauthorized")
        )

    async def async_list_devices(self) -> list[ImouDevice]:
        """Discover rich home devices and channels with legacy fallbacks."""
        last_error: ImouApiError | None = None
        merged: dict[str, dict[str, Any]] = {}
        devices: list[ImouDevice] = []
        incomplete: set[str] | None = None
        for list_devices in (
            self._list_device_basic_info,
            self._list_basic_devices,
            self._list_legacy_devices,
        ):
            try:
                raw_devices = await list_devices()
            except ImouAuthError:
                raise
            except _ImouLegacyEndpointUnavailable:
                continue
            except ImouApiError as err:
                if err.code == 429:
                    raise
                last_error = err
                continue
            last_error = None
            for raw in raw_devices:
                if not isinstance(raw, Mapping):
                    continue
                device_id = _api_identifier(raw, "deviceId", "deviceid")
                if not device_id or incomplete is not None and device_id not in incomplete:
                    continue
                record = merged.setdefault(device_id, {})
                known_device = device_from_api(record) if incomplete is not None else None
                channel_products = (
                    {channel.channel_id: channel.product_id for channel in known_device.channels}
                    if known_device is not None else {}
                )
                for key, value in raw.items():
                    if incomplete is not None and key not in (
                        "productId", "productid", "channelList", "channels",
                        "channelNum", "channelnum", "productChannelNum",
                    ):
                        continue
                    if key in ("channelList", "channels") and isinstance(value, list):
                        if incomplete is not None:
                            value = [
                                {
                                    "channelId": channel_id,
                                    "productId": channel_products.get(channel_id)
                                    or _api_identifier(channel, "productId", "productid"),
                                }
                                for index, channel in enumerate(value)
                                if isinstance(channel, Mapping)
                                for channel_id in (
                                    _api_identifier(channel, "channelId", "channelid") or str(index),
                                )
                            ]
                        previous = record.get(key)
                        record[key] = (
                            previous if isinstance(previous, list) else []
                        ) + [
                            channel
                            if _api_identifier(channel, "channelId", "channelid")
                            else {**channel, "channelId": str(index)}
                            for index, channel in enumerate(value)
                            if isinstance(channel, Mapping)
                        ]
                    elif (
                        record.get(key) in (None, "", [], {})
                        or key in ("productId", "productid")
                        and not _api_identifier(record, key)
                    ):
                        record[key] = value
            devices = [
                device
                for raw in merged.values()
                if (device := device_from_api(raw)) is not None
            ]
            if devices:
                incomplete = {
                    device.device_id for device in devices if not device.product_id
                }
                if not incomplete:
                    return devices
        if devices:
            return devices
        if last_error is not None:
            raise last_error
        return []

    async def async_get_latest_alarms(
        self, devices: list[ImouDevice]
    ) -> list[dict[str, Any]]:
        """Fetch the latest channel alarms used when MQTT push is unavailable."""
        device_list: list[dict[str, Any]] = []
        for device in devices[:128]:
            channel_ids = [channel.channel_id for channel in device.channels[:64]]
            raw_device = getattr(device, "raw", None)
            if not isinstance(raw_device, Mapping):
                raw_device = {}
            raw_ap_list = raw_device.get("apList") or raw_device.get("aplist") or []
            ap_ids: list[str] = []
            if isinstance(raw_ap_list, list):
                for ap in raw_ap_list[:64]:
                    if not isinstance(ap, Mapping):
                        continue
                    ap_id = str(ap.get("apId") or ap.get("deviceId") or "").strip()
                    if ap_id:
                        ap_ids.append(ap_id)
            category = str(raw_device.get("category") or "")
            sub_category = str(raw_device.get("subCategory") or "")
            multi_view = str(raw_device.get("multiView") or "0")
            product_id = str(getattr(device, "product_id", "") or "")
            device_list.append(
                {
                    "deviceId": device.device_id,
                    "productId": product_id,
                    "channelIds": channel_ids,
                    "apIds": ap_ids,
                    "isBluetooth": getattr(device, "catalog", None)
                    == "BluetoothLock",
                    "multiView": multi_view,
                    "category": category,
                    "subCategory": sub_category,
                }
            )
        if not device_list:
            return []
        try:
            data = await self.async_request(
                "cloud.message.GetDeviceLatestAlarmMixMessage",
                LATEST_ALARM_REVISION,
                {"deviceList": device_list, "isFamily": True},
            )
            self._latest_alarm_status = "mix"
        except ImouAuthError:
            raise
        except ImouApiError as err:
            if err.code == 429:
                raise
            self._latest_alarm_status = f"mix_error:{err.code}"
            _LOGGER.debug(
                "Imou latest mixed alarm fallback code=%s",
                err.code,
            )
            legacy_device_list = [
                {
                    "deviceId": item["deviceId"],
                    "channelIds": item["channelIds"],
                    "apIds": item["apIds"],
                }
                for item in device_list
            ]
            try:
                data = await self.async_request(
                    "cloud.message.GetDeviceLatestAlarmMessage",
                    LEGACY_LATEST_ALARM_REVISION,
                    {"deviceList": legacy_device_list},
                )
                self._latest_alarm_status = "legacy"
            except ImouApiError as legacy_error:
                self._latest_alarm_status = f"error:{legacy_error.code}"
                raise
        raw_alarm_list = data.get("alarmList") or []
        if not isinstance(raw_alarm_list, list):
            return []
        alarms: list[dict[str, Any]] = []
        for device_entry in raw_alarm_list[:512]:
            if not isinstance(device_entry, Mapping):
                continue
            device_id = str(device_entry.get("deviceId") or "")
            channel_alarms = device_entry.get("chnAlarms") or []
            if isinstance(channel_alarms, list):
                for alarm in channel_alarms[:128]:
                    if not isinstance(alarm, Mapping):
                        continue
                    record = dict(alarm)
                    if device_id and not record.get("deviceId"):
                        record["deviceId"] = device_id
                    record.setdefault("productId", device_entry.get("productId"))
                    record["_alarmScope"] = "channel"
                    alarms.append(record)
            device_alarm = device_entry.get("deviceAlarm")
            if isinstance(device_alarm, Mapping) and (
                any(
                    device_alarm.get(key) not in (None, "", [], {})
                    for key in (
                        "alarmId",
                        "refId",
                        "time",
                        "title",
                        "name",
                        "type",
                        "remark",
                        "skipUrl",
                    )
                )
                or bool(device_alarm.get("fileList"))
            ):
                record = dict(device_alarm)
                if device_id and not record.get("deviceId"):
                    record["deviceId"] = device_id
                record.setdefault("productId", device_entry.get("productId"))
                record.setdefault("channelId", "-1")
                record["_alarmScope"] = "device"
                alarms.append(record)
            ap_alarms = device_entry.get("apAlarms") or []
            if isinstance(ap_alarms, list):
                for alarm in ap_alarms[:32]:
                    if not isinstance(alarm, Mapping):
                        continue
                    record = dict(alarm)
                    if device_id and not record.get("deviceId"):
                        record["deviceId"] = device_id
                    record.setdefault("productId", device_entry.get("productId"))
                    record.setdefault("channelId", "-1")
                    record["_alarmScope"] = "ap"
                    alarms.append(record)
        return alarms

    def latest_alarm_diagnostic(self) -> str:
        """Return the safe status of the most recent cloud alarm poll."""
        return self._latest_alarm_status

    async def _list_family_ids(self) -> tuple[str, ...]:
        if time.monotonic() < self._family_cache_expires:
            return self._family_ids
        try:
            data = await self.async_request(
                "family.manager.UserFamilyGet", "201076", {"_nouse": 0}
            )
        except ImouAuthError:
            raise
        except ImouApiError as err:
            if err.code == 429:
                raise
            _LOGGER.debug("Imou family enumeration unavailable code=%s", err.code)
            self._family_cache_expires = time.monotonic() + 60
            return self._family_ids
        family_ids: dict[str, None] = {}
        for key in ("families", "joinFamilies", "joinedFamilies"):
            families = data.get(key)
            if not isinstance(families, list):
                continue
            for family in families:
                if not isinstance(family, Mapping):
                    continue
                family_id = _api_identifier(family, "familyId")
                if family_id:
                    family_ids[family_id] = None
                if len(family_ids) >= 32:
                    break
            if len(family_ids) >= 32:
                break
        self._family_ids = tuple(family_ids)
        self._family_cache_expires = time.monotonic() + 300
        return self._family_ids

    async def _list_device_basic_info(self) -> list[Mapping[str, Any]]:
        devices: list[Mapping[str, Any]] = []
        last_error: ImouApiError | None = None
        for family_id in ("", *(await self._list_family_ids())):
            try:
                devices.extend(
                    await self._list_device_pages(
                        "device.list.DeviceBasicInfoQueryV2",
                        "",
                        {
                            "familyId": family_id,
                            "groupId": "-1",
                            "limit": 64,
                            "needNewSecret": True,
                        },
                    )
                )
            except ImouAuthError:
                raise
            except ImouApiError as err:
                if err.code == 429:
                    raise
                last_error = err
                _LOGGER.debug("Imou device family unavailable code=%s", err.code)
        if not devices and last_error is not None:
            raise last_error
        return devices

    async def _list_device_pages(
        self,
        api: str,
        revision: str,
        payload: Mapping[str, Any],
        *,
        legacy: bool = False,
    ) -> list[Mapping[str, Any]]:
        devices: list[Mapping[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        offset = 0
        transfer = ""
        for _ in range(20):
            pagination = (
                {"pageId": offset}
                if legacy
                else {"offset": offset, "transferStr": transfer}
            )
            try:
                data = await self.async_request(api, revision, {**payload, **pagination})
            except ImouAuthError:
                raise
            except ImouApiError as err:
                if err.code == 429:
                    raise
                if devices:
                    break
                raise
            items = data.get("item" if legacy else "deviceList")
            if not isinstance(items, list) or not items:
                break
            page_keys: set[tuple[str, str, str]] = set()
            for item in items:
                if not isinstance(item, Mapping):
                    continue
                device = device_from_api(item)
                if device is None:
                    continue
                devices.append(item)
                page_keys.update(
                    (device.device_id, device.product_id, channel.channel_id)
                    for channel in device.channels
                )
            if not page_keys - seen:
                break
            seen.update(page_keys)
            if legacy:
                if as_bool(data.get("hasNextPage")) is False:
                    break
                next_page = offset
                for item in items:
                    if not isinstance(item, Mapping):
                        continue
                    try:
                        cursor = int(_api_identifier(item, "pageId"))
                    except ValueError:
                        continue
                    next_page = max(next_page, cursor)
                if next_page <= offset:
                    break
                offset = next_page
            else:
                if as_bool(data.get("hasNextPage")) is not True:
                    break
                offset += len(items)
                value = data.get("transferStr")
                transfer = value if isinstance(value, str) else ""
        return devices

    async def _list_basic_devices(self) -> list[Mapping[str, Any]]:
        return await self._list_device_pages(
            "device.list.BasicList",
            "199828",
            {"familyId": "", "groupId": "-1", "limit": 128},
        )

    async def _list_legacy_devices(self) -> list[Mapping[str, Any]]:
        async with self._legacy_discovery_lock:
            return await self._list_device_pages(
                _LEGACY_DEVICE_LIST_API,
                "3421",
                {"limit": 100, "type": ""},
                legacy=True,
            )

    async def async_query_model(
        self, product_id: str, md5_value: str = ""
    ) -> dict[str, Any]:
        """Download a product thing model."""
        return await self.async_request(
            "iot.manager.QueryModelInfo",
            "1",
            {
                "productId": product_id,
                "grayFlag": "",
                "neutralizeFlag": 1,
                "md5": md5_value,
            },
        )

    async def async_get_stream_entry_host(self, device_id: str) -> str | None:
        """Return the device stream-entry host used for cloud PTZ.

        The APK sets `DHDevice.streamEntryAddr` from the device detail query
        (`device.list.DetailInfoQuery`) before sending `things.ptz.PtzMove`.
        Note the device `streamEntryAddrV4` field is the MQTT host, not this
        HTTP entry.
        """
        data = await self.async_request(
            "device.list.DetailInfoQuery",
            "",
            {
                "familyId": "",
                "groupId": "-1",
                "limit": 64,
                "offset": 0,
                "transferStr": "",
            },
        )
        devices = data.get("deviceList") if isinstance(data, Mapping) else None
        if isinstance(devices, list):
            for item in devices:
                if not isinstance(item, Mapping):
                    continue
                if _api_identifier(item, "deviceId", "deviceid") != device_id:
                    continue
                if host := stream_entry_host(item):
                    return host
        return None

    @staticmethod
    def _group_control_enabled(group_control_flag: str) -> bool:
        return str(group_control_flag).strip().casefold() in {"1", "true"}

    def _control_api_candidates(
        self,
        operation: str,
        product_id: str,
        device_id: str,
        group_control_flag: str,
    ) -> tuple[tuple[str, str], ...]:
        if self._group_control_enabled(group_control_flag):
            return (("smart", f"iot.smart.{operation}"),)
        if not product_id:
            return (("legacy", f"iot.control.{operation}"),)
        modern_operation = _IOT_CONTROL_APIS[operation]
        candidates = {
            "iot": f"iot.control.{modern_operation}",
            "legacy": f"iot.control.{operation}",
        }
        cache_key = (product_id, device_id, str(group_control_flag))
        preferred = self._iot_control_modes.get(cache_key, "iot")
        alternate = "legacy" if preferred == "iot" else "iot"
        return (
            (preferred, candidates[preferred]),
            (alternate, candidates[alternate]),
        )

    async def _async_iot_request(
        self,
        api_name: str,
        payload: Mapping[str, Any],
        *,
        timeout_ms: int,
        transport: str,
    ) -> dict[str, Any]:
        """Call an IOT API through the APK MQTT path or signed HTTP."""
        if transport != "http":
            callback = self._mqtt_request
            if callback is not None:
                try:
                    response = await callback(api_name, payload, timeout_ms)
                except ImouMqttUnavailable:
                    if transport == "mqtt":
                        raise
                else:
                    return dict(response)
            elif transport == "mqtt":
                raise ImouMqttUnavailable("Imou MQTT request transport is offline")
        if transport == "mqtt":
            raise ImouMqttUnavailable("Imou MQTT request transport is offline")
        return await self.async_request(api_name, SIGNATURE_REVISION, payload)

    async def _async_control_request(
        self,
        operation: str,
        product_id: str,
        device_id: str,
        group_control_flag: str,
        payload: Mapping[str, Any],
        *,
        fallback_codes: frozenset[int] = frozenset(),
        fallback_on_any_error: bool = False,
    ) -> dict[str, Any]:
        candidates = self._control_api_candidates(
            operation, product_id, device_id, group_control_flag
        )
        cache_key = (product_id, device_id, str(group_control_flag))
        last_error: ImouApiError | None = None
        transports = ("mqtt", "http") if self._mqtt_request is not None else ("http",)
        for index, (mode, api_name) in enumerate(candidates):
            for transport in transports:
                try:
                    result = await self._async_iot_request(
                        api_name,
                        payload,
                        timeout_ms=int(payload.get("timeout") or IOT_CONTROL_TIMEOUT_MS),
                        transport=transport,
                    )
                except ImouMqttUnavailable:
                    continue
                except ImouAuthError:
                    raise
                except ImouApiError as err:
                    if err.code == 429 or (
                        operation != "GetProperties"
                        and isinstance(err, ImouConnectionError)
                    ):
                        raise
                    last_error = err
                    if transport == "mqtt":
                        if (
                            fallback_on_any_error
                            or err.code in fallback_codes
                            or isinstance(err, ImouConnectionError)
                        ):
                            _LOGGER.debug(
                                "Imou MQTT control fallback operation=%s api=%s code=%s",
                                operation,
                                api_name,
                                err.code,
                            )
                            continue
                        raise
                    can_fallback = index + 1 < len(candidates) and (
                        fallback_on_any_error or err.code in fallback_codes
                    )
                    if not can_fallback:
                        raise
                    _LOGGER.debug(
                        "Imou control API fallback operation=%s api=%s code=%s",
                        operation,
                        api_name,
                        err.code,
                    )
                    break
                else:
                    if mode in {"iot", "legacy"}:
                        self._iot_control_modes[cache_key] = mode
                    return result
        raise last_error or ImouApiError("Imou control request failed")

    async def _async_control_request_with_channel_fallback(
        self,
        operation: str,
        product_id: str,
        device_id: str,
        group_control_flag: str,
        payload: Mapping[str, Any],
        *,
        channel_id: str | int | None,
        fallback_codes: frozenset[int] = frozenset(),
        fallback_on_any_error: bool = False,
    ) -> dict[str, Any]:
        try:
            return await self._async_control_request(
                operation,
                product_id,
                device_id,
                group_control_flag,
                payload,
                fallback_codes=fallback_codes,
                fallback_on_any_error=fallback_on_any_error,
            )
        except ImouAuthError:
            raise
        except ImouApiError as err:
            if operation != "GetProperties" and isinstance(err, ImouConnectionError):
                raise
            if (
                not self._group_control_enabled(group_control_flag)
                and channel_id not in (None, "")
                and "channelId" in payload
                and err.code in PROPERTY_CONTROL_FALLBACK_CODES
            ):
                retry_payload = dict(payload)
                retry_payload.pop("channelId", None)
                _LOGGER.debug(
                    "Retrying Imou control without channelId operation=%s "
                    "device_id=%s code=%s",
                    operation,
                    device_id,
                    err.code,
                )
                return await self._async_control_request(
                    operation,
                    product_id,
                    device_id,
                    group_control_flag,
                    retry_payload,
                    fallback_codes=fallback_codes,
                    fallback_on_any_error=fallback_on_any_error,
                )
            raise

    async def async_get_properties(
        self,
        product_id: str,
        device_id: str,
        refs: list[str],
        *,
        group_control_flag: str = "0",
        channel_id: str | int | None = None,
        fallback_identifiers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        """Read numeric wire refs, with identifier fallback for legacy devices."""
        result: dict[str, Any] = {}
        for start in range(0, len(refs), 64):
            requested = refs[start : start + 64]
            primary_error: ImouApiError | None = None
            payload: dict[str, Any] = {
                "deviceId": device_id,
                "groupControlFlg": str(group_control_flag),
                "productId": product_id,
                "properties": requested,
                "qos": IOT_CONTROL_QOS,
                "timeout": IOT_CONTROL_TIMEOUT_MS,
            }
            numeric_channel_id = _numeric_channel_id(channel_id)
            if numeric_channel_id is not None:
                payload["channelId"] = numeric_channel_id
            values: Mapping[str, Any] = {}
            try:
                data = await self._async_control_request_with_channel_fallback(
                    "GetProperties",
                    product_id,
                    device_id,
                    group_control_flag,
                    payload,
                    channel_id=channel_id,
                    fallback_on_any_error=True,
                )
                candidate = data.get("properties")
                if isinstance(candidate, Mapping):
                    values = candidate
                    result.update(candidate)
            except ImouAuthError:
                raise
            except ImouApiError as err:
                if not fallback_identifiers or err.code == 429:
                    raise
                primary_error = err
                values = {}

            if fallback_identifiers:
                missing = [
                    ref
                    for ref in requested
                    if ref not in values
                    and (not ref.isdigit() or int(ref) not in values)
                    and (identifier := str(fallback_identifiers.get(ref) or ""))
                    and identifier not in values
                ]
                if not missing and primary_error is not None:
                    raise primary_error
                if missing:
                    identifiers = [
                        str(fallback_identifiers[ref]) for ref in missing
                    ]
                    retry_payload = dict(payload)
                    retry_payload["properties"] = identifiers
                    try:
                        retry_data = await self._async_control_request_with_channel_fallback(
                            "GetProperties",
                            product_id,
                            device_id,
                            group_control_flag,
                            retry_payload,
                            channel_id=channel_id,
                            fallback_on_any_error=True,
                        )
                    except ImouAuthError:
                        raise
                    except ImouApiError as fallback_error:
                        if fallback_error.code == 429:
                            raise
                        if not values:
                            if primary_error is not None:
                                raise fallback_error from primary_error
                            raise
                        continue
                    retry_values = retry_data.get("properties")
                    if isinstance(retry_values, Mapping):
                        result.update(retry_values)
        return result

    async def async_set_properties(
        self,
        product_id: str,
        device_id: str,
        properties: Mapping[str, Any],
        *,
        group_control_flag: str = "0",
        channel_id: str | int | None = None,
        sync_local_cache: bool = False,
        fallback_identifiers: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Write numeric wire refs, then retry identifiers for legacy devices."""
        payload: dict[str, Any] = {
            "deviceId": device_id,
            "groupControlFlg": str(group_control_flag),
            "productId": product_id,
            "properties": _encode_iot_value(properties),
            "qos": IOT_CONTROL_QOS,
            "syncLocalCache": bool(sync_local_cache),
            "timeout": IOT_CONTROL_TIMEOUT_MS,
        }
        numeric_channel_id = _numeric_channel_id(channel_id)
        if numeric_channel_id is not None:
            payload["channelId"] = numeric_channel_id
        try:
            return await self._async_control_request_with_channel_fallback(
                "SetProperties",
                product_id,
                device_id,
                group_control_flag,
                payload,
                channel_id=channel_id,
                fallback_codes=PROPERTY_CONTROL_FALLBACK_CODES,
            )
        except (ImouAuthError, ImouConnectionError):
            raise
        except ImouApiError as err:
            if (
                not fallback_identifiers
                or err.code is None
                or 300 <= err.code < 600
            ):
                raise
            _LOGGER.debug(
                "Retrying Imou property write by identifiers code=%s",
                err.code,
            )
            retry_payload = dict(payload)
            retry_payload["properties"] = _encode_iot_value(fallback_identifiers)
            return await self._async_control_request_with_channel_fallback(
                "SetProperties",
                product_id,
                device_id,
                group_control_flag,
                retry_payload,
                channel_id=channel_id,
                fallback_codes=PROPERTY_CONTROL_FALLBACK_CODES,
            )

    async def async_invoke_service(
        self,
        product_id: str,
        device_id: str,
        service: str,
        input_data: Mapping[str, Any],
        *,
        group_control_flag: str = "0",
        channel_id: str | int | None = None,
        timeout_ms: int = IOT_CONTROL_TIMEOUT_MS,
    ) -> dict[str, Any]:
        """Invoke a service exposed by a product thing model."""
        service_ref = (
            _STREAM_SERVICE_REF
            if service == _STREAM_SERVICE_NAME
            else str(service)
        )
        payload: dict[str, Any] = {
            "deviceId": device_id,
            "groupControlFlg": str(group_control_flag),
            "inputData": _encode_iot_value(input_data),
            "productId": product_id,
            "qos": IOT_CONTROL_QOS,
            "service": service_ref,
            "timeout": max(1000, min(int(timeout_ms), 60000)),
        }
        numeric_channel_id = _numeric_channel_id(channel_id)
        if numeric_channel_id is not None:
            payload["channelId"] = numeric_channel_id
        mqtt_config = self.mqtt_config()
        if mqtt_config is not None:
            payload["mqttHost"] = mqtt_config.ssl_address or mqtt_config.tcp_address
        result = await self._async_control_request_with_channel_fallback(
            "SetService",
            product_id,
            device_id,
            group_control_flag,
            payload,
            channel_id=channel_id,
            fallback_codes=PROPERTY_CONTROL_FALLBACK_CODES
            | SERVICE_CONTROL_FALLBACK_CODES,
        )
        if service_ref == _STREAM_SERVICE_REF:
            return _normalize_stream_service_result(result)
        return result

    async def async_ptz_move(
        self,
        device_id: str,
        channel_id: str,
        *,
        horizontal: float,
        vertical: float,
        zoom: float = 0,
        duration: int = PTZ_STEP_DURATION_MS,
        host: str | None = None,
    ) -> None:
        """Move PTZ using the recovered cloud API.

        The Imou Life app normalizes the axes to ``[-1, 1]`` (pan/tilt use
        ``+-0.625`` and zoom uses ``+-0.5``) and always sends a duration. It
        targets the device stream-entry host when one is known; the account
        entry host answers ``12100`` (no authority) for cloud cameras.
        """
        payload = {
            "channelId": channel_id,
            "deviceId": device_id,
            "duration": duration,
            "horizontal": horizontal,
            "vertical": vertical,
            "zoom": zoom,
        }
        if not host:
            await self.async_request(PTZ_MOVE_API, PTZ_MOVE_REVISION, payload)
            return
        if not self.authenticated:
            await self.async_authenticate()
        try:
            await self._request_with_retries(
                PTZ_MOVE_API,
                PTZ_MOVE_REVISION,
                payload,
                base_url=host,
                ssl_context=await _async_device_ssl_context(),
            )
        except ImouAuthError as err:
            # A device host rejection is a PTZ capability problem, not a lost
            # account session, so it must not trigger the reauth flow.
            raise ImouApiError(str(err), err.code) from err

    @staticmethod
    def _stream_service_input(
        stream_id: str,
        *,
        optimized: bool,
        encrypt_mode: int,
        extra: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """Build the APK CMRealTransferStreamUrlRequest payload."""
        try:
            numeric_stream_id: int | str = int(stream_id)
        except (TypeError, ValueError):
            numeric_stream_id = stream_id
        payload: dict[str, Any] = {
            "assistStream": "false",
            "audioType": "0",
            "bindCid": "",
            "bindDid": "",
            "bindPid": "",
            "design": "first",
            "encrypt": encrypt_mode,
            "imageSize": 0,
            "mixNum": 0,
            "quic": "0",
            "skipAuth": "",
            "streamId": numeric_stream_id,
            "type": "RTSV1" if optimized else "",
        }
        if extra:
            payload.update(extra)
        return {
            _STREAM_INPUT_REFS.get(str(key), str(key)): value
            for key, value in payload.items()
        }

    def live_diagnostic(
        self,
        product_id: str,
        device_id: str,
        channel_id: str,
        stream_id: str = "0",
    ) -> str:
        """Return a safe summary of the last stream negotiation result."""
        return self._live_diagnostics.get(
            (product_id, device_id, channel_id, stream_id),
            "not_requested",
        )

    def live_mode(
        self,
        product_id: str,
        device_id: str,
        channel_id: str,
        stream_id: str = "0",
    ) -> str:
        """Return the mode that produced the last playable live URL, if any."""
        cache_key = (product_id, device_id, channel_id, stream_id)
        if not self._live_diagnostics.get(cache_key, "").startswith("playable:"):
            return ""
        return self._live_modes.get(cache_key, "")

    def reject_live_mode(
        self,
        product_id: str,
        device_id: str,
        channel_id: str,
        stream_id: str,
        mode: str,
        *,
        ttl: float = LIVE_MODE_REJECT_TTL,
    ) -> None:
        """Try ``mode`` last for ``ttl`` seconds: the links it gave did not play.

        The mode is not dropped, so a camera with no other working mode keeps
        getting it.
        """
        if not mode:
            return
        cache_key = (product_id, device_id, channel_id, stream_id)
        self._live_rejected.setdefault(cache_key, {})[mode] = time.monotonic() + ttl
        if self._live_modes.get(cache_key) == mode:
            del self._live_modes[cache_key]
        self._live_cache.pop(cache_key, None)

    def _rejected_live_modes(self, cache_key: tuple[str, str, str, str]) -> set[str]:
        rejected = self._live_rejected.get(cache_key)
        if not rejected:
            return set()
        now = time.monotonic()
        for mode in [mode for mode, until in rejected.items() if until <= now]:
            del rejected[mode]
        if not rejected:
            del self._live_rejected[cache_key]
        return set(rejected)

    async def async_get_live_url(
        self,
        product_id: str,
        device_id: str,
        channel_id: str,
        *,
        stream_id: str = "0",
        extra: Mapping[str, Any] | None = None,
        use_cache: bool = True,
    ) -> dict[str, Any]:
        """Generate on-demand cloud transfer resources with a short cache.

        ``use_cache=False`` always asks Imou for new resources; transfer URLs
        are single-use, so every new RTSP session needs its own.
        """
        cache_key = (product_id, device_id, channel_id, stream_id)
        cached = self._live_cache.get(cache_key)
        if use_cache and cached and cached[0] > time.monotonic():
            return dict(cached[1])

        standard_payload: MutableMapping[str, Any] = {
            "channelId": channel_id,
            "deviceId": device_id,
            "streamId": stream_id,
        }
        transfer_payload: MutableMapping[str, Any] = {
            "assistStream": "false",
            "audioType": 0,
            "channelId": channel_id,
            "design": "first",
            "deviceId": device_id,
            "encrypt": "0",
            "imageSize": 0,
            "productId": product_id,
            "quic": "0",
            "skipAuth": "",
            "streamId": stream_id,
            "timeLimit": False,
            "videoLimit": 0,
        }
        if extra:
            transfer_payload.update(extra)
        optimized_payload = {
            **transfer_payload,
            "owner": "",
            "ownerType": "base",
            "type": "RTSV1",
        }
        last_error: ImouApiError | None = None
        last_result: dict[str, Any] | None = None

        # Transfer links (RTSP over TLS) come first: the standard API answers
        # some models (e.g. Bullet 2C) with relay links that hang up at once.
        # The mode that last played goes first; modes whose links did not play
        # (see ``reject_live_mode``) go last for a while.
        attempts: list[tuple[str, str, Any]] = [
            ("transfer", "direct", transfer_payload),
            ("rtsv1", "direct", optimized_payload),
            *(
                (f"standard-{stream_type.casefold()}", "standard", stream_type)
                for stream_type in ("RTSP", "HLS", "FLV", "RTMP")
            ),
            ("service-rtsv1", "service", True),
            ("service-standard", "service", False),
        ]
        preferred_mode = self._live_modes.get(cache_key)
        rejected = self._rejected_live_modes(cache_key)
        attempts.sort(
            key=lambda attempt: (attempt[0] in rejected, attempt[0] != preferred_mode)
        )
        standard_down = False
        for mode, family, option in attempts:
            if family == "standard" and standard_down:
                continue
            try:
                if family == "direct":
                    result = await self.async_request(
                        "things.media.GetRealTransferStreamUrl", "197891", option
                    )
                elif family == "standard":
                    result = await self.async_request(
                        "device.info.GetLiveStreamUrl",
                        "39565",
                        {**standard_payload, "streamType": option},
                    )
                else:
                    result = await self.async_invoke_service(
                        product_id,
                        device_id,
                        _STREAM_SERVICE_REF,
                        self._stream_service_input(
                            stream_id,
                            optimized=option,
                            encrypt_mode=0,
                            extra=extra,
                        ),
                        channel_id=channel_id,
                        timeout_ms=IOT_STREAM_TIMEOUT_MS,
                    )
            except ImouAuthError:
                raise
            except ImouApiError as err:
                connection_error = isinstance(err, ImouConnectionError)
                if err.code == 429 or (family == "service" and connection_error):
                    raise
                last_error = err
                _LOGGER.debug("Imou live URL unavailable mode=%s code=%s", mode, err.code)
                if family == "standard" and connection_error:
                    standard_down = True
                continue
            last_result = dict(result)
            if not _contains_playable_live_url(result):
                if _contains_live_url(result):
                    if family == "standard":
                        self._live_diagnostics[cache_key] = "private_transport"
                    _LOGGER.debug("Imou live URL uses private transport mode=%s", mode)
                continue
            self._live_modes[cache_key] = mode
            self._live_diagnostics[cache_key] = f"playable:{mode}"
            self._live_cache[cache_key] = (time.monotonic() + 20, dict(result))
            return result
        if last_result is not None:
            self._live_diagnostics[cache_key] = (
                "private_transport"
                if _contains_live_url(last_result)
                else "no_stream_url"
            )
            self._live_cache[cache_key] = (
                time.monotonic() + 20,
                dict(last_result),
            )
            return last_result
        self._live_diagnostics[cache_key] = (
            f"api_error:{last_error.code}"
            if last_error is not None and last_error.code is not None
            else "unavailable"
        )
        raise last_error or ImouApiError("Imou did not return a live stream URL")

    async def async_fetch_bytes(
        self, url: str, *, max_bytes: int = MAX_IMAGE_BYTES
    ) -> bytes:
        """Fetch a bounded snapshot without blocking the event loop."""
        try:
            async with (
                self._semaphore,
                self._session.get(url, timeout=self.request_timeout) as response,
            ):
                if response.status >= 400:
                    raise ImouConnectionError(f"Snapshot HTTP {response.status}")
                data = await _read_bounded(response.content, max_bytes)
        except ImouConnectionError:
            raise
        except Exception:
            raise ImouConnectionError("Snapshot request failed") from None
        if len(data) > max_bytes:
            raise ImouConnectionError("Snapshot exceeded size limit")
        return data
