"""Local RTSP relay over the Dahua/Imou P2P transport."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import secrets
import socket
import struct
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote
from xml.etree import ElementTree

from .models import ImouChannel, ImouDevice

_LOGGER = logging.getLogger(__name__)

_CLOUD_HOST = "www.easy4ipcloud.com"
_CLOUD_PORT = 8800
_CLOUD_USERNAME = "cba1b29e32cb17aa46b8ff9e73c7f40b"
_CLOUD_USERKEY = "996103384cdf19179e19243e959bbf8b"
_DEVICE_INFO_KEY = b"kRjmsUB&ezmdGLL67H#$ojw@XflcaIaf"
_DEVICE_INFO_IV = b"MydvJw*Iw1w&i^kk"
_ADDRESS_IV = b"2z52*lk9o6HRyJrf"
_HANDSHAKE_TIMEOUT = 10.0
_CONNECT_TIMEOUT = 10.0
_HEARTBEAT_SECONDS = 5.0
_MAX_DATAGRAM_BYTES = 65535
_MAX_CLIENT_BUFFER = 128
_DEFAULT_RTSP_PORT = 554


class ImouP2PError(Exception):
    """A bounded P2P connection failure safe for diagnostics."""

    def __init__(self, stage: str) -> None:
        super().__init__(stage)
        self.stage = stage


class _ImouP2PAuthRequired(ImouP2PError):
    """The camera requires credentials for P2P channel creation."""


@dataclass(slots=True, frozen=True)
class ImouP2PDeviceConfig:
    """Sensitive device connection metadata kept out of entity attributes."""

    serial: str
    p2p_username: str = field(default="", repr=False)
    p2p_password: str = field(default="", repr=False)
    p2p_type: int = 0
    p2p_port: int = _DEFAULT_RTSP_PORT
    rtsp_username: str = field(default="", repr=False)
    rtsp_password: str = field(default="", repr=False)

    @property
    def can_authenticate_p2p(self) -> bool:
        """Return whether a complete P2P credential pair is available."""
        return bool(self.p2p_username and self.p2p_password)


@dataclass(slots=True)
class _DhResponse:
    code: int
    status: str
    values: dict[str, str]


class _UdpEndpoint:
    """One non-blocking UDP socket whose local port stays stable."""

    def __init__(self, udp_socket: socket.socket) -> None:
        self.socket = udp_socket
        self.loop = asyncio.get_running_loop()
        self._resolved: dict[tuple[str, int], tuple[str, int]] = {}

    @classmethod
    async def async_create(cls) -> _UdpEndpoint:
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.setblocking(False)
        udp_socket.bind(("0.0.0.0", 0))
        return cls(udp_socket)

    @property
    def local_port(self) -> int:
        """Return the stable local UDP port."""
        return int(self.socket.getsockname()[1])

    async def async_resolve(self, host: str, port: int) -> tuple[str, int]:
        """Resolve one IPv4 UDP endpoint with a small in-session cache."""
        key = (host, port)
        if key in self._resolved:
            return self._resolved[key]
        try:
            addresses = await self.loop.getaddrinfo(
                host,
                port,
                family=socket.AF_INET,
                type=socket.SOCK_DGRAM,
            )
        except OSError as err:
            raise ImouP2PError("dns") from err
        if not addresses:
            raise ImouP2PError("dns")
        address = addresses[0][4]
        resolved = (str(address[0]), int(address[1]))
        self._resolved[key] = resolved
        return resolved

    async def async_sendto(
        self, data: bytes, target: tuple[str, int]
    ) -> None:
        """Send one datagram."""
        try:
            await self.loop.sock_sendto(self.socket, data, target)
        except OSError as err:
            raise ImouP2PError("udp_send") from err

    async def async_recvfrom(
        self, timeout: float | None = None
    ) -> tuple[bytes, tuple[str, int]]:
        """Receive one bounded datagram."""
        try:
            receive = self.loop.sock_recvfrom(self.socket, _MAX_DATAGRAM_BYTES)
            if timeout is not None:
                return await asyncio.wait_for(receive, timeout)
            return await receive
        except TimeoutError as err:
            raise ImouP2PError("timeout") from err
        except OSError as err:
            raise ImouP2PError("udp_receive") from err

    def close(self) -> None:
        """Close the UDP socket."""
        self.socket.close()


def plain_credential(value: Any) -> str:
    """Return ``value`` unless it looks like Imou's encrypted credential blob.

    BasicInfoQueryV2 may return ``deviceUsername``/``devicePassword`` as base64
    AES ciphertext (e.g. 24 characters = one 16-byte block). Using that as a
    login only produces 401s, so callers fall back to ``admin`` or the
    Safety Code typed by the user.
    """
    text = str(value or "").strip()
    if len(text) < 24 or len(text) % 4:
        return text
    try:
        decoded = base64.b64decode(text, validate=True)
    except ValueError:
        return text
    return "" if len(decoded) % 16 == 0 else text


def p2p_config_from_device(device: ImouDevice) -> ImouP2PDeviceConfig:
    """Extract P2P and RTSP credentials returned by BasicInfoQueryV2."""
    raw = device.raw if isinstance(device.raw, Mapping) else {}
    p2p_raw = raw.get("p2pConfig")
    if not isinstance(p2p_raw, Mapping):
        p2p_raw = {}
    device_username = plain_credential(raw.get("deviceUsername"))
    device_password = plain_credential(raw.get("devicePassword"))
    p2p_username = str(
        p2p_raw.get("account")
        or p2p_raw.get("accountNew")
        or p2p_raw.get("username")
        or p2p_raw.get("user")
        or device_username
    ).strip()
    p2p_password = str(
        p2p_raw.get("password")
        or p2p_raw.get("p2pToken")
        or p2p_raw.get("ak")
        or p2p_raw.get("accessKey")
        or p2p_raw.get("secret")
        or p2p_raw.get("token")
        or device_password
    ).strip()
    try:
        p2p_type = int(p2p_raw.get("type") or 0)
    except (TypeError, ValueError):
        p2p_type = 0
    p2p_port = _safe_port(p2p_raw.get("port"), _DEFAULT_RTSP_PORT)
    return ImouP2PDeviceConfig(
        serial=device.device_id,
        p2p_username=p2p_username,
        p2p_password=p2p_password,
        p2p_type=p2p_type,
        p2p_port=p2p_port,
        rtsp_username=device_username,
        rtsp_password=device_password,
    )


def rtsp_channel_number(device: ImouDevice, channel: ImouChannel) -> int:
    """Convert Imou channel IDs to Dahua's one-based RTSP channel number."""
    try:
        requested = int(channel.channel_id)
    except (TypeError, ValueError):
        return 1
    numeric_ids: list[int] = []
    for item in device.channels:
        try:
            numeric_ids.append(int(item.channel_id))
        except (TypeError, ValueError):
            continue
    if 0 in numeric_ids:
        return max(1, requested + 1)
    if numeric_ids and min(numeric_ids) >= 1:
        return max(1, requested)
    return max(1, requested + 1)


def build_rtsp_url(
    config: ImouP2PDeviceConfig,
    local_port: int,
    channel_number: int,
) -> str:
    """Build a loopback RTSP URL without exposing it in diagnostics."""
    user_info = ""
    if config.rtsp_username:
        username = quote(config.rtsp_username, safe="")
        if config.rtsp_password:
            password = quote(config.rtsp_password, safe="")
            user_info = f"{username}:{password}@"
        else:
            user_info = f"{username}@"
    return (
        f"rtsp://{user_info}127.0.0.1:{local_port}"
        f"/cam/realmonitor?channel={max(1, channel_number)}&subtype=0"
    )


def build_local_rtsp_url(
    config: ImouP2PDeviceConfig,
    host: str,
    channel_number: int,
    subtype: int = 0,
) -> str:
    """Build a direct RTSP URL when the device is on the same LAN as HA."""
    user_info = ""
    if config.rtsp_username:
        username = quote(config.rtsp_username, safe="")
        if config.rtsp_password:
            password = quote(config.rtsp_password, safe="")
            user_info = f"{username}:{password}@"
        else:
            user_info = f"{username}@"
    port = config.p2p_port
    return (
        f"rtsp://{user_info}{host}:{port}"
        f"/cam/realmonitor?channel={max(1, channel_number)}&subtype={max(0, subtype)}"
    )


def _device_ip_candidates(device: ImouDevice) -> list[str]:
    raw = device.raw if isinstance(device.raw, Mapping) else {}
    candidates: list[str] = []
    for key in (
        "ip", "lanIp", "lan_ip", "localIp", "local_ip", "deviceIp",
        "device_ip", "host", "addr", "address",
    ):
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            candidates.append(value.strip())
    for key in ("ipList", "lanIpList", "localIpList", "deviceIpList"):
        values = raw.get(key)
        if isinstance(values, (list, tuple)):
            for item in values:
                if isinstance(item, str) and item.strip():
                    candidates.append(item.strip())
    return list(dict.fromkeys(candidates))


def device_local_rtsp_url(
    device: ImouDevice,
    channel: ImouChannel,
    *,
    subtype: int = 0,
) -> str | None:
    """Build a LAN RTSP URL when device metadata supplies its LAN IP."""
    config = p2p_config_from_device(device)
    if not config.rtsp_username or not config.rtsp_password:
        return None
    candidates = _device_ip_candidates(device)
    if not candidates:
        return None
    host = candidates[0]
    if not host:
        return None
    return build_local_rtsp_url(
        config, host, rtsp_channel_number(device, channel), subtype
    )


def _parse_address(value: str, stage: str) -> tuple[str, int]:
    host, separator, raw_port = value.strip().rpartition(":")
    if not separator or not host:
        raise ImouP2PError(stage)
    try:
        port = int(raw_port)
    except ValueError as err:
        raise ImouP2PError(stage) from err
    if not 1 <= port <= 65535:
        raise ImouP2PError(stage)
    return host, port


def _xml_values(body: str) -> dict[str, str]:
    if not body.strip():
        return {}
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError as err:
        raise ImouP2PError("cloud_xml") from err
    values: dict[str, str] = {}
    for element in root.iter():
        value = (element.text or "").strip()
        if not value:
            continue
        tag = str(element.tag).rsplit("}", 1)[-1]
        values[tag] = value
    return values


def _parse_response(payload: bytes) -> _DhResponse:
    try:
        head, body = payload.decode("utf-8", "replace").split("\r\n\r\n", 1)
        lines = head.split("\r\n")
        _version, raw_code, status = lines[0].split(" ", 2)
        code = int(raw_code)
    except (ValueError, IndexError) as err:
        raise ImouP2PError("cloud_response") from err
    return _DhResponse(code, status, _xml_values(body))


def _cloud_request(path: str, body: str | None, sequence: int) -> bytes:
    nonce = secrets.randbelow(2**31)
    created = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    password = f"{nonce}{created}DHP2P:{_CLOUD_USERNAME}:{_CLOUD_USERKEY}"
    digest = base64.b64encode(hashlib.sha1(password.encode()).digest()).decode()
    request_body = body or ""
    request_body_bytes = request_body.encode()
    lines = [
        f"{'DHPOST' if body is not None else 'DHGET'} {path} HTTP/1.1",
        f"CSeq: {sequence}",
        'Authorization: WSSE profile="UsernameToken"',
        (
            'X-WSSE: UsernameToken Username="'
            f'{_CLOUD_USERNAME}", PasswordDigest="{digest}", '
            f'Nonce="{nonce}", Created="{created}"'
        ),
    ]
    if body is not None:
        lines.extend(
            ("Content-Type: ", f"Content-Length: {len(request_body_bytes)}")
        )
    return "\r\n".join(lines).encode() + b"\r\n\r\n" + request_body_bytes


async def _async_dh_request(
    endpoint: _UdpEndpoint,
    target: tuple[str, int],
    path: str,
    sequence: int,
    body: str | None = None,
    *,
    read_response: bool = True,
) -> _DhResponse | None:
    await endpoint.async_sendto(_cloud_request(path, body, sequence), target)
    if not read_response:
        return None
    payload, _source = await endpoint.async_recvfrom(_HANDSHAKE_TIMEOUT)
    response = _parse_response(payload)
    if response.code == 100:
        payload, _source = await endpoint.async_recvfrom(_HANDSHAKE_TIMEOUT)
        response = _parse_response(payload)
    return response


def _require_success(response: _DhResponse | None, stage: str) -> _DhResponse:
    if response is None:
        raise ImouP2PError(stage)
    if response.code >= 400:
        if response.code == 403 and stage == "p2p_channel":
            raise _ImouP2PAuthRequired(stage)
        raise ImouP2PError(f"{stage}_{response.code}")
    return response


def _device_info(encoded: str) -> dict[str, Any]:
    if not encoded:
        return {}
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        decryptor = Cipher(
            algorithms.AES(_DEVICE_INFO_KEY), modes.OFB(_DEVICE_INFO_IV)
        ).decryptor()
        decoded = base64.b64decode(encoded)
        plaintext = decryptor.update(decoded) + decryptor.finalize()
        value = json.loads(plaintext.rstrip(b"\x00").decode())
    except (ImportError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _device_key(username: str, password: str, random_salt: str) -> bytes:
    value = f"{username}:Login to {random_salt}:{password}"
    return hashlib.md5(value.encode()).hexdigest().upper().encode()


def _encrypt_address(key: bytes, nonce: int, address: str) -> str:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as err:
        raise ImouP2PError("crypto_unavailable") from err
    derived_key = hashlib.pbkdf2_hmac(
        "sha256", key, str(nonce).encode(), 20000, 32
    )
    encryptor = Cipher(algorithms.AES(derived_key), modes.OFB(_ADDRESS_IV)).encryptor()
    encrypted = encryptor.update(address.encode()) + encryptor.finalize()
    return base64.b64encode(encrypted).decode()


def _safe_port(value: Any, default: int = _DEFAULT_RTSP_PORT) -> int:
    try:
        port = int(value or default)
    except (TypeError, ValueError):
        return default
    return port if 1 <= port <= 65535 else default


def _decrypt_address(key: bytes, nonce: int, encoded: str) -> str:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as err:
        raise ImouP2PError("crypto_unavailable") from err
    try:
        derived_key = hashlib.pbkdf2_hmac(
            "sha256", key, str(nonce).encode(), 20000, 32
        )
        decryptor = Cipher(
            algorithms.AES(derived_key), modes.OFB(_ADDRESS_IV)
        ).decryptor()
        decoded = base64.b64decode(encoded, validate=True)
        plaintext = decryptor.update(decoded) + decryptor.finalize()
        return plaintext.decode()
    except ValueError as err:
        raise ImouP2PError("device_local_decrypt") from err


def _device_auth(
    username: str,
    key: bytes,
    nonce: int,
    random_salt: str,
    payload: str = "",
) -> str:
    created = int(time.time())
    message = f"{nonce}{created}{payload}".encode()
    digest = base64.b64encode(hmac.new(key, message, hashlib.sha256).digest()).decode()
    salt = f"<RandSalt>{random_salt}</RandSalt>" if random_salt else ""
    escaped_username = (
        username.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    return (
        f"<CreateDate>{created}</CreateDate>"
        f"<DevAuth>{digest}</DevAuth>"
        f"<Nonce>{nonce}</Nonce>"
        f"{salt}<UserName>{escaped_username}</UserName>"
    )


class _PtcSession:
    """Track PTCP byte and message counters for one device session."""

    def __init__(self) -> None:
        self.sent = 0
        self.received = 0
        self.count = 0
        self.message_id = 0
        self.remote_message_id = 0

    def build(self, body: bytes, *, sync: bool = False) -> bytes:
        """Serialize one PTCP packet and advance local counters."""
        packet_id = (
            0x0002FFFF if sync else (0x0000FFFF - self.count) & 0xFFFFFFFF
        )
        packet = struct.pack(
            "!4sLLLLL",
            b"PTCP",
            self.sent & 0xFFFFFFFF,
            self.received & 0xFFFFFFFF,
            packet_id,
            self.message_id,
            self.remote_message_id,
        ) + body
        self.sent = (self.sent + len(body)) & 0xFFFFFFFF
        self.message_id = (self.message_id + 1) & 0xFFFFFFFF
        if body and not sync:
            self.count = (self.count + 1) & 0xFFFFFFFF
        return packet

    def receive(self, packet: bytes) -> bytes:
        """Parse one PTCP packet and advance remote counters."""
        if len(packet) < 24:
            raise ImouP2PError("ptcp_packet")
        magic, _sent, _received, _packet_id, remote_id, _ack_id = struct.unpack(
            "!4sLLLLL", packet[:24]
        )
        if magic != b"PTCP":
            raise ImouP2PError("ptcp_packet")
        body = packet[24:]
        self.received = (self.received + len(body)) & 0xFFFFFFFF
        self.remote_message_id = remote_id
        return body


@dataclass(slots=True)
class _HandshakeResult:
    endpoint: _UdpEndpoint
    target: tuple[str, int]
    session: _PtcSession
    remote_rtsp_port: int


async def _async_receive_from(
    endpoint: _UdpEndpoint,
    target: tuple[str, int],
    timeout: float,
    stage: str,
    *,
    prefix: bytes = b"",
) -> bytes:
    deadline = asyncio.get_running_loop().time() + timeout
    for _ in range(64):
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            break
        try:
            payload, source = await endpoint.async_recvfrom(remaining)
        except ImouP2PError as err:
            if err.stage == "timeout":
                raise ImouP2PError(stage) from err
            raise
        if source == target and payload.startswith(prefix):
            return payload
    raise ImouP2PError(stage)


async def _async_expect_ptcp(
    endpoint: _UdpEndpoint,
    target: tuple[str, int],
    session: _PtcSession,
    expected_type: int | None,
    stage: str,
) -> bytes:
    deadline = asyncio.get_running_loop().time() + _HANDSHAKE_TIMEOUT
    for _ in range(64):
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            break
        packet = await _async_receive_from(
            endpoint, target, remaining, stage, prefix=b"PTCP"
        )
        body = session.receive(packet)
        if not body:
            if expected_type is None:
                return body
            continue
        if expected_type is not None and body[0] == expected_type:
            return body
        if body[0] == 0x13:
            await endpoint.async_sendto(session.build(b""), target)
            continue
        raise ImouP2PError(stage)
    raise ImouP2PError(stage)


async def _async_handshake(
    config: ImouP2PDeviceConfig, *, authenticated: bool
) -> _HandshakeResult:
    device_endpoint = await _UdpEndpoint.async_create()
    relay_endpoint: _UdpEndpoint | None = None
    sequence = 0
    completed = False

    async def request(
        endpoint: _UdpEndpoint,
        target: tuple[str, int],
        path: str,
        body: str | None = None,
        *,
        read_response: bool = True,
    ) -> _DhResponse | None:
        nonlocal sequence
        sequence += 1
        return await _async_dh_request(
            endpoint,
            target,
            path,
            sequence,
            body,
            read_response=read_response,
        )

    try:
        cloud = await device_endpoint.async_resolve(_CLOUD_HOST, _CLOUD_PORT)
        _require_success(
            await request(device_endpoint, cloud, "/probe/p2psrv"), "cloud_probe"
        )
        p2p_response = _require_success(
            await request(
                device_endpoint, cloud, f"/online/p2psrv/{config.serial}"
            ),
            "p2p_lookup",
        )
        p2p_server = _parse_address(p2p_response.values.get("US", ""), "p2p_server")
        relay_response = _require_success(
            await request(device_endpoint, cloud, "/online/relay"), "relay_lookup"
        )
        relay_server = _parse_address(
            relay_response.values.get("Address", ""), "relay_server"
        )

        relay_endpoint = await _UdpEndpoint.async_create()
        p2p_target = await relay_endpoint.async_resolve(*p2p_server)
        _require_success(
            await request(
                relay_endpoint, p2p_target, f"/probe/device/{config.serial}"
            ),
            "device_probe",
        )
        info: dict[str, Any] = {}
        try:
            info_response = await request(
                relay_endpoint, p2p_target, f"/info/device/{config.serial}"
            )
            if info_response is not None and info_response.code < 300:
                info = _device_info(info_response.values.get("Info", ""))
        except ImouP2PError:
            info = {}

        random_salt = str(info.get("randsalt") or "")
        remote_rtsp_port = _safe_port(info.get("rtspport"))

        identify_bytes = secrets.token_bytes(8)
        identify = " ".join(f"{value:x}" for value in identify_bytes)
        local_address = f"127.0.0.1:{device_endpoint.local_port}"
        key = b""
        request_nonce = 0
        auth = ""
        if authenticated:
            if not config.can_authenticate_p2p:
                raise ImouP2PError("p2p_credentials_missing")
            key = _device_key(
                config.p2p_username, config.p2p_password, random_salt
            )
            request_nonce = secrets.randbelow(2**31)
            encrypted_address = _encrypt_address(key, request_nonce, local_address)
            auth = _device_auth(
                config.p2p_username,
                key,
                request_nonce,
                random_salt,
                encrypted_address,
            )
            address_xml = (
                f"<IpEncrptV2>true</IpEncrptV2>"
                f"<LocalAddr>{encrypted_address}</LocalAddr>"
            )
        else:
            address_xml = (
                f"<IpEncrpt>true</IpEncrpt><LocalAddr>{local_address}</LocalAddr>"
            )
        channel_body = (
            f"<body>{auth}<Identify>{identify}</Identify>{address_xml}"
            "<version>5.0.0</version></body>"
        )
        await request(
            device_endpoint,
            cloud,
            f"/device/{config.serial}/p2p-channel",
            channel_body,
            read_response=False,
        )

        relay_target = await relay_endpoint.async_resolve(*relay_server)
        agent_response = _require_success(
            await request(relay_endpoint, relay_target, "/relay/agent"),
            "relay_agent",
        )
        token = agent_response.values.get("Token", "")
        agent_address = _parse_address(
            agent_response.values.get("Agent", ""), "relay_agent_address"
        )
        agent = await relay_endpoint.async_resolve(*agent_address)
        _require_success(
            await request(
                relay_endpoint,
                agent,
                f"/relay/start/{token}",
                "<body><Client>:0</Client></body>",
            ),
            "relay_start",
        )

        channel_payload, _source = await device_endpoint.async_recvfrom(
            _HANDSHAKE_TIMEOUT
        )
        channel_response = _parse_response(channel_payload)
        if channel_response.code == 100:
            channel_payload, _source = await device_endpoint.async_recvfrom(
                _HANDSHAKE_TIMEOUT
            )
            channel_response = _parse_response(channel_payload)
        channel_response = _require_success(channel_response, "p2p_channel")

        device_public = _parse_address(
            channel_response.values.get("PubAddr", ""), "device_public"
        )
        response_nonce = request_nonce
        if authenticated:
            try:
                response_nonce = int(
                    channel_response.values.get("Nonce") or request_nonce
                )
            except (TypeError, ValueError):
                response_nonce = request_nonce
        device_local_raw = channel_response.values.get("LocalAddr", "")
        if authenticated and device_local_raw:
            device_local = _decrypt_address(key, response_nonce, device_local_raw)
        else:
            device_local = device_local_raw or local_address

        relay_auth = ""
        if authenticated:
            relay_auth = _device_auth(
                config.p2p_username,
                key,
                response_nonce,
                random_salt,
            )
        relay_body = (
            f"<body>{relay_auth}<agentAddr>{agent_address[0]}:"
            f"{agent_address[1]}</agentAddr></body>"
        )
        await request(
            relay_endpoint,
            cloud,
            f"/device/{config.serial}/relay-channel",
            relay_body,
            read_response=False,
        )
        relay_notice = await _async_receive_from(
            relay_endpoint, agent, _HANDSHAKE_TIMEOUT, "relay_channel"
        )
        _require_success(_parse_response(relay_notice), "relay_channel")

        agent_session = _PtcSession()
        await relay_endpoint.async_sendto(
            agent_session.build(b"\x00\x03\x01\x00", sync=True), agent
        )
        agent_sync = await _async_expect_ptcp(
            relay_endpoint, agent, agent_session, 0x00, "agent_sync"
        )
        if agent_sync != b"\x00\x03\x01\x00":
            raise ImouP2PError("agent_sync")
        await relay_endpoint.async_sendto(
            agent_session.build(b"\x17" + b"\x00" * 11), agent
        )
        sign_body = await _async_expect_ptcp(
            relay_endpoint, agent, agent_session, 0x18, "agent_sign"
        )
        if not 12 < len(sign_body) <= 4096:
            raise ImouP2PError("agent_sign")
        sign = sign_body[12:]
        await relay_endpoint.async_sendto(agent_session.build(b""), agent)

        device_target = await device_endpoint.async_resolve(*device_public)
        device_host, device_port = _parse_address(
            device_local.rsplit(",", 1)[-1], "device_local"
        )
        try:
            local_bytes = struct.pack("!H", device_port) + socket.inet_aton(device_host)
            public_bytes = struct.pack("!H", device_target[1]) + socket.inet_aton(
                device_target[0]
            )
        except (OSError, struct.error) as err:
            raise ImouP2PError("device_address") from err
        identify_inverted = bytes(value ^ 0xFF for value in identify_bytes)
        cookie = secrets.token_bytes(4)
        transaction = secrets.token_bytes(12)
        await device_endpoint.async_sendto(
            b"\xff\xfe\xff\xe7"
            + cookie
            + transaction
            + b"\x7f\xd5\xff\xf7"
            + identify_inverted
            + b"\xff\xfb\xff\xf7\xff\xfe"
            + bytes(value ^ 0xFF for value in public_bytes),
            device_target,
        )
        response = await _async_receive_from(
            device_endpoint, device_target, _HANDSHAKE_TIMEOUT, "device_punch"
        )
        if len(response) < 20:
            raise ImouP2PError("device_punch")
        remote_transaction = response[8:20]
        await device_endpoint.async_sendto(
            b"\xfe\xfe\xff\xe7"
            + cookie
            + remote_transaction
            + b"\x7f\xd6\xff\xf7"
            + identify_inverted
            + b"\xff\xfb\xff\xf7\xff\xfe"
            + bytes(value ^ 0xFF for value in local_bytes),
            device_target,
        )
        if authenticated:
            await _async_receive_from(
                device_endpoint, device_target, _HANDSHAKE_TIMEOUT, "device_punch_auth"
            )
            punch_auth = (
                b"\xfe\xfe\xff\xf3"
                + cookie
                + remote_transaction
                + b"\x7f\xd6\xff\xf7"
                + identify_inverted
                + b"\xff\xfb\xff\xf7\xff\xfe"
                + b"\xa8\x13\x3f\x57\xfe\x37"
            )
            for _ in range(5):
                await device_endpoint.async_sendto(punch_auth, device_target)
        for _ in range(5):
            try:
                await _async_receive_from(
                    device_endpoint, device_target, 1.0, "device_punch_finish"
                )
            except ImouP2PError as err:
                if err.stage != "device_punch_finish":
                    raise
                break

        device_session = _PtcSession()
        await device_endpoint.async_sendto(
            device_session.build(b"\x00\x03\x01\x00", sync=True), device_target
        )
        device_sync = await _async_expect_ptcp(
            device_endpoint, device_target, device_session, 0x00, "device_sync"
        )
        if device_sync != b"\x00\x03\x01\x00":
            raise ImouP2PError("device_sync")
        await device_endpoint.async_sendto(
            device_session.build(b"\x19" + b"\x00" * 11 + sign), device_target
        )
        await _async_expect_ptcp(
            device_endpoint, device_target, device_session, 0x1A, "device_auth"
        )
        await device_endpoint.async_sendto(
            device_session.build(b"\x1b" + b"\x00" * 11), device_target
        )
        await _async_expect_ptcp(
            device_endpoint, device_target, device_session, None, "device_auth_ack"
        )

        completed = True
        return _HandshakeResult(
            endpoint=device_endpoint,
            target=device_target,
            session=device_session,
            remote_rtsp_port=remote_rtsp_port,
        )
    finally:
        if relay_endpoint is not None:
            relay_endpoint.close()
        if not completed:
            device_endpoint.close()


class ImouP2PRelay:
    """One shared local TCP listener backed by one camera P2P session."""

    _CLOSE_TIMEOUT = 5.0

    def __init__(self, config: ImouP2PDeviceConfig) -> None:
        self.config = config
        self.status = "idle"
        self.local_port: int | None = None
        self._endpoint: _UdpEndpoint | None = None
        self._target: tuple[str, int] | None = None
        self._session: _PtcSession | None = None
        self._remote_rtsp_port = _DEFAULT_RTSP_PORT
        self._server: asyncio.AbstractServer | None = None
        self._start_lock = asyncio.Lock()
        self._start_task: asyncio.Task[Any] | None = None
        self._close_task: asyncio.Task[None] | None = None
        self._generation = 0
        self._send_lock = asyncio.Lock()
        self._reader_task: asyncio.Task[None] | None = None
        self._heartbeat_task: asyncio.Task[None] | None = None
        self._client_tasks: set[asyncio.Task[Any]] = set()
        self._client_queues: dict[int, asyncio.Queue[bytes | None]] = {}
        self._client_writers: dict[int, asyncio.StreamWriter] = {}
        self._connect_waiters: dict[int, asyncio.Future[None]] = {}
        self._closing = False

    @property
    def ready(self) -> bool:
        """Return whether the relay can currently accept RTSP clients."""
        return (
            not self._closing
            and self.status == "ready"
            and self.local_port is not None
            and self._server is not None
            and self._reader_task is not None
            and not self._reader_task.done()
        )

    async def async_start(self) -> None:
        """Establish P2P and expose an ephemeral loopback TCP listener."""
        if self.ready:
            return
        generation = self._generation
        if self._close_task is not None and not self._close_task.done():
            raise ImouP2PError("session_closed")
        async with self._start_lock:
            if generation != self._generation:
                raise ImouP2PError("session_closed")
            if self.ready:
                return
            self._start_task = asyncio.current_task()
            try:
                await self._async_close_resources()
                if generation != self._generation:
                    raise ImouP2PError("session_closed")
                self._closing = False
                self.status = "connecting"
                authenticated_first = self.config.p2p_type > 0
                attempts = [authenticated_first]
                if self.config.can_authenticate_p2p and not authenticated_first:
                    attempts.append(True)
                if authenticated_first:
                    attempts.append(False)
                last_error: ImouP2PError | None = None
                result: _HandshakeResult | None = None
                for authenticated in dict.fromkeys(attempts):
                    if generation != self._generation:
                        raise ImouP2PError("session_closed")
                    if authenticated and not self.config.can_authenticate_p2p:
                        continue
                    try:
                        result = await _async_handshake(
                            self.config, authenticated=authenticated
                        )
                        break
                    except ImouP2PError as err:
                        last_error = err
                        if not isinstance(err, _ImouP2PAuthRequired) and len(attempts) == 1:
                            break
                if result is None:
                    self.status = f"error:{(last_error or ImouP2PError('handshake')).stage}"
                    raise last_error or ImouP2PError("handshake")
                self._endpoint = result.endpoint
                self._target = result.target
                self._session = result.session
                self._remote_rtsp_port = result.remote_rtsp_port
                if generation != self._generation:
                    raise ImouP2PError("session_closed")
                try:
                    self._server = await asyncio.start_server(
                        self._async_handle_client, "127.0.0.1", 0
                    )
                except OSError as err:
                    self.status = "error:tcp_listen"
                    raise ImouP2PError("tcp_listen") from err
                if generation != self._generation:
                    raise ImouP2PError("session_closed")
                sockets = self._server.sockets or ()
                if not sockets:
                    self.status = "error:tcp_listen"
                    raise ImouP2PError("tcp_listen")
                self.local_port = int(sockets[0].getsockname()[1])
                self._reader_task = asyncio.create_task(
                    self._async_read_device(),
                    name=f"imou_connect P2P reader {self.config.serial}",
                )
                self._heartbeat_task = asyncio.create_task(
                    self._async_heartbeat(),
                    name="imou_connect P2P heartbeat",
                )
                self.status = "ready"
            except BaseException:
                await self._async_close_resources()
                raise
            finally:
                self._start_task = None

    async def _async_send_body(self, body: bytes) -> None:
        endpoint = self._endpoint
        target = self._target
        session = self._session
        if endpoint is None or target is None or session is None:
            raise ImouP2PError("session_closed")
        async with self._send_lock:
            await endpoint.async_sendto(session.build(body), target)

    async def _async_read_device(self) -> None:
        endpoint = self._endpoint
        session = self._session
        if endpoint is None or session is None:
            return
        try:
            while not self._closing:
                packet, source = await endpoint.async_recvfrom()
                if source != self._target or not packet.startswith(b"PTCP"):
                    continue
                async with self._send_lock:
                    body = session.receive(packet)
                    if body:
                        target = self._target
                        if target is None:
                            raise ImouP2PError("session_closed")
                        await endpoint.async_sendto(session.build(b""), target)
                if not body:
                    continue
                packet_type = body[0]
                if packet_type == 0x10:
                    await self._async_route_payload(body)
                elif packet_type == 0x12:
                    self._async_route_status(body)
        except asyncio.CancelledError:
            raise
        except ImouP2PError as err:
            if not self._closing:
                self.status = f"error:{err.stage}"
                self._fail_clients(err)
        except (OSError, RuntimeError, ValueError, struct.error):
            if not self._closing:
                self.status = "error:session_reader"
                self._fail_clients(ImouP2PError("session_reader"))

    async def _async_route_payload(self, body: bytes) -> None:
        if len(body) < 12:
            raise ImouP2PError("ptcp_payload")
        header, realm, padding = struct.unpack("!LLL", body[:12])
        payload_length = header & 0xFFFF
        payload = body[12:]
        if padding != 0 or payload_length != len(payload):
            raise ImouP2PError("ptcp_payload")
        queue = self._client_queues.get(realm)
        if queue is None:
            return
        try:
            queue.put_nowait(payload)
        except asyncio.QueueFull:
            writer = self._client_writers.get(realm)
            if writer is not None:
                writer.close()

    def _async_route_status(self, body: bytes) -> None:
        if len(body) < 12:
            return
        realm = struct.unpack("!L", body[4:8])[0]
        status = body[12:].rstrip(b"\x00").decode("ascii", "ignore")
        waiter = self._connect_waiters.get(realm)
        if status == "CONN" and waiter is not None and not waiter.done():
            waiter.set_result(None)
        elif status == "DISC":
            if waiter is not None and not waiter.done():
                waiter.set_exception(ImouP2PError("remote_disconnect"))
            queue = self._client_queues.get(realm)
            if queue is not None:
                with suppress(asyncio.QueueFull):
                    queue.put_nowait(None)

    async def _async_heartbeat(self) -> None:
        try:
            while not self._closing:
                await asyncio.sleep(_HEARTBEAT_SECONDS)
                if not self._closing:
                    await self._async_send_body(b"\x13" + b"\x00" * 11)
        except asyncio.CancelledError:
            raise
        except ImouP2PError as err:
            if not self._closing:
                self.status = f"error:{err.stage}"
                self._fail_clients(err)

    async def _async_handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if self._closing:
            writer.close()
            writer.transport.abort()
            return
        task = asyncio.current_task()
        if task is not None:
            self._client_tasks.add(task)
        realm = secrets.randbits(32)
        while realm in self._client_queues:
            realm = secrets.randbits(32)
        queue: asyncio.Queue[bytes | None] = asyncio.Queue(_MAX_CLIENT_BUFFER)
        waiter = asyncio.get_running_loop().create_future()
        self._client_queues[realm] = queue
        self._client_writers[realm] = writer
        self._connect_waiters[realm] = waiter
        io_tasks: list[asyncio.Task[None]] = []
        try:
            bind_body = (
                b"\x11\x00\x00\x00"
                + struct.pack("!L", realm)
                + b"\x00\x00\x00\x00"
                + struct.pack("!L", self._remote_rtsp_port)
                + b"\x7f\x00\x00\x01"
            )
            await self._async_send_body(bind_body)
            await asyncio.wait_for(asyncio.shield(waiter), _CONNECT_TIMEOUT)
            reader_task = asyncio.create_task(self._async_client_reader(reader, realm))
            writer_task = asyncio.create_task(self._async_client_writer(writer, queue))
            io_tasks.extend((reader_task, writer_task))
            done, pending = await asyncio.wait(
                io_tasks, return_when=asyncio.FIRST_COMPLETED
            )
            for pending_task in pending:
                pending_task.cancel()
            await asyncio.gather(*done, *pending, return_exceptions=True)
        except (TimeoutError, ImouP2PError) as err:
            stage = err.stage if isinstance(err, ImouP2PError) else "rtsp_connect_timeout"
            self.status = f"error:{stage}"
            _LOGGER.warning("Imou P2P TCP connection failed stage=%s", stage)
        finally:
            if not waiter.done():
                waiter.cancel()
            try:
                for io_task in io_tasks:
                    if not io_task.done():
                        io_task.cancel()
                if io_tasks:
                    await asyncio.gather(*io_tasks, return_exceptions=True)
                if self._session is not None and not self._closing:
                    with suppress(ImouP2PError):
                        await self._async_send_body(
                            b"\x12\x00\x00\x00"
                            + struct.pack("!L", realm)
                            + b"\x00\x00\x00\x00DISC"
                        )
            finally:
                writer.close()
                try:
                    async with asyncio.timeout(self._CLOSE_TIMEOUT):
                        await writer.wait_closed()
                except (TimeoutError, OSError):
                    writer.transport.abort()
                except asyncio.CancelledError:
                    writer.transport.abort()
                    raise
                finally:
                    self._client_queues.pop(realm, None)
                    self._client_writers.pop(realm, None)
                    self._connect_waiters.pop(realm, None)
                    if task is not None:
                        self._client_tasks.discard(task)

    async def _async_client_reader(
        self, reader: asyncio.StreamReader, realm: int
    ) -> None:
        while data := await reader.read(4096):
            offset = 0
            while offset < len(data):
                chunk = data[offset : offset + 65535]
                offset += len(chunk)
                body = (
                    struct.pack("!LLL", 0x10000000 | len(chunk), realm, 0)
                    + chunk
                )
                await self._async_send_body(body)

    @staticmethod
    async def _async_client_writer(
        writer: asyncio.StreamWriter, queue: asyncio.Queue[bytes | None]
    ) -> None:
        while True:
            data = await queue.get()
            if data is None:
                return
            writer.write(data)
            await writer.drain()

    def _fail_clients(self, error: ImouP2PError | None) -> None:
        for waiter in tuple(self._connect_waiters.values()):
            if not waiter.done():
                if error is None:
                    waiter.cancel()
                else:
                    waiter.set_exception(error)
        for writer in tuple(self._client_writers.values()):
            writer.close()

    def stream_url(self, device: ImouDevice, channel: ImouChannel) -> str:
        """Return the local RTSP URL after a successful start."""
        if not self.ready or self.local_port is None:
            raise ImouP2PError("not_ready")
        return build_rtsp_url(
            self.config,
            self.local_port,
            rtsp_channel_number(device, channel),
        )

    async def async_close(self) -> None:
        """Stop the listener, clients, heartbeat, and P2P socket."""
        if self._close_task is None or self._close_task.done():
            self._generation += 1
            self._closing = True
            if self._start_task is not None:
                self._start_task.cancel()
            self._close_task = asyncio.create_task(
                self._async_close_locked(), name="imou_connect P2P close"
            )
        close_task = self._close_task
        cancelled = False
        while not close_task.done():
            try:
                await asyncio.shield(close_task)
            except asyncio.CancelledError:
                cancelled = True
        close_task.result()
        if cancelled:
            raise asyncio.CancelledError

    async def _async_close_locked(self) -> None:
        async with self._start_lock:
            await self._async_close_resources()

    async def _async_close_resources(self) -> None:
        self._closing = True
        server = self._server
        self._server = None
        self.local_port = None
        if server is not None:
            server.close()
        current = asyncio.current_task()
        tasks = [
            task
            for task in (self._reader_task, self._heartbeat_task)
            if task is not None and task is not current
        ]
        self._reader_task = None
        self._heartbeat_task = None
        tasks.extend(task for task in self._client_tasks if task is not current)
        self._fail_clients(None)
        writers = tuple(self._client_writers.values())
        for task in tasks:
            task.cancel()
        results: list[Any] = []
        try:
            async with asyncio.timeout(self._CLOSE_TIMEOUT * 2):
                if tasks:
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                if server is not None:
                    await server.wait_closed()
        except TimeoutError as err:
            for writer in writers:
                writer.transport.abort()
            raise ImouP2PError("close_timeout") from err
        finally:
            self._client_tasks.clear()
            self._client_queues.clear()
            self._client_writers.clear()
            self._connect_waiters.clear()
            if self._endpoint is not None:
                self._endpoint.close()
            self._endpoint = None
            self._target = None
            self._session = None
            if not self.status.startswith("error:"):
                self.status = "closed"
        for result in results:
            if isinstance(result, BaseException) and not isinstance(
                result, asyncio.CancelledError
            ):
                raise result


RelayFactory = Callable[[ImouP2PDeviceConfig], ImouP2PRelay]


class ImouP2PRelayManager:
    """Own lazy per-device relays for one Home Assistant config entry."""

    def __init__(self, relay_factory: RelayFactory = ImouP2PRelay) -> None:
        self._relay_factory = relay_factory
        self._relays: dict[str, ImouP2PRelay] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def async_stream_url(
        self, device: ImouDevice, channel: ImouChannel
    ) -> str:
        """Start or reuse a relay and return its loopback RTSP URL."""
        key = device.device_id.casefold()
        config = p2p_config_from_device(device)
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            relay = self._relays.get(key)
            if relay is not None and (
                relay.config != config or relay.status.startswith("error:")
            ):
                await relay.async_close()
                relay = None
            if relay is None:
                relay = self._relay_factory(config)
                self._relays[key] = relay
            try:
                await relay.async_start()
            except ImouP2PError:
                if self._relays.get(key) is relay and relay.status == "closed":
                    self._relays.pop(key, None)
                raise
            return relay.stream_url(device, channel)

    def diagnostic(self, device_id: str) -> str:
        """Return a credential-free relay status for one device."""
        relay = self._relays.get(device_id.casefold())
        return relay.status if relay is not None else "idle"

    async def async_close(self) -> None:
        """Close every relay owned by this config entry."""
        relays = tuple(self._relays.values())
        self._relays.clear()
        self._locks.clear()
        if relays:
            await asyncio.gather(
                *(relay.async_close() for relay in relays),
                return_exceptions=True,
            )
