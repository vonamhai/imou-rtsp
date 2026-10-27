"""Find Dahua/Imou cameras on the LAN with the DHIP ``DHDiscover.search`` probe.

The packet layout follows the MIT licensed OpenIPC/python-dhip and
rroller/dahua projects: a 32 byte little-endian DHIP header followed by a JSON
body, sent to the multicast group 239.255.255.251:37810 (and broadcast).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import socket
import struct
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from typing import Any

_LOGGER = logging.getLogger(__name__)

DISCOVER_GROUP = "239.255.255.251"
DISCOVER_PORT = 37810
_HEADER = struct.Struct("<IIIIIIII")
_MAGIC = 0x50494844  # b"DHIP"


@dataclass(frozen=True, slots=True)
class DiscoveredDevice:
    serial: str
    ip: str
    model: str = ""
    name: str = ""
    mac: str = ""
    vendor: str = ""
    version: str = ""
    channels: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "serial": self.serial,
            "ip": self.ip,
            "model": self.model,
            "name": self.name,
            "mac": self.mac,
            "vendor": self.vendor,
            "version": self.version,
            "channels": self.channels,
        }


def build_probe() -> bytes:
    body = json.dumps(
        {"method": "DHDiscover.search", "params": {"mac": "", "uni": 1}},
        separators=(",", ":"),
    ).encode()
    return _HEADER.pack(_HEADER.size, _MAGIC, 0, 0, len(body), 0, len(body), 0) + body


def _valid_ip(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    try:
        address = ipaddress.IPv4Address(value.strip())
    except ValueError:
        return ""
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        return ""
    return str(address)


def _text(info: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = info.get(key)
        if isinstance(value, (str, int)) and str(value).strip():
            return str(value).strip()
    return ""


def parse_reply(data: bytes, source_ip: str) -> DiscoveredDevice | None:
    """Parse one discovery reply; return ``None`` for probes and junk."""
    start = data.find(b"{")
    if start < 0:
        return None
    text = data[start:].rstrip(b"\x00 \r\n\t").decode("utf-8", "replace")
    try:
        message, _ = json.JSONDecoder().raw_decode(text)
    except ValueError:
        return None
    if not isinstance(message, Mapping):
        return None
    params = message.get("params")
    if not isinstance(params, Mapping):
        return None
    info = params.get("deviceInfo")
    if not isinstance(info, Mapping):
        return None
    serial = _text(info, "SerialNo", "serialNo", "SN")
    if not serial:
        return None
    ip = ""
    ipv4 = info.get("IPv4Address")
    if isinstance(ipv4, Mapping):
        ip = _valid_ip(ipv4.get("IPAddress")) or _valid_ip(ipv4.get("IPAddr"))
    ip = ip or _valid_ip(source_ip)
    if not ip:
        return None
    channels: int | None
    try:
        channels = int(info.get("VideoInputChannels"))
    except (TypeError, ValueError):
        channels = None
    return DiscoveredDevice(
        serial=serial,
        ip=ip,
        model=_text(info, "DeviceType", "DeviceClass"),
        name=_text(info, "MachineName"),
        mac=_text(message, "mac") or _text(info, "Mac", "mac"),
        vendor=_text(info, "Vendor", "Manufacturer"),
        version=_text(info, "Version"),
        channels=channels,
    )


class _Collector(asyncio.DatagramProtocol):
    def __init__(self, found: dict[str, DiscoveredDevice]) -> None:
        self.found = found

    def datagram_received(self, data: bytes, addr: tuple[Any, ...]) -> None:
        device = parse_reply(data, str(addr[0]))
        if device is not None:
            self.found.setdefault(device.serial.casefold(), device)

    def error_received(self, exc: Exception) -> None:
        _LOGGER.debug("Discovery socket error: %s", exc)


def _multicast_socket() -> socket.socket | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            with suppress(OSError):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(("", DISCOVER_PORT))
        membership = struct.pack(
            "4s4s", socket.inet_aton(DISCOVER_GROUP), socket.inet_aton("0.0.0.0")
        )
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        sock.setblocking(False)
        return sock
    except OSError as err:
        _LOGGER.debug("Multicast listener unavailable: %s", err)
        sock.close()
        return None


async def discover(timeout: float = 3.0) -> dict[str, DiscoveredDevice]:
    """Probe the LAN and return devices keyed by case-folded serial number."""
    loop = asyncio.get_running_loop()
    found: dict[str, DiscoveredDevice] = {}
    transports: list[asyncio.BaseTransport] = []
    try:
        sender, _ = await loop.create_datagram_endpoint(
            lambda: _Collector(found),
            local_addr=("0.0.0.0", 0),
            allow_broadcast=True,
        )
        transports.append(sender)
        sock = sender.get_extra_info("socket")
        if sock is not None:
            with suppress(OSError):
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        listener = _multicast_socket()
        if listener is not None:
            try:
                multicast, _ = await loop.create_datagram_endpoint(
                    lambda: _Collector(found), sock=listener
                )
                transports.append(multicast)
            except OSError:
                listener.close()
        probe_packet = build_probe()
        for _ in range(2):
            for target in ((DISCOVER_GROUP, DISCOVER_PORT), ("255.255.255.255", DISCOVER_PORT)):
                try:
                    sender.sendto(probe_packet, target)
                except OSError as err:
                    _LOGGER.debug("Discovery probe to %s failed: %s", target[0], err)
            await asyncio.sleep(timeout / 2)
    finally:
        for transport in transports:
            transport.close()
    return found
