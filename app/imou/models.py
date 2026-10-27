"""Data models and thing-model parsing for Imou Life."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any, Final

from .const import PTZ_STREAM_HOST_FIELDS

PRIMITIVE_TYPES = frozenset({"bool", "enum", "int", "float", "double", "text"})
SENSITIVE_PARTS = (
    "credential",
    "password",
    "secret",
    "privatekey",
    "accesskey",
    "token",
)
_CJK_PATTERN = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]")
_IDENTIFIER_LABELS = {
    "alarm": "Cảnh báo",
    "alarmenable": "Cảnh báo",
    "alarmswitch": "Cảnh báo",
    "autotracking": "Tự động theo dõi",
    "battery": "Pin",
    "batterylevel": "Mức pin",
    "crydetect": "Phát hiện tiếng khóc",
    "cryenable": "Phát hiện tiếng khóc",
    "daynightmode": "Chế độ ngày đêm",
    "firmwareversion": "Phiên bản firmware",
    "humandetect": "Phát hiện người",
    "humandetection": "Phát hiện người",
    "humanenable": "Phát hiện người",
    "humansensitivity": "Độ nhạy phát hiện người",
    "humidity": "Độ ẩm",
    "indicatorlight": "Đèn trạng thái",
    "intrusiondetect": "Phát hiện xâm nhập",
    "ledenable": "Đèn trạng thái",
    "micenable": "Micrô",
    "motiondetect": "Phát hiện chuyển động",
    "motiondetection": "Phát hiện chuyển động",
    "motionenable": "Phát hiện chuyển động",
    "motionsensitivity": "Độ nhạy chuyển động",
    "nightvision": "Chế độ nhìn đêm",
    "persondetect": "Phát hiện người",
    "pirdetect": "Cảm biến PIR",
    "pirenable": "Cảm biến PIR",
    "privacyenable": "Chế độ riêng tư",
    "privacymode": "Chế độ riêng tư",
    "reboot": "Khởi động lại",
    "recordenable": "Ghi hình",
    "recording": "Ghi hình",
    "restart": "Khởi động lại",
    "sdcardstatus": "Trạng thái thẻ nhớ",
    "sensitivity": "Độ nhạy",
    "signalstrength": "Cường độ tín hiệu",
    "siren": "Còi báo động",
    "sleepmode": "Chế độ ngủ",
    "sounddetect": "Phát hiện âm thanh",
    "soundenable": "Phát hiện âm thanh",
    "speakervolume": "Âm lượng loa",
    "spotlight": "Đèn chiếu sáng",
    "status": "Trạng thái",
    "statuslight": "Đèn trạng thái",
    "storage": "Bộ nhớ",
    "tamperdetect": "Phát hiện phá hoại",
    "temperature": "Nhiệt độ",
    "volume": "Âm lượng",
    "whitelight": "Đèn trắng",
    "wifisignal": "Tín hiệu Wi-Fi",
}
_ENUM_VALUE_LABELS = {
    "alarm": "Báo động",
    "auto": "Tự động",
    "away": "Vắng nhà",
    "blackandwhite": "Đen trắng",
    "blackwhite": "Đen trắng",
    "bw": "Đen trắng",
    "color": "Màu",
    "day": "Ban ngày",
    "disable": "Tắt",
    "disabled": "Tắt",
    "enable": "Bật",
    "enabled": "Bật",
    "false": "Tắt",
    "high": "Cao",
    "home": "Ở nhà",
    "low": "Thấp",
    "medium": "Trung bình",
    "middle": "Trung bình",
    "night": "Ban đêm",
    "normal": "Bình thường",
    "off": "Tắt",
    "on": "Bật",
    "silent": "Im lặng",
    "smart": "Thông minh",
    "true": "Bật",
}
_UNIT_LABELS = {
    "℃": "°C",
    "℉": "°F",
    "厘米": "cm",
    "分钟": "min",
    "华氏度": "°F",
    "天": "d",
    "小时": "h",
    "摄氏度": "°C",
    "毫秒": "ms",
    "毫米": "mm",
    "百分比": "%",
    "秒": "s",
    "米": "m",
}


def _contains_cjk(value: str) -> bool:
    return bool(_CJK_PATTERN.search(value))


def _identifier_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def _humanize_identifier(identifier: str) -> str:
    value = re.sub(r"[_\-.]+", " ", identifier.strip())
    value = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", value)
    value = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", value)
    value = re.sub(r"(?<=[A-Za-z])(?=\d)|(?<=\d)(?=[A-Za-z])", " ", value)
    value = " ".join(value.split())
    if not value or _contains_cjk(value):
        return ""
    return value[:1].upper() + value[1:]


def _model_name(identifier: str, value: Any, fallback: str) -> str:
    supplied = str(value or "").strip()
    if supplied and not _contains_cjk(supplied):
        return supplied
    mapped = _IDENTIFIER_LABELS.get(_identifier_key(identifier))
    return mapped or _humanize_identifier(identifier) or fallback


def _model_description(value: Any) -> str | None:
    supplied = str(value or "").strip()
    if not supplied or _contains_cjk(supplied):
        return None
    return supplied


def _enum_label(identifier: str, value: str, supplied: Any, position: int) -> str:
    description = str(supplied or "").strip()
    if description and not _contains_cjk(description):
        return description
    value_key = _identifier_key(value)
    mapped = _ENUM_VALUE_LABELS.get(value_key)
    if mapped:
        return mapped
    identifier_key = _identifier_key(identifier)
    if value in {"0", "1"} and identifier_key.endswith(("enable", "switch")):
        return "Bật" if value == "1" else "Tắt"
    humanized = _humanize_identifier(value)
    return humanized or f"Tùy chọn {position}"


def _model_unit(value: Any) -> str | None:
    supplied = str(value or "").strip()
    if not supplied:
        return None
    if supplied in _UNIT_LABELS:
        return _UNIT_LABELS[supplied]
    return None if _contains_cjk(supplied) else supplied


def as_bool(value: Any) -> bool | None:
    """Convert common API boolean representations."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "on", "yes", "enable", "enabled", "online"}:
            return True
        if normalized in {"0", "false", "off", "no", "disable", "disabled", "offline"}:
            return False
    return None


def is_online_status(value: Any) -> bool | None:
    """Interpret device and channel online states."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return int(value) == 1
    normalized = str(value).strip().lower()
    if normalized in {"1", "on", "online", "ready", "normal"}:
        return True
    if normalized in {"0", "2", "off", "offline", "sleep", "sleeping"}:
        return False
    return None


ABILITY_KEYS: Final = ("ability", "abilities", "capability", "capabilities")


def _raw_declares_ability(raw: Mapping[str, Any], ability: str) -> bool:
    """Return whether raw device metadata lists a named capability."""
    needle = ability.lower()
    for key, value in raw.items():
        if str(key).lower() not in ABILITY_KEYS:
            continue
        if needle in _flatten_ability_text(value).lower():
            return True
    return False


def _flatten_ability_text(value: Any) -> str:
    if isinstance(value, Mapping):
        return " ".join(
            f"{key} {_flatten_ability_text(item)}" for key, item in value.items()
        )
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten_ability_text(item) for item in value)
    return str(value)


def stream_entry_host(raw: Mapping[str, Any]) -> str | None:
    """Return the device stream-entry base URL used for cloud PTZ.

    Imou Life sends `things.ptz.PtzMove` to the device's `streamEntryAddr`
    host; the account entry host rejects it with code `12100` (no authority).
    MQTT brokers (the `streamEntryAddrV4` value) are not HTTP entries.
    """
    for key in PTZ_STREAM_HOST_FIELDS:
        value = raw.get(key)
        if not isinstance(value, str):
            continue
        host = value.strip().rstrip("/")
        if not host or "mqtt" in host.lower() or ":8883" in host:
            continue
        if not host.startswith(("http://", "https://")):
            host = f"https://{host}"
        return host
    return None


@dataclass(slots=True, frozen=True)
class ImouChannel:
    """A camera or recorder channel."""

    channel_id: str
    name: str
    status: str | None = None
    picture_url: str | None = None
    product_id: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)


@dataclass(slots=True, frozen=True)
class ThingProperty:
    """One primitive property from an Imou thing model."""

    identifier: str
    ref: str
    name: str
    data_type: str
    access_mode: str
    unit: str | None = None
    minimum: float | None = None
    maximum: float | None = None
    step: float | None = None
    enum_options: tuple[str, ...] = ()
    enum_labels: Mapping[str, str] = field(default_factory=dict, repr=False, hash=False)
    description: str | None = None

    @property
    def readable(self) -> bool:
        """Return whether the property can be read."""
        return "r" in self.access_mode

    @property
    def writable(self) -> bool:
        """Return whether the property can be changed."""
        return "w" in self.access_mode

    @property
    def sensitive(self) -> bool:
        """Return whether exposing this property could leak credentials."""
        normalized = self.identifier.replace("_", "").lower()
        return any(part in normalized for part in SENSITIVE_PARTS)


@dataclass(slots=True, frozen=True)
class ThingService:
    """One service from an Imou thing model."""

    identifier: str
    ref: str
    name: str
    input_data: tuple[ThingProperty, ...] = ()
    input_data_valid: bool = True

    @property
    def zero_input(self) -> bool:
        return self.input_data_valid and not self.input_data


@dataclass(slots=True, frozen=True)
class ThingModel:
    """Parsed model for a product."""

    properties: tuple[ThingProperty, ...] = ()
    services: tuple[ThingService, ...] = ()
    md5: str | None = None

    def exposed_properties(self, limit: int) -> tuple[ThingProperty, ...]:
        """Return stable primitive properties suitable for HA entities."""
        result: list[ThingProperty] = []
        for prop in self.properties:
            if (
                not (prop.readable or prop.writable)
                or prop.sensitive
                or prop.data_type not in PRIMITIVE_TYPES
                or prop.writable and prop.data_type == "enum" and not prop.enum_options
            ):
                continue
            result.append(prop)
            if len(result) >= limit:
                break
        return tuple(result)

    def _identifiers(self) -> tuple[str, ...]:
        """Return every property and service identifier of the model."""
        return tuple(prop.identifier for prop in self.properties) + tuple(
            service.identifier for service in self.services
        )

    @property
    def supports_ptz(self) -> bool:
        """Return whether the thing model advertises pan/tilt control."""
        return any("ptz" in identifier.lower() for identifier in self._identifiers())

    @property
    def supports_zoom(self) -> bool:
        """Return whether the thing model advertises zoom control."""
        return any(
            "zoom" in identifier.lower() for identifier in self._identifiers()
        )


@dataclass(slots=True, frozen=True)
class ImouDevice:
    """Normalized cloud device with channels and current properties."""

    device_id: str
    product_id: str
    name: str
    status: str | None = None
    model: str | None = None
    catalog: str | None = None
    group_control_flag: str = "0"
    channels: tuple[ImouChannel, ...] = ()
    properties: Mapping[str, Any] = field(
        default_factory=dict, repr=False, compare=False
    )
    thing_model: ThingModel = field(
        default_factory=ThingModel, repr=False, compare=False
    )
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @property
    def online(self) -> bool | None:
        """Return normalized availability."""
        return is_online_status(self.status)

    @property
    def supports_ptz(self) -> bool:
        """Return whether this device exposes PTZ controls."""
        return self.thing_model.supports_ptz or _raw_declares_ability(self.raw, "ptz")

    @property
    def supports_zoom(self) -> bool:
        """Return whether this device exposes zoom controls."""
        return self.thing_model.supports_zoom or self.supports_ptz

    def with_properties(self, values: Mapping[str, Any]) -> ImouDevice:
        """Return a copy with fresh property values."""
        return replace(self, properties=dict(values))

    def with_thing_model(self, model: ThingModel) -> ImouDevice:
        """Return a copy with a parsed thing model."""
        return replace(self, thing_model=model)


def _float_or_none(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _parse_property(
    raw: Mapping[str, Any], default_access: str = "r"
) -> ThingProperty | None:
    identifier = str(raw.get("identifier") or "").strip()
    ref = str(raw.get("ref") or "").strip()
    data_type = raw.get("dataType") or {}
    if not isinstance(data_type, Mapping):
        return None
    kind = str(data_type.get("type") or "").strip().lower()
    if not identifier or not ref or not kind:
        return None
    specs = data_type.get("specs") or {}
    if not isinstance(specs, Mapping):
        specs = {}
    value_range = specs.get("range") or ()
    minimum = maximum = None
    if isinstance(value_range, (list, tuple)) and len(value_range) >= 2:
        minimum = _float_or_none(value_range[0])
        maximum = _float_or_none(value_range[1])
    enum_labels: dict[str, str] = {}
    enum_options: list[str] = []
    enum_list = specs.get("list") or ()
    if isinstance(enum_list, list):
        for position, item in enumerate(enum_list, start=1):
            if not isinstance(item, Mapping) or "value" not in item:
                continue
            value = str(item["value"])
            enum_options.append(value)
            enum_labels[value] = _enum_label(
                identifier, value, item.get("desc"), position
            )
    return ThingProperty(
        identifier=identifier,
        ref=ref,
        name=_model_name(identifier, raw.get("name"), f"Thuộc tính {ref}"),
        data_type=kind,
        access_mode=str(raw.get("accessMode") or default_access).lower(),
        unit=_model_unit(specs.get("unit")),
        minimum=minimum,
        maximum=maximum,
        step=_float_or_none(specs.get("step")),
        enum_options=tuple(enum_options),
        enum_labels=enum_labels,
        description=_model_description(raw.get("description") or raw.get("desc")),
    )


def parse_thing_model(
    model_json: str | Mapping[str, Any], md5: str | None = None
) -> ThingModel:
    """Parse the JSON returned by iot.manager.QueryModelInfo."""
    raw: Any = model_json
    for _ in range(2):
        if not isinstance(raw, str):
            break
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return ThingModel(md5=md5)
    if not isinstance(raw, Mapping):
        return ThingModel(md5=md5)

    properties: list[ThingProperty] = []
    seen_refs: set[str] = set()
    for key in ("properties", "platform_properties"):
        values = raw.get(key) or ()
        if not isinstance(values, list):
            continue
        for item in values:
            if not isinstance(item, Mapping):
                continue
            parsed = _parse_property(item)
            if parsed is None or parsed.ref in seen_refs:
                continue
            seen_refs.add(parsed.ref)
            properties.append(parsed)

    services: list[ThingService] = []
    seen_services: set[str] = set()
    for key in ("services", "platform_services"):
        values = raw.get(key) or ()
        if not isinstance(values, list):
            continue
        for item in values:
            if not isinstance(item, Mapping):
                continue
            identifier = str(item.get("identifier") or "").strip()
            ref = str(item.get("ref") or "").strip()
            if not identifier or not ref or ref in seen_services:
                continue
            seen_services.add(ref)
            raw_inputs = item.get("inputData", [])
            inputs_valid = isinstance(raw_inputs, list)
            inputs = (
                tuple(
                    prop
                    for child in raw_inputs
                    if isinstance(child, Mapping)
                    and (prop := _parse_property(child, default_access="w")) is not None
                )
                if inputs_valid else ()
            )
            inputs_valid = inputs_valid and len(inputs) == len(raw_inputs)
            services.append(
                ThingService(
                    identifier=identifier,
                    ref=ref,
                    name=_model_name(
                        identifier, item.get("name"), f"Dịch vụ {ref}"
                    ),
                    input_data=inputs,
                    input_data_valid=inputs_valid,
                )
            )
    return ThingModel(tuple(properties), tuple(services), md5=md5)


def normalize_property_values(
    definitions: Iterable[ThingProperty], values: Mapping[str, Any]
) -> dict[str, Any]:
    """Map API values keyed by either refs or identifiers to identifiers."""
    normalized: dict[str, Any] = {}
    for definition in definitions:
        if definition.ref in values:
            normalized[definition.identifier] = values[definition.ref]
        elif definition.identifier in values:
            normalized[definition.identifier] = values[definition.identifier]
        else:
            try:
                numeric_ref = int(definition.ref)
            except ValueError:
                continue
            if numeric_ref in values:
                normalized[definition.identifier] = values[numeric_ref]
    return normalized


def _first(raw: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if raw.get(key) not in (None, ""):
            return raw[key]
    return default


def _api_identifier(raw: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = raw.get(key)
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            text = str(value).strip()
            if text:
                return text
    return ""


def device_from_api(raw: Mapping[str, Any]) -> ImouDevice | None:
    """Normalize devices from BasicInfoQueryV2, BasicList, or the legacy list."""
    device_id = _api_identifier(raw, "deviceId", "deviceid")
    product_id = _api_identifier(raw, "productId", "productid")
    if not device_id:
        return None
    name = str(_first(raw, "name", "deviceName", "devicename", default=device_id))
    channel_data: dict[str, dict[str, Any]] = {}
    for key in ("channelList", "channels"):
        raw_channels = raw.get(key)
        if not isinstance(raw_channels, list):
            continue
        for index, channel in enumerate(raw_channels):
            if not isinstance(channel, Mapping):
                continue
            channel_id = _api_identifier(channel, "channelId", "channelid") or str(index)
            merged = channel_data.setdefault(channel_id, {})
            for field_name, value in channel.items():
                if (
                    merged.get(field_name) in (None, "", [], {})
                    or field_name in ("productId", "productid")
                    and not _api_identifier(merged, field_name)
                ):
                    merged[field_name] = value
    channels = [
        ImouChannel(
            channel_id=channel_id,
            name=str(
                _first(
                    channel,
                    "channelName",
                    "channelname",
                    "name",
                    default=f"Channel {channel_id}",
                )
            ),
            status=str(channel.get("status"))
            if channel.get("status") is not None
            else None,
            picture_url=_first(channel, "picUrl", "picurl", "pictureUrl", "thumbnailUrl"),
            product_id=_api_identifier(channel, "productId", "productid") or product_id,
            raw=dict(channel),
        )
        for channel_id, channel in channel_data.items()
    ]
    if not channels:
        channel_count = _first(
            raw, "channelNum", "channelnum", "productChannelNum", default=1
        )
        try:
            channel_count = max(1, min(int(channel_count), 64))
        except (TypeError, ValueError, OverflowError):
            channel_count = 1
        channels = [
            ImouChannel(
                str(index),
                name if channel_count == 1 else f"{name} {index + 1}",
                product_id=product_id,
            )
            for index in range(channel_count)
        ]
    if not product_id and len(channels) == 1:
        for key in ("channelNum", "channelnum", "productChannelNum"):
            try:
                if raw.get(key) not in (None, "") and int(_api_identifier(raw, key)) != 1:
                    break
            except (TypeError, ValueError, OverflowError):
                break
        else:
            product_id = channels[0].product_id or ""
    return ImouDevice(
        device_id=device_id,
        product_id=product_id,
        name=name,
        status=str(raw.get("status")) if raw.get("status") is not None else None,
        model=str(
            _first(
                raw,
                "deviceModelName",
                "deviceModel",
                "devicemodel",
                "productModel",
                default="",
            )
        )
        or None,
        catalog=str(_first(raw, "catalog", "category", default="")) or None,
        group_control_flag=str(raw.get("groupControlFlg") or "0"),
        channels=tuple(channels),
        raw=dict(raw),
    )
