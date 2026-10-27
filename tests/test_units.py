from __future__ import annotations

import base64
import json
import struct

import pytest
from helpers import make_device, make_settings

from app.cameras import CameraConfig, ConfigError, apply_update
from app.captcha_page import decode_image, render_page
from app.cloud import CloudManager, camera_name, split_key, unique_path, used_paths
from app.discovery import build_probe, parse_reply
from app.imou.api import ImouCaptchaChallenge
from app.mediamtx import describe_tracks, go_duration_seconds, path_conf_matches, render_config
from app.rtsp_probe import parse_sdp_codecs
from app.settings import Settings
from app.store import Store
from app.streams import camera_credentials, cloud_lan_ip, dahua_rtsp_url, public_url
from app.util import mask_account, redact_query, redact_url, slugify

PNG = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * 24).decode()


# ------------------------------------------------------------------ util


def test_slugify_handles_vietnamese() -> None:
    assert slugify("Cổng trước") == "cong_truoc"
    assert slugify("Đường vào") == "duong_vao"
    assert slugify("Phòng khách #2") == "phong_khach_2"
    assert slugify("  !!! ") == "camera"


def test_redaction_and_masking() -> None:
    assert redact_url("lỗi rtsp://admin:p%40ss@10.0.0.2:554/x") == "lỗi rtsp://***@10.0.0.2:554/x"
    assert (
        redact_query("https://u:p@cdn.example:8443/live.m3u8?token=abc")
        == "https://***@cdn.example:8443/live.m3u8?***"
    )
    assert redact_query("rtsp://10.0.0.2/cam") == "rtsp://10.0.0.2/cam"
    assert mask_account("nguyenvana@gmail.com") == "ng***@gmail.com"
    assert mask_account("0912345678") == "091***78"
    assert mask_account("abc") == "***"


# --------------------------------------------------------------- settings


def test_settings_defaults() -> None:
    settings = Settings.from_env({})
    assert settings.web_port == 8090
    assert settings.rtsp_port == 8554
    assert settings.rtsp_transports == ("udp", "tcp")
    assert settings.rtsp_username == ""
    assert settings.lan_scan_interval == 900


@pytest.mark.parametrize(
    "env",
    [
        {"RTSP_USERNAME": "viewer"},
        {"RTSP_USERNAME": "any", "RTSP_PASSWORD": "x"},
        {"RTSP_TRANSPORTS": "http"},
        {"WEB_PORT": "70000"},
        {"WEB_PORT": "abc"},
        {"ENABLE_HLS": "maybe"},
        {"MEDIAMTX_LOG_LEVEL": "trace"},
        {"REFRESH_INTERVAL": "5"},
    ],
)
def test_settings_rejects_bad_values(env: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        Settings.from_env(env)


# ---------------------------------------------------------------- cameras


def test_camera_config_from_dict_is_lenient() -> None:
    config = CameraConfig.from_dict(
        {"enabled": "yes", "port": 99999, "mode": "weird", "path": "Bad Path", "channel": 2}
    )
    assert config.enabled is False
    assert config.port == 554
    assert config.mode == "lan"
    assert config.path == ""
    assert config.channel == 2


def test_stream_paths_and_public_dict() -> None:
    config = CameraConfig(enabled=True, path="cong", sub=True, password="secret")
    assert config.stream_paths() == [("main", "cong"), ("sub", "cong_sub")]
    public = config.public_dict()
    assert "password" not in public and public["password_set"] is True
    config.mode = "custom"
    assert config.stream_paths() == [("main", "cong")]
    config.enabled = False
    assert config.stream_paths() == []


def test_apply_update_validates_and_keeps_password() -> None:
    current = CameraConfig(enabled=True, path="cong", password="old")
    updated = apply_update(
        current,
        {"path": "Cong_2", "port": "8554", "password": "", "host": " 192.168.1.20 ", "sub": True},
    )
    assert (updated.path, updated.port, updated.password, updated.host) == (
        "cong_2",
        8554,
        "old",
        "192.168.1.20",
    )
    assert updated.sub is True
    assert current.path == "cong"
    assert apply_update(updated, {"password": "new"}).password == "new"
    assert apply_update(updated, {"password_clear": True}).password == ""
    custom = apply_update(
        updated, {"mode": "custom", "custom_url": "rtsp://u:p@10.0.0.9:554/live"}
    )
    assert custom.custom_url == "rtsp://u:p@10.0.0.9:554/live"


@pytest.mark.parametrize(
    ("payload", "field"),
    [
        ({"path": "có dấu"}, "path"),
        ({"path": ""}, "path"),
        ({"port": "0"}, "port"),
        ({"port": True}, "port"),
        ({"channel": "300"}, "channel"),
        ({"mode": "ftp"}, "mode"),
        ({"host": "a/b"}, "host"),
        ({"host": "0.0.0.0"}, "host"),
        ({"enabled": "maybe"}, "enabled"),
        ({"mode": "custom", "custom_url": ""}, "custom_url"),
        ({"custom_url": "file:///etc/passwd"}, "custom_url"),
        ({"main": False, "sub": False}, "main"),
        ({"rtsp_transport": "quic"}, "rtsp_transport"),
        ({"username": "a\nb"}, "username"),
        ({"password": "x\x00y"}, "password"),
    ],
)
def test_apply_update_rejects(payload: dict[str, object], field: str) -> None:
    with pytest.raises(ConfigError) as info:
        apply_update(CameraConfig(enabled=True, path="cong"), payload)
    assert info.value.field == field


# ------------------------------------------------------------------ cloud


def test_camera_names_and_keys() -> None:
    single = make_device()
    assert camera_name(single, single.channels[0]) == "Cổng trước"
    nvr = make_device(
        deviceId="NVR1",
        name="Đầu ghi",
        channelList=[
            {"channelId": "0", "channelName": "Sân"},
            {"channelId": "1", "channelName": "Đầu ghi"},
            {"channelId": "2"},
        ],
    )
    assert [camera_name(nvr, channel) for channel in nvr.channels] == [
        "Sân",
        "Đầu ghi 1",
        "Channel 2",
    ]
    assert split_key("NVR1:1") == ("NVR1", "1")
    assert split_key("A:B:2") == ("A:B", "2")


def test_unique_and_used_paths() -> None:
    cameras = {
        "a:0": CameraConfig(path="cong"),
        "b:0": CameraConfig(path="san"),
        "c:0": CameraConfig(),
    }
    used = used_paths(cameras)
    assert used == {"cong", "cong_sub", "san", "san_sub"}
    assert used_paths(cameras, exclude="a:0") == {"san", "san_sub"}
    assert unique_path("cong", used) == "cong_2"
    assert unique_path("moi", used) == "moi"
    assert unique_path("san", used | {"san_2"}) == "san_3"
    assert unique_path("x", {"x_sub"}) == "x_2"


def test_sync_cameras_creates_unique_paths(tmp_path) -> None:
    store = Store(tmp_path)
    store.load()
    record = store.add_account("user@example.com", "pw", store.terminal_id)
    store.save_devices(
        record.id,
        [
            {"deviceId": "AAA", "productId": "P", "name": "Cổng trước"},
            {"deviceId": "BBB", "productId": "P", "name": "Cổng trước"},
            {
                "deviceId": "NVR",
                "productId": "P",
                "name": "Đầu ghi",
                "channelList": [
                    {"channelId": "0", "channelName": "Sân"},
                    {"channelId": "1", "channelName": "Bếp"},
                ],
            },
        ]
    )
    cloud = CloudManager(make_settings(tmp_path), store, None)
    assert cloud.sync_cameras() == 4
    assert {key: config.path for key, config in store.cameras.items()} == {
        "AAA:0": "cong_truoc",
        "BBB:0": "cong_truoc_2",
        "NVR:0": "san",
        "NVR:1": "bep",
    }
    assert all(config.enabled and config.mode == "cloud" for config in store.cameras.values())
    assert cloud.sync_cameras() == 0
    device, channel = cloud.find("NVR:1")
    assert device is not None and channel is not None and channel.name == "Bếp"
    assert cloud.find("NVR:9")[1] is None
    reloaded = Store(tmp_path)
    reloaded.load()
    assert reloaded.cameras["BBB:0"].path == "cong_truoc_2"
    assert reloaded.terminal_id == store.terminal_id


# ------------------------------------------------------------------ store


def test_store_keeps_or_repairs_terminal_id(tmp_path) -> None:
    store = Store(tmp_path)
    store.load()
    assert len(store.terminal_id) == 32
    again = Store(tmp_path)
    again.load()
    assert again.terminal_id == store.terminal_id
    (tmp_path / "config.json").write_text('{"terminal_id": "short"}', encoding="utf-8")
    repaired = Store(tmp_path)
    repaired.load()
    assert repaired.terminal_id != "short"
    saved = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
    assert saved["terminal_id"] == repaired.terminal_id


def test_store_moves_corrupt_config_aside(tmp_path) -> None:
    (tmp_path / "config.json").write_text("{not json", encoding="utf-8")
    store = Store(tmp_path)
    store.load()
    assert list(tmp_path.glob("config.json.corrupt-*"))
    assert store.cameras == {} and store.accounts == []


def test_store_account_round_trip(tmp_path) -> None:
    store = Store(tmp_path)
    store.load()
    first = store.add_account("user@example.com", "pw", store.unused_terminal_id())
    assert first.terminal_id == store.terminal_id
    second = store.add_account("0912345678", "pw2", store.unused_terminal_id())
    assert second.terminal_id != store.terminal_id and len(second.terminal_id) == 32
    assert first.id != second.id
    store.save_devices(first.id, [{"deviceId": "AAA"}])
    store.save_devices(second.id, [{"deviceId": "BBB"}])
    store.cameras["X:0"] = CameraConfig(enabled=True, path="x", password="cam")
    store.save()
    loaded = Store(tmp_path)
    loaded.load()
    assert [record.to_dict() for record in loaded.accounts] == [first.to_dict(), second.to_dict()]
    assert loaded.load_devices(second.id) == [{"deviceId": "BBB"}]
    assert loaded.cameras["X:0"].password == "cam"
    loaded.update_account(first.id, "user@example.com", "new")
    assert loaded.accounts[0].terminal_id == first.terminal_id
    with pytest.raises(KeyError):
        loaded.update_account("missing1", "x", "y")
    assert loaded.remove_account(first.id) is True
    assert loaded.remove_account(first.id) is False
    assert not loaded.devices_path(first.id).exists()
    fresh = Store(tmp_path)
    fresh.load()
    assert [record.id for record in fresh.accounts] == [second.id]
    assert fresh.load_devices(second.id) == [{"deviceId": "BBB"}]
    assert fresh.cameras["X:0"].path == "x"
    assert fresh.unused_terminal_id() == fresh.terminal_id
    with pytest.raises(ValueError):
        fresh.devices_path("../x")


# ---------------------------------------------------------------- streams


def test_dahua_rtsp_url_quotes_credentials() -> None:
    assert (
        dahua_rtsp_url("192.168.1.20", 554, "admin", "Ab:c@1/2#x", 1, 0)
        == "rtsp://admin:Ab%3Ac%401%2F2%23x@192.168.1.20:554/cam/realmonitor?channel=1&subtype=0"
    )
    assert (
        dahua_rtsp_url("fe80::1", 554, "", "", 0, 1)
        == "rtsp://[fe80::1]:554/cam/realmonitor?channel=1&subtype=1"
    )
    assert public_url("fe80::1", 8554, "cong") == "rtsp://[fe80::1]:8554/cong"
    assert public_url("192.168.1.2", 8554, "cong") == "rtsp://192.168.1.2:8554/cong"


def test_camera_credentials_prefer_ui_values() -> None:
    device = make_device(devicePassword="CLOUDPW")
    assert camera_credentials(device, CameraConfig()) == ("admin", "CLOUDPW")
    assert camera_credentials(device, CameraConfig(username="u", password="p")) == ("u", "p")
    assert camera_credentials(None, CameraConfig()) == ("admin", "")


def test_cloud_lan_ip_only_returns_private_ipv4() -> None:
    assert cloud_lan_ip(make_device(ip="8.8.8.8", lanIp="192.168.1.30")) == "192.168.1.30"
    assert cloud_lan_ip(make_device(ip="8.8.8.8")) == ""
    assert cloud_lan_ip(None) == ""


def test_parse_sdp_codecs() -> None:
    sdp = (
        "v=0\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H265/90000\r\n"
        "m=audio 0 RTP/AVP 8\r\n"
        "m=application 0 RTP/AVP 107\r\na=rtpmap:107 vnd.onvif.metadata/90000\r\n"
    )
    assert parse_sdp_codecs(sdp) == ["video H265", "audio PCMA", "application VND.ONVIF.METADATA"]
    assert parse_sdp_codecs("") == []


# --------------------------------------------------------------- mediamtx


@pytest.mark.parametrize(
    ("value", "seconds"),
    [
        ("10s", 10.0),
        ("1m0s", 60.0),
        ("1h2m3.5s", 3723.5),
        ("250ms", 0.25),
        ("0", 0.0),
        (5, 5.0),
        ("abc", None),
        ("10x", None),
        (None, None),
    ],
)
def test_go_duration_seconds(value: object, seconds: float | None) -> None:
    result = go_duration_seconds(value)
    if seconds is None:
        assert result is None
    else:
        assert result == pytest.approx(seconds)


def test_path_conf_matches_compares_durations() -> None:
    current = {"sourceOnDemandStartTimeout": "10s", "sourceOnDemand": True, "other": 1}
    assert path_conf_matches({"sourceOnDemandStartTimeout": "10s", "sourceOnDemand": True}, current)
    assert path_conf_matches({"x": "1m"}, {"x": "1m0s"})
    assert not path_conf_matches({"sourceOnDemand": False}, current)


def test_render_config_users(tmp_path) -> None:
    config = render_config(make_settings(tmp_path), "bridgeX", "secret")
    internal, public = config["authInternalUsers"]
    assert internal["user"] == "bridgeX" and internal["ips"] == ["127.0.0.1/32", "::1/128"]
    assert {"action": "api"} in internal["permissions"]
    assert public["user"] == "any" and public["permissions"] == [{"action": "read"}]
    assert config["paths"] == {} and config["apiAddress"] == "127.0.0.1:9997"
    locked = make_settings(
        tmp_path, RTSP_USERNAME="viewer", RTSP_PASSWORD="pw", RTSP_TRANSPORTS="tcp"
    )
    config = render_config(locked, "bridgeX", "secret")
    assert [user["user"] for user in config["authInternalUsers"]] == ["bridgeX", "viewer"]
    assert config["rtspTransports"] == ["tcp"]


def test_describe_tracks() -> None:
    info = {
        "tracks2": [
            {"codec": "H265", "codecProps": {"width": 2560, "height": 1440}},
            {"codec": "MPEG-4 Audio", "codecProps": {}},
        ]
    }
    assert describe_tracks(info) == "H265 2560x1440, MPEG-4 Audio"
    assert describe_tracks({"tracks": ["H264"]}) == "H264"
    assert describe_tracks(None) == ""


# -------------------------------------------------------------- discovery


def _dhip(body: bytes) -> bytes:
    return struct.pack("<IIIIIIII", 32, 0x50494844, 0, 0, len(body), 0, len(body), 0) + body


def test_discovery_probe_and_reply() -> None:
    packet = build_probe()
    header = struct.unpack("<IIIIIIII", packet[:32])
    assert header[0] == 32 and packet[4:8] == b"DHIP"
    assert header[4] == header[6] == len(packet) - 32
    assert json.loads(packet[32:])["method"] == "DHDiscover.search"

    body = json.dumps(
        {
            "method": "client.notifyDevInfo",
            "mac": "aa:bb:cc:dd:ee:ff",
            "params": {
                "deviceInfo": {
                    "SerialNo": "7B0ABC123",
                    "DeviceType": "IPC-C22EP",
                    "IPv4Address": {"IPAddress": "192.168.1.44"},
                    "Vendor": "Imou",
                    "VideoInputChannels": 1,
                    "Version": "2.840",
                }
            },
        }
    ).encode()
    device = parse_reply(_dhip(body) + b"\x00", "192.168.1.200")
    assert device is not None
    assert (device.serial, device.ip, device.model, device.channels, device.mac) == (
        "7B0ABC123",
        "192.168.1.44",
        "IPC-C22EP",
        1,
        "aa:bb:cc:dd:ee:ff",
    )
    assert parse_reply(packet, "192.168.1.5") is None
    assert parse_reply(b"garbage", "1.2.3.4") is None
    no_ip = json.dumps(
        {"params": {"deviceInfo": {"SerialNo": "X1", "IPv4Address": {"IPAddress": "0.0.0.0"}}}}
    ).encode()
    fallback = parse_reply(_dhip(no_ip), "192.168.1.9")
    assert fallback is not None and fallback.ip == "192.168.1.9"


# ---------------------------------------------------------------- captcha


def test_decode_image() -> None:
    image, content_type = decode_image(PNG)
    assert image.startswith(b"\x89PNG") and content_type == "image/png"
    assert decode_image(f"data:image/png;base64,{PNG}")[1] == "image/png"
    jpeg = base64.b64encode(b"\xff\xd8\xff\xe0" + b"\x00" * 8).decode()
    assert decode_image(jpeg)[1] == "image/jpeg"
    for bad in ("data:text/html;base64,PGI+", "not base64!!", "", "data:image/png,abc"):
        with pytest.raises(ValueError):
            decode_image(bad)


def test_render_page_modes() -> None:
    geetest = ImouCaptchaChallenge(
        mode="geetest",
        captcha_id="cid",
        captcha_server="https://gcaptcha4.example",
        web_challenge="ch</script>",
    )
    page = render_page(geetest, 3, "fp", 1700000000000)
    assert "static/gl4.js" in page
    assert '"captchaId":"cid"' in page
    assert "ch<\\/script>" in page and "ch</script>" not in page
    image = ImouCaptchaChallenge(mode="image", image=PNG)
    page = render_page(image, 4, "fp", 1)
    assert "captcha/image?g=4" in page and "gl4.js" not in page
