"""CAPTCHA page for the Imou sign-in (GeeTest v4 or a four character image).

Ported from ``captcha_ui.py``/``captcha.py`` of
trankhanhduy2929-beep/imou_homeassistant (MIT). The GeeTest parameters mimic
the Imou Life Android app, which is what the Imou cloud expects.
"""

from __future__ import annotations

import json
from base64 import b64decode
from binascii import Error as BinasciiError
from typing import Any

from .imou.api import ImouCaptchaChallenge

GEETEST_PACKAGE_NAME = "com.mm.android.smartlifeiot"
GEETEST_APP_VERSION = "10.1.6"
GEETEST_BUILD = "500542"
GEETEST_CLIENT_VERSION = "1.8.11"
GEETEST_CLIENT_TYPE = "android"
MAX_IMAGE_BYTES = 2 * 1024 * 1024

NO_STORE_HEADERS = {
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


def geetest_config(
    challenge: ImouCaptchaChallenge, fingerprint: str, first_seen: int
) -> dict[str, Any]:
    """Build the parameter object assembled by GeeLab SDK 1.8.11."""
    return {
        "product": "bind",
        "displayArea": "center",
        "displayMode": 1,
        "protocol": "https://",
        "captchaId": challenge.captcha_id,
        "challenge": challenge.web_challenge,
        "debug": False,
        "language": "vi-vn",
        "apiServers": [challenge.captcha_server],
        "timeout": 10000,
        "clientVersion": GEETEST_CLIENT_VERSION,
        "clientType": GEETEST_CLIENT_TYPE,
        "mask": {"outside": False},
        "mi": {
            "geeid": {
                "bd": "$unknown",
                "d": "$unknown",
                "e": "$unknown",
                "fp": fingerprint,
                "ts": str(first_seen),
                "ver": "1.0.0",
                "client_type": GEETEST_CLIENT_TYPE,
            },
            "packageName": GEETEST_PACKAGE_NAME,
            "displayName": "Imou%20Life",
            "appVer": GEETEST_APP_VERSION,
            "build": GEETEST_BUILD,
            "clientVersion": GEETEST_CLIENT_VERSION,
        },
    }


def _sniff_image_type(image: bytes) -> str | None:
    if image.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if image.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if image.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if image[:4] == b"RIFF" and image[8:12] == b"WEBP":
        return "image/webp"
    return None


def decode_image(value: str) -> tuple[bytes, str]:
    """Decode the base64 picture CAPTCHA (optionally a ``data:`` URL)."""
    content_type = "image/jpeg"
    encoded = value.strip()
    if encoded.startswith("data:"):
        header, separator, encoded = encoded.partition(",")
        if not separator or ";base64" not in header:
            raise ValueError("Invalid CAPTCHA image")
        candidate = header[5:].split(";", 1)[0].strip().lower()
        if candidate not in {"image/jpeg", "image/png", "image/gif", "image/webp"}:
            raise ValueError("Unsupported CAPTCHA image type")
        content_type = candidate
    try:
        image = b64decode(encoded, validate=True)
    except (BinasciiError, ValueError) as err:
        raise ValueError("Invalid CAPTCHA image") from err
    if not image or len(image) > MAX_IMAGE_BYTES:
        raise ValueError("Invalid CAPTCHA image size")
    return image, _sniff_image_type(image) or content_type


_HEAD = """<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>Xác minh Imou</title>
<style>:root{color-scheme:light dark;font-family:system-ui,sans-serif}body{padding:24px;text-align:center}main{max-width:620px;margin:auto}#captcha-shell{min-height:330px;display:grid;place-items:center;margin:18px auto;padding:12px;border:1px solid #7775;border-radius:12px;background:#fff;color:#111}#captcha{width:100%;min-height:300px}button{border:0;border-radius:8px;padding:12px 20px;font:inherit;font-weight:600;background:#687078;color:#fff;cursor:pointer}button:disabled{cursor:wait;opacity:.55}#status{white-space:pre-wrap;min-height:52px;margin:18px 0}.hint{font-size:.9rem;opacity:.75}form{display:flex;gap:10px;justify-content:center;align-items:center;flex-wrap:wrap}input{font:inherit;font-size:1.25rem;letter-spacing:.25rem;text-align:center;width:10rem;padding:10px;border:1px solid #777;border-radius:8px}#captcha-image{min-width:150px;min-height:50px;image-rendering:auto;background:#fff;border:10px solid #fff;border-radius:8px}a{color:inherit}</style></head>
<body><main><h2>Xác minh đăng nhập Imou</h2>
<p>Imou yêu cầu CAPTCHA. Hoàn tất bên dưới để ứng dụng tiếp tục đăng nhập.</p>"""

_FOOTER = """<p class="hint">Trang này chỉ gửi kết quả CAPTCHA về ứng dụng. Mật khẩu và token Imou không được đưa vào trình duyệt.</p>
<p class="hint"><a href="./">← Quay lại trang chính</a></p></main></body></html>"""

_COMMON_SCRIPT = """<script>
const generation = __GENERATION__;
const statusBox = document.getElementById("status");
let submitting = false;
async function postJson(url, body) {
  const response = await fetch(url, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body || {}), credentials: "same-origin"});
  let data = {};
  try { data = await response.json(); } catch (error) {}
  return {response, data};
}
async function sendResult(result) {
  if (submitting) return;
  submitting = true;
  statusBox.textContent = "Đang gửi kết quả tới Imou…";
  try {
    const {response, data} = await postJson("api/captcha/submit", Object.assign({generation: generation}, result || {}));
    if (!response.ok || !data.ok) {
      if (typeof data.generation === "number" && data.generation !== generation) { location.reload(); return; }
      throw new Error(data.error || "Imou không chấp nhận CAPTCHA.");
    }
  } catch (error) {
    statusBox.textContent = error.message;
    submitting = false;
    const button = document.getElementById("submit");
    if (button) button.disabled = false;
  }
}
async function refreshCaptcha() {
  const button = document.getElementById("refresh");
  button.disabled = true;
  statusBox.textContent = "Đang tạo CAPTCHA mới…";
  try {
    const {response, data} = await postJson("api/captcha/refresh", {});
    if (!response.ok || !data.ok) throw new Error(data.error || "Không tạo được CAPTCHA mới.");
  } catch (error) {
    statusBox.textContent = error.message;
    button.disabled = false;
  }
}
document.getElementById("refresh").addEventListener("click", refreshCaptcha);
async function readStatus() {
  try {
    const response = await fetch("api/login", {cache: "no-store", credentials: "same-origin"});
    if (!response.ok) return;
    const login = await response.json();
    if (login.step !== "captcha") { location.href = "./"; return; }
    const captcha = login.captcha || {};
    if (captcha.generation !== generation) { location.reload(); return; }
    if (captcha.message && (submitting || captcha.status !== "required")) statusBox.textContent = captcha.message;
    if (captcha.status === "rejected" && !login.busy) {
      submitting = false;
      const button = document.getElementById("submit");
      if (button) button.disabled = false;
      const refresh = document.getElementById("refresh");
      if (refresh) refresh.disabled = false;
    }
  } catch (error) {}
}
setInterval(readStatus, 1500);
</script>"""

_IMAGE_BODY = """<p><img id="captcha-image" src="captcha/image?g=__GENERATION__" alt="Ảnh CAPTCHA Imou"></p>
<form id="captcha-form"><input id="captcha-code" name="code" inputmode="text" autocomplete="off" autocapitalize="characters" minlength="4" maxlength="4" pattern="[A-Za-z0-9]{4}" required aria-label="Mã CAPTCHA bốn ký tự"><button id="submit" type="submit">Xác minh</button></form>
<p><button id="refresh" type="button">Đổi ảnh CAPTCHA</button></p><div id="status" role="status" aria-live="polite">Nhập bốn ký tự trong ảnh.</div>"""

_IMAGE_SCRIPT = """<script>
document.getElementById("captcha-form").addEventListener("submit", function(event) {
  event.preventDefault();
  document.getElementById("submit").disabled = true;
  sendResult({code: document.getElementById("captcha-code").value.trim()});
});
</script>"""

_GEETEST_BODY = """<div id="captcha-shell"><div id="captcha"></div></div>
<p><button id="refresh" type="button">Tạo CAPTCHA mới</button></p><div id="status" role="status" aria-live="polite">Đang tải CAPTCHA hình ảnh…</div>"""

_GEETEST_SCRIPT = """<script src="static/gl4.js"></script><script>
const config = __CONFIG__;
config.onError = function() { statusBox.textContent = "GeeTest không tải được CAPTCHA. Hãy bấm “Tạo CAPTCHA mới”."; };
if (typeof window.initGeetest4 !== "function") {
  statusBox.textContent = "Không tải được thư viện GeeTest.";
} else {
  window.initGeetest4(config, function(captchaObj) {
    window.imouCaptcha = captchaObj;
    captchaObj.appendTo(document.getElementById("captcha")).onReady(function() {
      statusBox.textContent = "Hãy hoàn tất CAPTCHA hình ảnh.";
      if (typeof captchaObj.showCaptcha === "function") captchaObj.showCaptcha();
      else if (typeof captchaObj.showBox === "function") captchaObj.showBox();
    }).onSuccess(function() {
      sendResult(captchaObj.getValidate());
    }).onClose(function() {
      statusBox.textContent = "CAPTCHA đã đóng. Bấm “Tạo CAPTCHA mới” để thử lại.";
    }).onError(config.onError).onFail(function() {
      statusBox.textContent = "GeeTest báo xác minh chưa đạt. Hãy thử lại.";
    });
  });
}
</script>"""


def render_page(
    challenge: ImouCaptchaChallenge, generation: int, fingerprint: str, first_seen: int
) -> str:
    """Render GeeTest4 or the four-character fallback image form."""
    common = _COMMON_SCRIPT.replace("__GENERATION__", str(int(generation)))
    if challenge.is_image:
        body = _IMAGE_BODY.replace("__GENERATION__", str(int(generation)))
        return _HEAD + body + common + _IMAGE_SCRIPT + _FOOTER
    config_json = json.dumps(
        geetest_config(challenge, fingerprint, first_seen),
        ensure_ascii=False,
        separators=(",", ":"),
    ).replace("</", "<\\/")
    return _HEAD + _GEETEST_BODY + common + _GEETEST_SCRIPT.replace("__CONFIG__", config_json) + _FOOTER
