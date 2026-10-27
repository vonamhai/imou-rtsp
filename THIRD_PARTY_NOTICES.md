# Third-party notices

This project, and the Docker image built from it, include or are derived from the components below.

## imou_homeassistant

- Source: https://github.com/trankhanhduy2929-beep/imou_homeassistant
- Copyright (c) 2026 trankhanhduy2929-beep
- License: MIT (full text below)
- Used in this project:
  - `app/imou/` is copied from `custom_components/imou_connect/`, keeping the Home-Assistant-independent API, model and P2P modules. See `app/imou/LICENSE`.
  - The Imou sign-in flow (CAPTCHA and verification code) in `app/login.py` and `app/captcha_page.py` is adapted from the integration's config flow and CAPTCHA page.

## dh-p2p

- Source: https://github.com/khoanguyen-3fc/dh-p2p
- Copyright (c) 2023 khoanguyen-3fc
- License: MIT (full text below)
- Used in this project: the Dahua/Imou P2P transport in `app/imou/p2p.py` is informed by this proof of concept. See `app/imou/THIRD_PARTY_NOTICES.md`.

## MediaMTX

- Source: https://github.com/bluenviron/mediamtx
- Copyright (c) 2019 aler9
- License: MIT (full text below)
- Used in this project: the unmodified `mediamtx` binary from the official `bluenviron/mediamtx` image is copied into the Docker image as `/usr/local/bin/mediamtx`.

## GeeTest CAPTCHA v4 loader (`app/static/gl4.js`)

- "v4.2.0 Geelab Inc."
- Used in this project: copied unchanged from imou_homeassistant (`custom_components/imou_connect/web/gl4.js`). It is loaded only by the CAPTCHA page, to show the verification challenge that Imou requires during sign-in.
- This file belongs to its respective owner and is not covered by this project's MIT license.

## Python packages installed in the Docker image

| Package | License |
|---|---|
| [aiohttp](https://github.com/aio-libs/aiohttp) and its dependencies | Apache-2.0 / MIT |
| [cryptography](https://github.com/pyca/cryptography) | Apache-2.0 OR BSD-3-Clause |

The base image `python:3.12-slim-bookworm` (Python: PSF License; Debian packages: their respective licenses) is used unchanged.

## MIT License text

The following text applies to imou_homeassistant, dh-p2p and MediaMTX, each with its copyright notice above.

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
