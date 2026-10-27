# Imou → RTSP cho Synology (Docker)

Ứng dụng Docker đăng nhập **một hoặc nhiều tài khoản Imou Life**, lấy danh sách camera và tạo **một link RTSP cố định cho mỗi camera/kênh**. Các link dùng được cho VLC, Synology Surveillance Station, Home Assistant, Frigate, Blue Iris…

- API Imou (đăng nhập, CAPTCHA, mã OTP, danh sách thiết bị, P2P) lấy từ [imou_homeassistant](https://github.com/trankhanhduy2929-beep/imou_homeassistant) (MIT) và được tách khỏi Home Assistant.
- Máy chủ RTSP là [MediaMTX](https://github.com/bluenviron/mediamtx). Ứng dụng tự chạy và cấu hình MediaMTX.
- Có giao diện web tiếng Việt: đăng nhập Imou (gắn được nhiều tài khoản), cấu hình từng camera, sao chép link, kiểm tra luồng.
- Có image dựng sẵn cho amd64 và arm64: `ghcr.io/vonamhai/imou-rtsp:latest`, do GitHub Actions build từ mã nguồn trong repo này. NAS tự tải image về, không cần chép mã nguồn lên NAS.

```
Camera Imou ──(cloud / LAN RTSP / P2P)──► MediaMTX trong container ──► rtsp://IP-NAS:8554/<tên>
                                                                    └─► rtsp://IP-NAS:8554/<tên>_sub
```

## Nguồn lấy hình

| Chế độ | Mô tả |
|---|---|
| **Cloud** (mặc định) | Lấy hình qua máy chủ trung chuyển (relay) của Imou, giống khi xem trực tiếp trong app Imou Life. Không cần Safety Code hay IP camera; dùng được cho camera cùng mạng, camera ở mạng khác và **camera 4G/SIM**. Link RTSP của Imou chỉ dùng được một lần, nên mỗi lần kết nối ứng dụng tự xin một link mới. Nếu máy chủ Imou ngắt kết nối ngay, ứng dụng tự thử lại qua TLS rồi xin loại link khác. Một số tài khoản/thiết bị chỉ nhận luồng mã hóa riêng, không dùng được. |
| **LAN** | MediaMTX lấy RTSP trực tiếp từ camera: `rtsp://admin:<mật khẩu>@IP-camera:554/cam/realmonitor?channel=1&subtype=0` (`subtype=1` là luồng phụ). Nhanh và không phụ thuộc máy chủ Imou, nhưng camera phải cùng mạng với NAS. **Mật khẩu là Safety Code in trên nhãn camera**, hoặc mật khẩu thiết bị nếu bạn đã đổi. IP camera được tự dò trong LAN, hoặc bạn nhập tay. |
| **P2P** (thử nghiệm) | Kết nối tới camera qua máy chủ P2P của Imou, khi NAS và camera khác mạng. Vẫn cần Safety Code. |
| **URL tùy chỉnh** | Phát lại bất kỳ nguồn `rtsp://`, `rtmp://`, `http(s)://…m3u8`, `srt://`… |

Mặc định chỉ kết nối tới camera **khi có người xem** (tùy chọn "Chỉ kết nối tới camera khi có người xem").

### Camera 4G / chế độ Cloud

Camera 4G (dùng SIM) không cùng mạng với NAS nên chỉ dùng được chế độ **Cloud** (chế độ mặc định).

- Nên dùng **luồng phụ** (link `<tên>_sub`, thường là H.264 + AAC, khoảng 100 kbit/s cả hình lẫn tiếng). Luồng chính (thường là H.265) cần nhiều băng thông tải lên. Khi sóng 4G yếu, luồng chính có thể kết nối được nhưng không có hình, hoặc bị giật. Khi đó hãy bỏ chọn **Luồng chính (HD)** trong **Cấu hình**.
- Nếu camera đang nghỉ, lần mở đầu tiên mất khoảng **20–30 giây** để máy chủ Imou đánh thức camera. Các lần mở sau gần như ngay lập tức.
- Hình ảnh đi qua máy chủ Imou và dùng dữ liệu di động của SIM trong camera, nên hãy giữ tùy chọn "Chỉ kết nối tới camera khi có người xem". Nếu tắt tùy chọn này để ghi hình liên tục, riêng luồng phụ đã tốn khoảng 30 GB/tháng trở lên.

## Cài đặt trên Synology (Container Manager)

Yêu cầu: DSM 7.2 trở lên, gói **Container Manager**, NAS dùng CPU x86-64 (Intel/AMD) hoặc ARM64 và ra được Internet.

1. Trong **File Station**, mở thư mục chia sẻ `docker` và tạo thư mục `imou-rtsp`.
2. Vào **Container Manager → Project → Create**:
   - Project name: `imou-rtsp`.
   - Path: thư mục vừa tạo (`/docker/imou-rtsp`).
   - Source: **Create docker-compose.yml**, rồi dán toàn bộ nội dung file [`docker-compose.yml`](docker-compose.yml) của repo này.
3. Trong nội dung vừa dán, sửa:
   - `WEB_PASSWORD`: mật khẩu giao diện web (tên đăng nhập `admin`).
   - `RTSP_USERNAME` / `RTSP_PASSWORD`: tài khoản để xem link RTSP. Đặt cả hai, hoặc để trống cả hai (`""`).
   - Đổi `WEB_PORT` / `RTSP_PORT` nếu cổng 8090 / 8554 đã có ứng dụng khác dùng.

   Nên dùng mật khẩu chỉ gồm chữ và số: Docker Compose hiểu ký tự `$` là biến, còn `@`, `:`, `/` làm hỏng link RTSP có kèm mật khẩu.
4. Bấm **Next** qua các bước (không cần cấu hình Web Station), rồi **Done**. NAS tải image `ghcr.io/vonamhai/imou-rtsp:latest` rồi chạy container. Thư mục `data/` (tài khoản, cấu hình camera) được tạo trong thư mục project.
5. Mở `http://IP-NAS:8090`, đăng nhập tài khoản Imou Life. Nếu được yêu cầu, làm CAPTCHA (nút *Mở trang CAPTCHA*) rồi nhập mã 6 số gửi qua SMS/email. Có camera ở tài khoản khác? Bấm **Thêm tài khoản** (xem mục [Nhiều tài khoản Imou](#nhiều-tài-khoản-imou)).
6. Danh sách camera hiện ra. Mỗi kênh tự được bật ở chế độ **Cloud**, với đường dẫn đặt theo tên camera (ví dụ "Cổng trước" → `cong_truoc`), nên thường chỉ cần bấm **Kiểm tra luồng**. Bấm **Cấu hình** nếu muốn bật **Luồng phụ**, hoặc chuyển camera cùng mạng với NAS sang chế độ LAN:
   - chọn **Nguồn lấy hình: LAN**;
   - nhập **Mật khẩu camera (Safety Code)**;
   - nhập **IP camera** nếu chưa tự dò được.
   Bấm **Lưu**, rồi **Kiểm tra luồng**.
7. Bấm **Sao chép** để lấy link, ví dụ `rtsp://192.168.1.10:8554/cong_truoc`. Nếu đã đặt `RTSP_USERNAME`/`RTSP_PASSWORD`, trình xem sẽ hỏi tài khoản; hoặc bạn tự thêm vào link: `rtsp://xem:matkhau@192.168.1.10:8554/cong_truoc`.

Nếu dùng SSH thay cho giao diện: chép file `docker-compose.yml` (đã sửa mật khẩu) vào `/volume1/docker/imou-rtsp`, rồi chạy `cd /volume1/docker/imou-rtsp && sudo docker compose up -d`.

### Cập nhật lên bản mới

Thư mục `data/` (tài khoản, cấu hình camera, link RTSP) được giữ nguyên khi cập nhật. Camera đã cấu hình giữ nguyên chế độ đang dùng; camera mới, hoặc camera bấm **Đặt lại mặc định**, dùng chế độ Cloud.

- Trên giao diện: **Project → imou-rtsp → Action → Stop**, rồi **Action → Clean** (xóa container). Vào **Image**, xóa image `ghcr.io/vonamhai/imou-rtsp`. Quay lại **Project → imou-rtsp → Action → Build**: NAS tải image mới nhất và chạy lại.
- Qua SSH: `cd /volume1/docker/imou-rtsp && sudo docker compose pull && sudo docker compose up -d`.

### Tự build từ mã nguồn (không bắt buộc)

Nếu không muốn dùng image dựng sẵn: tải mã nguồn (**Code → Download ZIP** trên GitHub), giải nén rồi tải cả thư mục lên NAS, ví dụ `/docker/imou-rtsp` (phải chứa trực tiếp `Dockerfile` và `app/`). Trong `docker-compose.yml`, bỏ dấu `#` ở dòng `# build: .`, sửa mật khẩu, rồi tạo project với Source là file `docker-compose.yml` có sẵn trong thư mục. Lần đầu NAS build image, mất vài phút.

### Thêm vào Surveillance Station

*IP Camera → Add*, chọn Brand **[User Define]**, rồi dán link RTSP vào ô đường dẫn (Path). Thêm `user:pass@` vào link nếu đã đặt tài khoản RTSP. Vì Surveillance Station chạy trên chính NAS, có thể dùng `127.0.0.1` thay cho IP của NAS.

## Nhiều tài khoản Imou

Gắn được tối đa 20 tài khoản Imou Life, ví dụ camera ở nhà và camera ở cửa hàng nằm ở hai tài khoản khác nhau.

- Bấm **Thêm tài khoản** trong mục **Tài khoản Imou** rồi đăng nhập như bước 5. Imou xác minh từng tài khoản riêng, nên mỗi tài khoản có thể phải làm CAPTCHA/OTP riêng.
- Camera của mọi tài khoản nằm chung một danh sách; khi có từ hai tài khoản, mỗi camera ghi rõ thuộc tài khoản nào. Đường dẫn RTSP không bao giờ trùng: hai camera cùng tên "Sân sau" sẽ là `san_sau` và `san_sau_2`.
- Mỗi dòng tài khoản có ba nút:
  - **Làm mới danh sách**: tải lại danh sách thiết bị của riêng tài khoản đó.
  - **Đăng nhập lại**: dùng mật khẩu đã lưu. Nếu đã đổi mật khẩu Imou, hãy nhập mật khẩu mới vào ô hiện ra.
  - **Gỡ tài khoản**: xóa tài khoản, mật khẩu đã lưu và danh sách thiết bị của tài khoản đó.
- Gỡ tài khoản **không xóa cấu hình camera**: link RTSP, Safety Code và IP vẫn được giữ, và camera hiện nhãn "Không còn trong tài khoản". Camera ở chế độ LAN (đã có IP và Safety Code) hoặc URL tùy chỉnh vẫn xem được; chế độ P2P và Cloud cần tài khoản chứa camera. Gắn lại tài khoản thì camera dùng lại đúng link cũ. Muốn xóa hẳn một camera, bấm **Đặt lại mặc định** trên thẻ camera đó.
- Camera được chia sẻ giữa các tài khoản đã gắn chỉ hiện một lần, với một link RTSP. Luồng Cloud được lấy qua tài khoản chủ sở hữu; nếu tài khoản đó cần đăng nhập lại thì ứng dụng dùng tài khoản được chia sẻ.
- Nhập một tài khoản đã gắn vào form **Thêm tài khoản** sẽ đăng nhập lại tài khoản đó, không tạo bản trùng.
- Nâng cấp từ bản chỉ có một tài khoản: lần chạy đầu tiên tự chuyển dữ liệu sang dạng mới (`devices.json` thành `devices-<mã tài khoản>.json`). Không cần đăng nhập lại, link RTSP giữ nguyên.

## Chạy thử trên Docker Desktop (Windows/macOS)

Docker Desktop không hỗ trợ đầy đủ `network_mode: host`. Vì vậy hãy dùng thêm file `docker-compose.desktop.yml`: file này chuyển sang mạng bridge và chỉ mở cổng cho chính máy đang chạy.

```bash
docker compose -f docker-compose.yml -f docker-compose.desktop.yml up -d
docker compose -f docker-compose.yml -f docker-compose.desktop.yml down      # dừng và xóa container
```

- Lệnh trên tải image dựng sẵn. Muốn chạy mã nguồn đang sửa, bỏ dấu `#` ở dòng `# build: .` trong `docker-compose.yml` rồi thêm `--build`.
- Mở `http://localhost:8090`. Link RTSP có dạng `rtsp://localhost:8554/<tên>`.
- Ở chế độ này không dò được camera trong LAN; hãy nhập IP camera bằng tay.
- Chế độ LAN chỉ chạy khi máy cùng mạng với camera. Nếu không, hãy dùng chế độ Cloud, hoặc P2P (cần Safety Code).

## Biến môi trường

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `WEB_PORT` | `8090` | Cổng giao diện web |
| `WEB_USERNAME` / `WEB_PASSWORD` | `admin` / *(trống)* | Basic Auth cho giao diện web. Để trống `WEB_PASSWORD` thì không cần đăng nhập. |
| `PUBLIC_HOST` | *(trống)* | IP/tên miền hiển thị trong link RTSP. Mặc định lấy theo địa chỉ bạn dùng để mở trang web. |
| `RTSP_PORT` | `8554` | Cổng RTSP cho người xem |
| `RTP_PORT` / `RTCP_PORT` | `8000` / `8001` | Cổng UDP khi người xem dùng RTSP qua UDP |
| `RTSP_TRANSPORTS` | `udp,tcp` | Giao thức cho người xem: `udp`, `multicast`, `tcp` |
| `RTSP_USERNAME` / `RTSP_PASSWORD` | *(trống)* | Tài khoản xem link RTSP. Phải đặt cả hai. |
| `ENABLE_HLS`, `HLS_PORT` | `false`, `8888` | Xem qua trình duyệt: `http://IP-NAS:8888/<tên>/` |
| `ENABLE_WEBRTC`, `WEBRTC_PORT`, `WEBRTC_UDP_PORT` | `false`, `8889`, `8189` | Xem WebRTC: `http://IP-NAS:8889/<tên>/` |
| `LAN_SCAN_INTERVAL` | `900` | Số giây giữa hai lần dò camera trong LAN (UDP 37810). `0` = tắt. |
| `REFRESH_INTERVAL` | `600` | Số giây giữa hai lần làm mới danh sách thiết bị Imou |
| `P2P_IDLE_TIMEOUT` | `60` | Đóng kết nối P2P sau số giây này khi không còn người xem |
| `CLOUD_URL_TTL` | `600` | Số giây dùng lại một link cloud HLS/RTMP trước khi xin link mới. Link RTSP của Imou luôn được xin mới cho mỗi lần kết nối. |
| `IMOU_LANGUAGE` | `en_US` | Mã ngôn ngữ gửi kèm các yêu cầu tới API Imou |
| `MEDIAMTX_API_PORT` | `9997` | API nội bộ của MediaMTX, chỉ nghe trên 127.0.0.1 |
| `LOG_LEVEL`, `MEDIAMTX_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `DATA_DIR` | `/data` | Thư mục lưu cấu hình (mount ra `./data`) |
| `TZ` | | Múi giờ, ví dụ `Asia/Ho_Chi_Minh` |

Container dùng `network_mode: host` vì dò camera trong LAN cần UDP broadcast, và RTSP/UDP và P2P chạy ổn định hơn ở chế độ này. Các cổng đang dùng:

- 8090/tcp: web
- 8554/tcp: RTSP
- 8000–8001/udp: RTSP qua UDP
- 8888 và 8889/tcp, 8189/udp: chỉ khi bật HLS hoặc WebRTC
- 9997/tcp: API MediaMTX, chỉ trên 127.0.0.1

## Bảo mật

- `data/config.json` lưu **các tài khoản, mật khẩu Imou và mật khẩu camera ở dạng rõ**; `data/devices-*.json` lưu danh sách thiết bị Imou trả về, có thể gồm cả mật khẩu thiết bị. Hãy giới hạn quyền truy cập thư mục `data/` và đừng chia sẻ nó.
- Hãy đặt `WEB_PASSWORD`, `RTSP_USERNAME` và `RTSP_PASSWORD`.
- Không mở cổng 8090/8554 ra Internet. Muốn xem từ xa, hãy dùng VPN (Tailscale, WireGuard, OpenVPN…).
- Nếu đặt giao diện sau reverse proxy, proxy phải giữ nguyên header `Host` hoặc gửi `X-Forwarded-Host`; nếu không, các thao tác lưu sẽ bị chặn (chống CSRF). Đặt thêm `PUBLIC_HOST` để link RTSP hiển thị đúng địa chỉ.

## Xử lý sự cố

| Hiện tượng | Cách xử lý |
|---|---|
| Tạo project báo `pull access denied`, `denied` hoặc `unauthorized` khi tải `ghcr.io/vonamhai/imou-rtsp` | NAS chưa ra được Internet (kiểm tra DNS/gateway của NAS), hoặc image chưa được đặt công khai trên GitHub (chủ repo vào **Package settings → Change visibility → Public**). |
| Không mở được `http://IP-NAS:8090`, hoặc trình xem không kết nối được link RTSP | Kiểm tra container đang chạy (*Container Manager → Container*). Nếu đã bật tường lửa DSM (*Control Panel → Security → Firewall*), thêm quy tắc cho phép cổng TCP 8090, 8554 và UDP 8000–8001 (hoặc các cổng bạn đã đổi). |
| Build báo `dockerfile parse error on line 1: unknown instruction:` (không có chữ nào sau dấu hai chấm) | Chỉ gặp khi tự build từ mã nguồn: file trên NAS bị chép hỏng, đúng tên và kích thước nhưng nội dung toàn byte 0. Hãy dùng image dựng sẵn như phần cài đặt, hoặc tải lại mã nguồn. |
| Kiểm tra luồng báo `401` / `Unauthorized` | Sai Safety Code hoặc tài khoản camera. Tài khoản thường là `admin`. |
| `i/o timeout`, `connection refused` | Sai IP camera, camera không cùng mạng với NAS, hoặc cổng RTSP 554 bị chặn. Thử mở link `rtsp://admin:<Safety Code>@IP-camera:554/cam/realmonitor?channel=1&subtype=0` bằng VLC. |
| Không tự dò được IP | Camera nằm khác subnet/VLAN, hoặc mạng chặn broadcast. Hãy nhập IP tay và đặt IP tĩnh cho camera trên router. |
| `address already in use` trong nhật ký | Cổng đã có ứng dụng khác dùng (ví dụ Frigate/go2rtc cũng dùng 8554). Đổi `RTSP_PORT`, `WEB_PORT`, `RTP_PORT`, `RTCP_PORT`. |
| Camera pin (Cell Go, Cell Pro…) | Camera ngủ để tiết kiệm pin nên không có luồng RTSP liên tục. Ứng dụng không hỗ trợ loại này. |
| Camera 4G: lần đầu mở link lâu hoặc báo lỗi | Camera đang nghỉ, máy chủ Imou cần khoảng 20–30 giây để đánh thức. Hãy chờ hoặc mở lại link. Nếu trình xem có thời gian chờ ngắn (ví dụ ffmpeg với `-timeout`), hãy tăng lên từ 60 giây. |
| Camera 4G: luồng phụ chạy, luồng chính không có hình (**Kiểm tra luồng** báo "không gửi hình") | Sóng 4G không đủ băng thông tải lên cho luồng chính. Dùng link `_sub` và bỏ chọn **Luồng chính (HD)**, hoặc giảm độ phân giải/bitrate luồng chính trong app Imou. |
| Chế độ Cloud: **Kiểm tra luồng** báo "Máy chủ cloud của Imou ngắt kết nối ngay" | Máy chủ Imou không phục vụ loại link vừa cấp (từng gặp với camera Wi‑Fi Bullet 2C). Ứng dụng tự thử lại qua TLS, rồi tạm ưu tiên loại link khác trong 10 phút, nên hãy kiểm tra lại. Nếu vẫn lỗi, dòng `Cloud relay for /<tên> …` trong nhật ký cho biết loại link và lý do. Camera cùng mạng với NAS có thể dùng chế độ LAN. |
| Trình xem không hiện hình, chỉ có tiếng | Nhiều trình duyệt không phát được H.265. Dùng luồng phụ (thường là H.264) hoặc đổi chuẩn nén trong app Imou. |
| Imou đòi đăng nhập lại | Bấm **Đăng nhập lại** ở dòng tài khoản đó, làm CAPTCHA/OTP nếu có. Mật khẩu đã lưu sẽ được dùng lại. Các tài khoản khác vẫn chạy bình thường. |

Nhật ký có trong mục **Nhật ký hoạt động** trên trang web, hoặc ở *Container Manager → Container → imou-rtsp → Details → Log*.

## Lưu ý

- API Imou ở đây là API không chính thức của ứng dụng Imou Life, nên có thể ngừng hoạt động khi Imou thay đổi.
- Ứng dụng đã có kiểm thử tự động: đăng nhập (giả lập), nhiều tài khoản (giả lập), web, P2P relay, luồng LAN thật đi qua MediaMTX với một camera RTSP giả lập, và chế độ Cloud với một máy chủ relay giả lập. Đã thử với **tài khoản Imou thật và một camera 4G ở chế độ Cloud**: luồng phụ (H.264 + AAC) chạy được; luồng chính (H.265) kết nối được nhưng không có hình vì sóng 4G yếu. Chế độ LAN và P2P chưa được thử với camera thật. Chế độ P2P là thử nghiệm.

## Phát triển

```bash
pip install -r requirements-dev.txt
pytest                                    # thêm MEDIAMTX_BIN=/đường/dẫn/mediamtx để chạy kiểm thử tích hợp
DATA_DIR=./data MEDIAMTX_BIN=/đường/dẫn/mediamtx python -m app
```

Mỗi lần đẩy lên nhánh `main` hoặc tag `v*`, GitHub Actions ([`.github/workflows/docker-image.yml`](.github/workflows/docker-image.yml)) chạy kiểm thử rồi build image amd64 + arm64 và đẩy lên `ghcr.io/vonamhai/imou-rtsp`. Tag `v1.2.3` tạo thêm image `ghcr.io/vonamhai/imou-rtsp:1.2.3`.

Build image cho kiến trúc khác (ví dụ trên PC để import vào NAS):

```bash
docker buildx build --platform linux/amd64 -t imou-rtsp:latest --load .
docker save imou-rtsp:latest -o imou-rtsp.tar   # Container Manager → Image → Import
```

## Giấy phép

MIT, xem [LICENSE](LICENSE). Mã và thành phần của bên thứ ba được liệt kê trong [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
