"use strict";

(function () {
  const STATE_TEXT = {
    live: "Đang phát",
    standby: "Chờ người xem",
    connecting: "Đang kết nối",
    error: "Lỗi",
    pending: "Đang cấu hình",
    offline: "Máy chủ RTSP chưa chạy",
  };
  const STATE_CLASS = {live: "good", standby: "info", connecting: "warn", error: "bad", pending: "warn", offline: "bad"};
  const MODE_TEXT = {lan: "LAN", p2p: "P2P", cloud: "Cloud", custom: "URL tùy chỉnh"};
  const CLOUD_TEXT = {
    not_configured: "Chưa đăng nhập",
    connecting: "Đang kết nối",
    ok: "Đã kết nối",
    needs_login: "Cần đăng nhập lại",
    error: "Lỗi",
  };
  const CLOUD_CLASS = {ok: "good", connecting: "info", needs_login: "warn", error: "bad"};
  const MTX_TEXT = {stopped: "Đã dừng", starting: "Đang khởi động", running: "Đang chạy", crashed: "Lỗi", missing: "Thiếu MediaMTX"};
  const MTX_CLASS = {running: "good", starting: "info", stopped: "warn", crashed: "bad", missing: "bad"};

  const $ = (selector, root) => (root || document).querySelector(selector);
  const $$ = (selector, root) => Array.from((root || document).querySelectorAll(selector));

  let state = null;
  let lastStep = null;
  let lastFinished = null;
  let pollTimer = null;
  let bannerTimer = null;
  let connectionLost = false;
  let addingAccount = false;
  let formMode = "";
  const cards = new Map();
  const accountRows = new Map();

  function setText(element, text) {
    if (element.textContent !== text) element.textContent = text;
  }

  function setBadge(element, text, kind, base) {
    setText(element, text);
    element.className = base + (kind ? " " + kind : "");
  }

  function banner(message, kind) {
    const box = $("#banner");
    box.textContent = message;
    box.className = "banner" + (kind ? " " + kind : "");
    box.hidden = false;
    clearTimeout(bannerTimer);
    bannerTimer = setTimeout(() => { box.hidden = true; }, kind === "error" ? 12000 : 6000);
  }

  async function api(path, body) {
    const options = body === undefined
      ? {cache: "no-store", credentials: "same-origin"}
      : {
          method: "POST",
          cache: "no-store",
          credentials: "same-origin",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify(body),
        };
    let response;
    try {
      response = await fetch(path, options);
    } catch (error) {
      throw new Error("Không kết nối được tới ứng dụng.");
    }
    let data = {};
    try {
      data = await response.json();
    } catch (error) {
      data = {};
    }
    if (!response.ok || data.ok === false) {
      const error = new Error(data.error || "Lỗi HTTP " + response.status);
      error.data = data;
      error.status = response.status;
      throw error;
    }
    return data;
  }

  function formatTime(epochSeconds) {
    return epochSeconds ? new Date(epochSeconds * 1000).toLocaleString("vi-VN") : "";
  }

  function hostForUrl(host) {
    return host.includes(":") && !host.startsWith("[") ? "[" + host + "]" : host;
  }

  function field(form, name) {
    return form.elements.namedItem(name);
  }

  // ------------------------------------------------------------- rendering

  function render() {
    if (!state) return;
    setText($("#version"), "v" + state.version);
    renderChips();
    renderAccount();
    renderCameraSection();
  }

  function renderChips() {
    const cloud = state.cloud;
    const chipCloud = $("#chip-cloud");
    let text = "Imou: " + (CLOUD_TEXT[cloud.status] || cloud.status);
    if (cloud.account_count > 1) {
      // The chip shows the worst status; say how many accounts it applies to.
      const affected = state.accounts.filter((account) => account.status === cloud.status).length;
      const count = affected && affected < cloud.account_count ? affected + "/" + cloud.account_count : cloud.account_count;
      text += " (" + count + " tài khoản)";
    }
    setBadge(chipCloud, text, CLOUD_CLASS[cloud.status], "chip");
    chipCloud.title = cloud.message || "";
    const mtx = state.mediamtx;
    const chipMtx = $("#chip-mtx");
    setBadge(chipMtx, "Máy chủ RTSP: " + (MTX_TEXT[mtx.state] || mtx.state), MTX_CLASS[mtx.state], "chip");
    chipMtx.title = mtx.message || "";
  }

  function renderAccount() {
    const login = state.login;
    const accounts = state.accounts;
    const step = login.step;
    const busy = login.busy;
    const inFlow = step === "captcha" || step === "otp";

    if (step === "captcha" && lastStep !== null && lastStep !== "captcha") {
      lastStep = step;
      location.href = "captcha";
      return;
    }
    // Compare stamps, not steps: a quick sign-in can finish between two polls.
    const finished = login.finished || 0;
    if (lastFinished !== null && finished > lastFinished) {
      addingAccount = false;
      formMode = "";
      $("#login-password").value = "";
      banner("Đã đăng nhập " + (login.label || "tài khoản Imou") + ".", "okay");
    }
    if (lastFinished === null || finished > lastFinished) lastFinished = finished;
    lastStep = step;

    renderAccounts(busy || inFlow);
    const addButton = $("#btn-add-account");
    addButton.hidden = accounts.length === 0;
    addButton.disabled = busy || inFlow;

    // A failed sign-in of a linked account asks again for that account only.
    const failed = step === "account" && !!login.error;
    const target = failed && login.target ? accounts.find((account) => account.id === login.target) : null;
    const showForm = !inFlow && (accounts.length === 0 || addingAccount || failed);
    $("#login-form").hidden = !showForm;
    if (showForm) {
      const mode = target ? "relogin:" + target.id : "add";
      const accountInput = $("#login-account");
      if (mode !== formMode) {
        formMode = mode;
        accountInput.value = failed && login.account ? login.account : "";
        accountInput.readOnly = !!target;
        $("#login-password").value = "";
      }
      setText($("#login-title"), target ? "Đăng nhập lại " + target.label : "Thêm tài khoản Imou");
      $("#login-intro").hidden = !!target;
      $("#login-hint").hidden = !target;
      $("#btn-login-close").hidden = accounts.length === 0;
    } else {
      formMode = "";
    }
    $("#btn-login").disabled = busy;

    for (const element of $$(".login-label")) setText(element, login.label || "");
    $("#captcha-step").hidden = step !== "captcha";
    $("#otp-form").hidden = step !== "otp";
    if (step === "otp") setText($("#otp-delivery"), login.delivery || "");
    $("#btn-otp").disabled = busy;
    $("#btn-resend").disabled = busy;

    $("#login-busy").hidden = !busy;
    setText(
      $("#login-busy-text"),
      (login.label ? "Đang đăng nhập " + login.label : "Đang làm việc với Imou") + ", có thể mất tới 30 giây…"
    );
    const errorText = login.error ? login.error_text || login.error : "";
    setText($("#login-error"), errorText);
    $("#login-error").hidden = !errorText || busy;
    setText($("#login-info"), login.info || "");
    $("#login-info").hidden = !login.info || busy;
  }

  function renderAccounts(locked) {
    const container = $("#accounts");
    const seen = new Set();
    state.accounts.forEach((account, index) => {
      let row = accountRows.get(account.id);
      if (!row) {
        row = createAccountRow(account.id);
        accountRows.set(account.id, row);
      }
      seen.add(account.id);
      updateAccountRow(row, account, locked);
      if (container.children[index] !== row.root) {
        container.insertBefore(row.root, container.children[index] || null);
      }
    });
    for (const [id, row] of accountRows) {
      if (!seen.has(id)) {
        row.root.remove();
        accountRows.delete(id);
      }
    }
  }

  function createAccountRow(id) {
    const root = $("#account-template").content.firstElementChild.cloneNode(true);
    const row = {id, root, account: null, refreshing: false};
    $(".acct-refresh", root).addEventListener("click", () => refreshAccount(row));
    $(".acct-relogin", root).addEventListener("click", () => {
      addingAccount = false;
      action("api/login", {account_id: id, password: ""});
    });
    $(".acct-remove", root).addEventListener("click", () => removeAccount(row));
    return row;
  }

  function updateAccountRow(row, account, locked) {
    row.account = account;
    const root = row.root;
    setText($(".acct-label", root), account.label);
    setBadge($(".acct-status", root), CLOUD_TEXT[account.status] || account.status, CLOUD_CLASS[account.status], "badge acct-status");
    const parts = [account.device_count + " thiết bị"];
    if (account.updated) parts.push("cập nhật lúc " + formatTime(account.updated));
    if (account.message) parts.push(account.message);
    setText($(".acct-detail", root), parts.join(" · "));
    $(".acct-refresh", root).disabled = locked || row.refreshing || account.status === "needs_login";
    const relogin = $(".acct-relogin", root);
    relogin.className = account.status === "needs_login" ? "acct-relogin" : "secondary acct-relogin";
    relogin.disabled = locked;
    $(".acct-remove", root).disabled = locked;
  }

  function renderCameraSection() {
    const rtsp = state.rtsp;
    let info = "Link RTSP có dạng rtsp://" + hostForUrl(rtsp.host) + ":" + rtsp.port + "/<đường dẫn>";
    info += rtsp.auth
      ? " · cần đăng nhập bằng tài khoản RTSP “" + rtsp.username + "”."
      : " · không cần mật khẩu (đặt RTSP_USERNAME/RTSP_PASSWORD để bảo vệ).";
    setText($("#rtsp-info"), info);

    const discovery = state.discovery;
    let text;
    if (discovery.running) text = "Đang quét LAN…";
    else if (discovery.last) text = "Quét LAN lần cuối " + formatTime(discovery.last) + ": đã biết " + discovery.found + " thiết bị Imou/Dahua.";
    else text = "Chưa quét LAN.";
    if (discovery.error) text += " " + discovery.error;
    setText($("#discovery-info"), text);
    $("#btn-discover").disabled = discovery.running;

    const streamsError = state.streams_error ? "Lỗi khi cấu hình máy chủ RTSP: " + state.streams_error : "";
    setText($("#streams-error"), streamsError);
    $("#streams-error").hidden = !streamsError;

    const container = $("#cameras");
    const seen = new Set();
    state.cameras.forEach((camera, index) => {
      let card = cards.get(camera.key);
      if (!card) {
        card = createCard(camera.key);
        cards.set(camera.key, card);
      }
      seen.add(camera.key);
      updateCard(card, camera);
      if (container.children[index] !== card.root) {
        container.insertBefore(card.root, container.children[index] || null);
      }
    });
    for (const [key, card] of cards) {
      if (!seen.has(key)) {
        card.root.remove();
        cards.delete(key);
      }
    }
    $("#no-cameras").hidden = state.cameras.length > 0;
  }

  function createCard(key) {
    const root = $("#camera-template").content.firstElementChild.cloneNode(true);
    const card = {key, root, camera: null, streamsSignature: "", form: $(".cam-form", root)};
    $(".cam-toggle", root).addEventListener("click", () => (card.form.hidden ? openForm(card) : closeForm(card)));
    $(".cam-cancel", root).addEventListener("click", () => closeForm(card));
    $(".cam-reset", root).addEventListener("click", () => resetCamera(card));
    $(".cam-test", root).addEventListener("click", () => testCamera(card));
    card.form.addEventListener("submit", (event) => {
      event.preventDefault();
      saveCamera(card);
    });
    field(card.form, "mode").addEventListener("change", () => applyModeVisibility(card));
    return card;
  }

  function updateCard(card, camera) {
    card.camera = camera;
    const root = card.root;
    setText($(".cam-name", root), camera.name || camera.device_id);
    const meta = [];
    if (camera.device_name && camera.device_name !== camera.name) meta.push(camera.device_name);
    if (camera.model) meta.push(camera.model);
    meta.push("SN " + camera.device_id);
    if (camera.multi_channel) meta.push("kênh " + camera.channel_id);
    if (camera.account && state.accounts.length > 1) meta.push("tài khoản " + camera.account);
    setText($(".cam-meta", root), meta.join(" · "));

    const online = $(".cam-online", root);
    if (!camera.in_account) {
      setBadge(online, "Không còn trong tài khoản", "warn", "badge cam-online");
      online.hidden = false;
    } else if (camera.online === true) {
      setBadge(online, "Trực tuyến", "good", "badge cam-online");
      online.hidden = false;
    } else if (camera.online === false) {
      setBadge(online, "Ngoại tuyến", "bad", "badge cam-online");
      online.hidden = false;
    } else {
      online.hidden = true;
    }
    setBadge($(".cam-mode", root), MODE_TEXT[camera.config.mode] || camera.config.mode, "info", "badge cam-mode");
    root.classList.toggle("disabled", !camera.config.enabled);
    $(".cam-disabled", root).hidden = camera.config.enabled;
    renderStreams(card, camera);
  }

  function renderStreams(card, camera) {
    const rtsp = state.rtsp;
    const signature = JSON.stringify([camera.streams, rtsp.host, rtsp.hls, rtsp.webrtc]);
    if (signature === card.streamsSignature) return;
    card.streamsSignature = signature;
    const box = $(".streams", card.root);
    box.textContent = "";
    for (const stream of camera.streams) {
      const row = $("#stream-template").content.firstElementChild.cloneNode(true);
      row.classList.add(stream.state);
      setText($(".kind", row), stream.kind === "sub" ? "Luồng phụ" : "Luồng chính");
      setBadge($(".state", row), STATE_TEXT[stream.state] || stream.state, STATE_CLASS[stream.state], "badge state");
      setText($(".readers", row), stream.readers ? stream.readers + " người xem" : "");
      const input = $(".url", row);
      input.value = stream.url;
      input.addEventListener("focus", () => input.select());
      $(".copy", row).addEventListener("click", (event) => copyText(input, event.currentTarget));
      let detail = stream.detail || "";
      if (stream.source) detail += (detail ? " · " : "") + "Nguồn: " + stream.source;
      setText($(".detail", row), detail);
      const links = $(".web-links", row);
      const host = hostForUrl(rtsp.host);
      if (rtsp.webrtc) links.appendChild(webLink("http://" + host + ":" + rtsp.webrtc_port + "/" + stream.path + "/", "Xem thử (WebRTC)"));
      if (rtsp.hls) links.appendChild(webLink("http://" + host + ":" + rtsp.hls_port + "/" + stream.path + "/", "Xem thử (HLS)"));
      links.hidden = !(rtsp.webrtc || rtsp.hls);
      box.appendChild(row);
    }
  }

  function webLink(href, label) {
    const link = document.createElement("a");
    link.href = href;
    link.textContent = label;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    return link;
  }

  async function copyText(input, button) {
    let copied = false;
    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(input.value);
        copied = true;
      } catch (error) {
        copied = false;
      }
    }
    if (!copied) {
      input.focus();
      input.select();
      try {
        copied = document.execCommand("copy");
      } catch (error) {
        copied = false;
      }
    }
    button.textContent = copied ? "Đã chép" : "Hãy tự chép (Ctrl+C)";
    setTimeout(() => { button.textContent = "Sao chép"; }, 1800);
  }

  // ------------------------------------------------------------ camera form

  function applyModeVisibility(card) {
    const mode = field(card.form, "mode").value;
    const passwordSet = !!(card.camera && card.camera.config.password_set);
    for (const label of $$("[data-modes]", card.form)) {
      const modes = label.dataset.modes.split(" ");
      let hidden = !modes.includes(mode);
      if (label.classList.contains("pw-clear") && !passwordSet) hidden = true;
      label.hidden = hidden;
    }
  }

  function clearInvalid(form) {
    for (const element of $$(".invalid", form)) element.classList.remove("invalid");
  }

  function fillForm(card) {
    const camera = card.camera;
    const config = camera.config;
    const form = card.form;
    field(form, "enabled").checked = config.enabled;
    field(form, "path").value = config.path;
    field(form, "mode").value = config.mode;
    field(form, "host").value = config.host;
    field(form, "auto_host").checked = config.auto_host;
    field(form, "port").value = config.port;
    field(form, "username").value = config.username;
    field(form, "username").placeholder = camera.effective_username || "admin";
    const password = field(form, "password");
    password.value = "";
    if (config.password_set) password.placeholder = "Đã lưu – để trống để giữ nguyên";
    else if (camera.cloud_password) password.placeholder = "Imou đã cung cấp – để trống để dùng";
    else password.placeholder = "Safety Code in trên tem camera";
    field(form, "password_clear").checked = false;
    field(form, "channel").value = config.channel;
    field(form, "main").checked = config.main;
    field(form, "sub").checked = config.sub;
    field(form, "on_demand").checked = config.on_demand;
    field(form, "rtsp_transport").value = config.rtsp_transport;
    field(form, "custom_url").value = config.custom_url || "";
    const hints = [];
    if (camera.discovered_ip) hints.push("IP tìm thấy khi quét LAN: " + camera.discovered_ip);
    if (camera.cloud_ip) hints.push("IP do Imou báo: " + camera.cloud_ip);
    if (!camera.discovered_ip && !camera.cloud_ip) {
      hints.push("Chưa biết IP camera – bấm “Quét LAN” hoặc nhập IP (xem trong app Imou Life hoặc trang quản lý router).");
    }
    setText($(".form-hints", form), hints.join(" · "));
    clearInvalid(form);
    $(".form-error", form).hidden = true;
    applyModeVisibility(card);
  }

  function openForm(card) {
    fillForm(card);
    card.form.hidden = false;
    setText($(".cam-toggle", card.root), "Ẩn cấu hình");
  }

  function closeForm(card) {
    card.form.hidden = true;
    setText($(".cam-toggle", card.root), "Cấu hình");
  }

  async function saveCamera(card) {
    const form = card.form;
    const payload = {
      enabled: field(form, "enabled").checked,
      path: field(form, "path").value.trim().toLowerCase(),
      mode: field(form, "mode").value,
      host: field(form, "host").value.trim(),
      auto_host: field(form, "auto_host").checked,
      username: field(form, "username").value.trim(),
      main: field(form, "main").checked,
      sub: field(form, "sub").checked,
      on_demand: field(form, "on_demand").checked,
      rtsp_transport: field(form, "rtsp_transport").value,
      custom_url: field(form, "custom_url").value.trim(),
    };
    const port = field(form, "port").value.trim();
    if (port) payload.port = port;
    const channel = field(form, "channel").value.trim();
    if (channel) payload.channel = channel;
    const password = field(form, "password").value;
    if (password) payload.password = password;
    if (field(form, "password_clear").checked) payload.password_clear = true;

    clearInvalid(form);
    const errorBox = $(".form-error", form);
    errorBox.hidden = true;
    const submit = $('button[type="submit"]', form);
    submit.disabled = true;
    try {
      await api("api/cameras/" + encodeURIComponent(card.key), payload);
      field(form, "password").value = "";
      closeForm(card);
      banner("Đã lưu cấu hình “" + ((card.camera && card.camera.name) || card.key) + "”.", "okay");
      await refreshState();
    } catch (error) {
      errorBox.textContent = error.message;
      errorBox.hidden = false;
      const name = error.data && error.data.field;
      const input = name ? field(form, name) : null;
      if (input && input.classList) {
        input.classList.add("invalid");
        input.focus();
      }
    } finally {
      submit.disabled = false;
    }
  }

  async function resetCamera(card) {
    if (!window.confirm("Đặt lại cấu hình mặc định cho camera này? Mật khẩu camera đã lưu cũng bị xóa.")) return;
    try {
      const data = await api("api/cameras/" + encodeURIComponent(card.key) + "/reset", {});
      closeForm(card);
      banner(data.removed ? "Đã xóa camera không còn trong tài khoản." : "Đã đặt lại cấu hình mặc định.", "okay");
      await refreshState();
    } catch (error) {
      banner(error.message, "error");
    }
  }

  async function testCamera(card) {
    const button = $(".cam-test", card.root);
    const box = $(".cam-test-result", card.root);
    button.disabled = true;
    box.hidden = false;
    box.textContent = "Đang kiểm tra – có thể mất 1–2 phút…";
    let data;
    try {
      data = await api("api/cameras/" + encodeURIComponent(card.key) + "/test", {});
    } catch (error) {
      if (error.data && Array.isArray(error.data.results)) {
        data = error.data;
      } else {
        box.textContent = error.message;
        button.disabled = false;
        return;
      }
    }
    const lines = [];
    if (!data.results.length) lines.push("Camera đang tắt hoặc chưa bật luồng nào.");
    for (const item of data.results) {
      const label = item.kind === "sub" ? "Luồng phụ" : "Luồng chính";
      if (item.ok) {
        lines.push("✔ " + label + ": xem được" + (item.codecs.length ? " (" + item.codecs.join(", ") + ")" : ""));
      } else {
        lines.push("✘ " + label + ": " + (item.error || "không xem được"));
      }
    }
    box.textContent = lines.join("\n");
    button.disabled = false;
    refreshState();
  }

  // ---------------------------------------------------------------- account

  async function action(path, body, okMessage) {
    try {
      const data = await api(path, body || {});
      if (okMessage) banner(okMessage, "okay");
      return data;
    } catch (error) {
      banner(error.message, "error");
      return null;
    } finally {
      refreshState();
    }
  }

  $("#login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const passwordInput = $("#login-password");
    const body = {account: $("#login-account").value.trim(), password: passwordInput.value};
    if (formMode.startsWith("relogin:")) body.account_id = formMode.slice("relogin:".length);
    const result = await action("api/login", body);
    if (result) passwordInput.value = "";
  });

  $("#otp-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = $("#otp-code");
    const result = await action("api/otp", {code: input.value.trim()});
    if (result) input.value = "";
  });

  $("#btn-resend").addEventListener("click", () => action("api/otp/resend"));
  for (const button of $$('[data-action="cancel-login"]')) {
    button.addEventListener("click", () => action("api/login/cancel"));
  }

  $("#btn-add-account").addEventListener("click", async () => {
    addingAccount = true;
    formMode = "";
    if (state && state.login.error) {
      try {
        await api("api/login/cancel", {});
      } catch (error) {
        banner(error.message, "error");
      }
    }
    await refreshState();
    $("#login-account").focus();
  });

  $("#btn-login-close").addEventListener("click", () => {
    addingAccount = false;
    formMode = "";
    action("api/login/cancel");
  });

  async function refreshAccount(row) {
    const button = $(".acct-refresh", row.root);
    row.refreshing = true;
    button.disabled = true;
    try {
      const data = await api("api/accounts/" + encodeURIComponent(row.id) + "/refresh", {});
      if (data.status === "ok") banner(data.message || "Đã làm mới danh sách thiết bị.", "okay");
      else banner(data.message || "Không làm mới được danh sách thiết bị.", "error");
    } catch (error) {
      banner(error.message, "error");
    } finally {
      row.refreshing = false;
      refreshState();
    }
  }

  function removeAccount(row) {
    const label = row.account ? row.account.label : "";
    if (!window.confirm("Gỡ tài khoản Imou " + label + "? Cấu hình camera và link RTSP hiện có vẫn được giữ.")) return;
    action("api/accounts/" + encodeURIComponent(row.id) + "/remove", {}, "Đã gỡ tài khoản " + label + ".");
  }

  $("#btn-discover").addEventListener("click", async () => {
    const button = $("#btn-discover");
    button.disabled = true;
    try {
      const data = await api("api/discover", {});
      if (data.error) banner(data.error, "error");
      else banner("Quét xong: lần này tìm thấy " + data.found + " thiết bị Imou/Dahua.", "okay");
    } catch (error) {
      banner(error.message, "error");
    } finally {
      button.disabled = false;
      refreshState();
    }
  });

  // ------------------------------------------------------------------- logs

  async function loadLogs() {
    try {
      const data = await api("api/logs");
      const pre = $("#logs");
      pre.textContent = data.lines.join("\n") || "(trống)";
      pre.scrollTop = pre.scrollHeight;
    } catch (error) {
      banner(error.message, "error");
    }
  }

  $("#logs-panel").addEventListener("toggle", () => {
    if ($("#logs-panel").open) loadLogs();
  });
  $("#btn-logs").addEventListener("click", loadLogs);

  // ---------------------------------------------------------------- polling

  async function refreshState() {
    try {
      state = await api("api/state");
      connectionLost = false;
      render();
    } catch (error) {
      if (!connectionLost) banner(error.message, "error");
      connectionLost = true;
    }
  }

  function schedule() {
    clearTimeout(pollTimer);
    let delay = 3000;
    if (document.hidden) delay = 15000;
    else if (state && state.login.busy) delay = 1500;
    pollTimer = setTimeout(async () => {
      await refreshState();
      schedule();
    }, delay);
  }

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) refreshState().then(schedule);
  });

  refreshState().then(schedule);
})();
