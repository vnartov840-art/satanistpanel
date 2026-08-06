/**
 * Самодостаточный сервер лицензионных ключей.
 *
 * Совместим по формату с существующим Android-кодом (LicenseApi.java):
 *   - принимает POST c полями game / user_key / serial (form-urlencoded)
 *   - отвечает JSON { status: true, data: { token } } при успехе
 *   - отвечает JSON { status: false, msg: "..." } при ошибке
 *
 * Чтобы переключить приложение с modkey.host на этот сервер,
 * в LicenseApi.java достаточно поменять:
 *   ENDPOINT = "https://<твой-домен-на-render>/connect"
 *
 * Формат ключей: SATANIST-XX-YYYYYYYYYYYY
 *   XX  — короткий код (буквы/цифры, по умолчанию 2 символа)
 *   YYY — основная случайная часть (по умолчанию 12 символов)
 *
 * Хранилище: JSON-файл (data/keys.json). Это ПРОСТОЕ решение для
 * старта. На Render бесплатный инстанс не гарантирует сохранность
 * диска между деплоями/перезапусками контейнера — если нужна
 * надёжность, переезжай на Render Postgres (see README).
 */

const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "keys.json");
const ADMIN_KEY = process.env.ADMIN_KEY || "change-me"; // задай в переменных окружения Render!
const PRODUCT_NAME = process.env.PRODUCT_NAME || "SatanistVPN";

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ keys: [] }, null, 2));

function readDb() {
  return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}
function writeDb(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function randomAlnum(len) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let out = "";
  const bytes = crypto.randomBytes(len);
  for (let i = 0; i < len; i++) out += chars[bytes[i] % chars.length];
  return out;
}

/** Пример: SATANIST-3H-Kvq82nmOAxP */
function generateKey({ midLen = 2, mainLen = 12 } = {}) {
  return `SATANIST-${randomAlnum(midLen)}-${randomAlnum(mainLen)}`;
}

/**
 * Считает абсолютную дату истечения (мс) из тела запроса на генерацию.
 * Поддерживает выбор длительности в часах ИЛИ днях (то, что просили
 * добавить в панель), а также старый формат expiresInDays для
 * обратной совместимости. Ничего не передано / infinite=true → null
 * (бессрочный ключ).
 */
function computeExpiresAt(body) {
  if (body.infinite === true || body.infinite === "true") return null;

  const unit = body.durationUnit === "hours" ? "hours"
    : body.durationUnit === "days" ? "days"
    : null;
  const value = parseFloat(body.durationValue);

  if (unit && value > 0) {
    const ms = unit === "hours" ? value * 3600000 : value * 86400000;
    return Date.now() + ms;
  }

  // Обратная совместимость со старым полем.
  if (body.expiresInDays) {
    const days = parseInt(body.expiresInDays, 10);
    if (days > 0) return Date.now() + days * 86400000;
  }

  return null;
}

function requireAdmin(req, res, next) {
  const key = req.header("x-admin-key") || req.query.admin_key;
  if (key !== ADMIN_KEY) {
    return res.status(401).json({ status: false, msg: "Unauthorized" });
  }
  next();
}

/* ---------- Публичный эндпоинт: проверка ключа ---------- */

app.post(["/connect", "/398/connect"], (req, res) => {
  const userKey = (req.body.user_key || "").trim();
  const serial = (req.body.serial || "").trim();
  const product = (req.body.game || "").trim();

  if (!userKey || !serial) {
    return res.json({ status: false, msg: "Missing user_key or serial" });
  }
  if (product && product !== PRODUCT_NAME) {
    return res.json({ status: false, msg: "Unknown product" });
  }

  const db = readDb();
  const entry = db.keys.find((k) => k.key === userKey);

  if (!entry) {
    return res.json({ status: false, msg: "Key not found" });
  }
  if (entry.revoked) {
    return res.json({ status: false, msg: "Key revoked" });
  }
  if (entry.expiresAt && Date.now() > entry.expiresAt) {
    return res.json({ status: false, msg: "Key expired" });
  }
  if (entry.serial && entry.serial !== serial) {
    return res.json({ status: false, msg: "Key bound to another device" });
  }

  // Первая активация — привязываем к устройству
  if (!entry.serial) {
    entry.serial = serial;
    entry.activatedAt = Date.now();
    writeDb(db);
  }

  const token = crypto
    .createHash("sha256")
    .update(entry.key + entry.serial + (process.env.TOKEN_SALT || "salt"))
    .digest("hex")
    .slice(0, 32);

  return res.json({ status: true, data: { token, expiresAt: entry.expiresAt || 0 } });
});

/* ---------- Админ: логин панели (проверка admin key) ---------- */

// Панель дергает это при входе — просто подтверждает, что x-admin-key верный,
// без выдачи какого-то отдельного токена (сам admin key и есть "пароль").
app.post("/admin/login", requireAdmin, (req, res) => {
  res.json({ status: true });
});

/* ---------- Админ: генерация и управление ключами ---------- */

// Генерация N ключей. body: { count, durationValue, durationUnit } или { count, infinite: true }
app.post("/admin/generate", requireAdmin, (req, res) => {
  const count = Math.min(parseInt(req.body.count, 10) || 1, 500);
  const expiresAt = computeExpiresAt(req.body);

  const db = readDb();
  const created = [];
  for (let i = 0; i < count; i++) {
    let key;
    do {
      key = generateKey();
    } while (db.keys.some((k) => k.key === key)); // на случай коллизии

    const entry = {
      key,
      serial: null,
      createdAt: Date.now(),
      activatedAt: null,
      expiresAt: expiresAt,
      revoked: false,
    };
    db.keys.push(entry);
    created.push(key);
  }
  writeDb(db);
  res.json({ status: true, data: { keys: created } });
});

// Список всех ключей
app.get("/admin/keys", requireAdmin, (req, res) => {
  const db = readDb();
  res.json({ status: true, data: db.keys });
});

// Отозвать ключ ("Остановить" в панели)
app.post("/admin/revoke", requireAdmin, (req, res) => {
  const db = readDb();
  const entry = db.keys.find((k) => k.key === (req.body.key || "").trim());
  if (!entry) return res.status(404).json({ status: false, msg: "Key not found" });
  entry.revoked = true;
  writeDb(db);
  res.json({ status: true });
});

// Снова разрешить остановленный ключ
app.post("/admin/unrevoke", requireAdmin, (req, res) => {
  const db = readDb();
  const entry = db.keys.find((k) => k.key === (req.body.key || "").trim());
  if (!entry) return res.status(404).json({ status: false, msg: "Key not found" });
  entry.revoked = false;
  writeDb(db);
  res.json({ status: true });
});

// Отвязать устройство (снять serial), чтобы ключ можно было активировать заново
app.post("/admin/unbind", requireAdmin, (req, res) => {
  const db = readDb();
  const entry = db.keys.find((k) => k.key === (req.body.key || "").trim());
  if (!entry) return res.status(404).json({ status: false, msg: "Key not found" });
  entry.serial = null;
  entry.activatedAt = null;
  writeDb(db);
  res.json({ status: true });
});

// Полностью удалить ключ из базы ("Удалить" в панели)
app.post("/admin/delete", requireAdmin, (req, res) => {
  const targetKey = (req.body.key || "").trim();
  const db = readDb();
  const before = db.keys.length;
  db.keys = db.keys.filter((k) => k.key !== targetKey);
  if (db.keys.length === before) {
    return res.status(404).json({ status: false, msg: "Key not found" });
  }
  writeDb(db);
  res.json({ status: true });
});

/* ---------- Веб-панель: логин → главное меню (создание ключа) → управление ключами ---------- */
/* HTML зашит прямо в код сервера — не зависит от папки public/
   и от того, доехала ли она до GitHub/Render. */
const PANEL_HTML = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>SatanistVPN — панель</title>
<style>
  :root {
    --bg: #0f0f13;
    --panel: #17171d;
    --panel-2: #1e1e26;
    --border: #2a2a34;
    --text: #eee;
    --muted: #9a9aa5;
    --accent: #8b2fc9;
    --accent-hover: #a444e0;
    --danger: #e0473d;
    --danger-hover: #f0605a;
    --ok: #3ddc84;
  }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    min-height: 100vh;
  }
  input, button, select {
    font-family: inherit;
    font-size: 14px;
  }
  input, select {
    width: 100%;
    padding: 11px 12px;
    background: var(--panel-2);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 8px;
    outline: none;
  }
  input:focus, select:focus { border-color: var(--accent); }
  button {
    padding: 11px 16px;
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 8px;
    cursor: pointer;
    font-weight: 600;
  }
  button:hover { background: var(--accent-hover); }
  button.secondary { background: var(--panel-2); border: 1px solid var(--border); }
  button.secondary:hover { background: #26262f; }
  button.danger { background: var(--danger); }
  button.danger:hover { background: var(--danger-hover); }
  button:disabled { opacity: .5; cursor: default; }
  label { display: block; margin-bottom: 6px; color: var(--muted); font-size: 13px; }
  .field { margin-bottom: 14px; }
  .hidden { display: none !important; }

  /* ---------- Логин ---------- */
  #view-login {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 16px;
  }
  .login-card {
    width: 100%;
    max-width: 340px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 28px 24px;
  }
  .login-card h1 {
    font-size: 20px;
    margin: 0 0 4px;
    text-align: center;
  }
  .login-card .sub {
    color: var(--muted);
    font-size: 13px;
    text-align: center;
    margin-bottom: 22px;
  }
  .login-error {
    color: var(--danger);
    font-size: 13px;
    margin-top: 10px;
    text-align: center;
    min-height: 16px;
  }

  /* ---------- Общий каркас после входа ---------- */
  #view-app { display: none; min-height: 100vh; }
  .topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 18px;
    border-bottom: 1px solid var(--border);
    background: var(--panel);
    position: sticky;
    top: 0;
    z-index: 5;
  }
  .topbar h2 { margin: 0; font-size: 16px; }
  .burger {
    background: transparent;
    border: none;
    font-size: 22px;
    line-height: 1;
    padding: 6px 10px;
    color: var(--text);
    cursor: pointer;
  }
  .burger:hover { background: var(--panel-2); border-radius: 8px; }

  .content { max-width: 560px; margin: 0 auto; padding: 20px 16px 60px; }
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 20px;
    margin-bottom: 18px;
  }
  .card h3 { margin: 0 0 16px; font-size: 15px; }

  .duration-row { display: flex; gap: 8px; }
  .duration-row input { flex: 1; }
  .duration-row select { flex: 1; }
  .infinite-toggle {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 10px 0 16px;
    color: var(--muted);
    font-size: 13px;
  }
  .infinite-toggle input { width: auto; }

  .generated-list {
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px;
    margin-top: 14px;
    font-family: "SF Mono", Consolas, monospace;
    font-size: 13px;
    white-space: pre-wrap;
    word-break: break-all;
  }

  /* ---------- Drawer управления ключами ---------- */
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,.5);
    z-index: 10;
    opacity: 0;
    pointer-events: none;
    transition: opacity .2s ease;
  }
  .overlay.open { opacity: 1; pointer-events: auto; }
  .drawer {
    position: fixed;
    top: 0; right: 0; bottom: 0;
    width: min(380px, 92vw);
    background: var(--panel);
    border-left: 1px solid var(--border);
    z-index: 11;
    transform: translateX(100%);
    transition: transform .22s ease;
    display: flex;
    flex-direction: column;
  }
  .drawer.open { transform: translateX(0); }
  .drawer-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 16px 12px;
    border-bottom: 1px solid var(--border);
  }
  .drawer-header h3 { margin: 0; font-size: 15px; }
  .drawer-close {
    background: transparent;
    border: none;
    color: var(--muted);
    font-size: 20px;
    cursor: pointer;
    padding: 4px 8px;
  }
  .drawer-close:hover { color: var(--text); }
  .drawer-body { flex: 1; overflow-y: auto; padding: 10px 12px; }
  .drawer-refresh { padding: 10px 16px 0; }

  .key-item {
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 12px;
    margin-bottom: 8px;
    cursor: pointer;
  }
  .key-item:hover { border-color: var(--accent); }
  .key-item.selected { border-color: var(--accent); background: #241a2e; }
  .key-item .key-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }
  .key-item .key-code {
    font-family: "SF Mono", Consolas, monospace;
    font-size: 12.5px;
    word-break: break-all;
  }
  .badge {
    flex-shrink: 0;
    font-size: 11px;
    font-weight: 700;
    padding: 3px 8px;
    border-radius: 999px;
    white-space: nowrap;
  }
  .badge.active { background: rgba(61,220,132,.15); color: var(--ok); }
  .badge.inactive { background: rgba(224,71,61,.15); color: var(--danger); }
  .key-item .remaining {
    margin-top: 6px;
    font-size: 12px;
    color: var(--muted);
  }

  .key-details {
    border-top: 1px solid var(--border);
    padding: 14px 16px 18px;
  }
  .key-details .kd-key {
    font-family: "SF Mono", Consolas, monospace;
    font-size: 13px;
    word-break: break-all;
    margin-bottom: 10px;
  }
  .kd-row {
    display: flex;
    justify-content: space-between;
    font-size: 13px;
    color: var(--muted);
    margin-bottom: 6px;
  }
  .kd-row span:last-child { color: var(--text); }
  .kd-actions { display: flex; gap: 8px; margin-top: 12px; }
  .kd-actions button { flex: 1; }
  .empty-note { color: var(--muted); font-size: 13px; text-align: center; padding: 20px 0; }
</style>
</head>
<body>

  <!-- ===== Экран входа ===== -->
  <div id="view-login">
    <div class="login-card">
      <h1>SatanistVPN</h1>
      <div class="sub">Панель управления ключами</div>
      <div class="field">
        <label>Admin key</label>
        <input type="password" id="loginInput" placeholder="Пароль администратора" />
      </div>
      <button id="loginBtn" style="width:100%">Войти</button>
      <div class="login-error" id="loginError"></div>
    </div>
  </div>

  <!-- ===== Главный экран после входа ===== -->
  <div id="view-app">
    <div class="topbar">
      <h2>SatanistVPN</h2>
      <button class="burger" id="openDrawerBtn" title="Управление ключами">&#9776;</button>
    </div>

    <div class="content">
      <div class="card">
        <h3>Создать ключ</h3>

        <div class="field">
          <label>Количество ключей</label>
          <input type="number" id="genCount" value="1" min="1" max="500" />
        </div>

        <div class="field">
          <label>Срок действия</label>
          <div class="duration-row">
            <input type="number" id="genDurationValue" value="30" min="1" />
            <select id="genDurationUnit">
              <option value="days" selected>дней</option>
              <option value="hours">часов</option>
            </select>
          </div>
        </div>

        <div class="infinite-toggle">
          <input type="checkbox" id="genInfinite" />
          <label for="genInfinite" style="margin:0">Бессрочный ключ</label>
        </div>

        <button id="generateBtn" style="width:100%">Сгенерировать</button>

        <div class="generated-list hidden" id="generatedList"></div>
      </div>
    </div>
  </div>

  <!-- ===== Drawer: управление ключами ===== -->
  <div class="overlay" id="overlay"></div>
  <div class="drawer" id="drawer">
    <div class="drawer-header">
      <h3>Управление ключами</h3>
      <button class="drawer-close" id="closeDrawerBtn">&times;</button>
    </div>
    <div class="drawer-refresh">
      <button class="secondary" id="refreshKeysBtn" style="width:100%">Обновить список</button>
    </div>
    <div class="drawer-body" id="keyList"></div>
    <div id="keyDetails"></div>
  </div>

<script>
let adminKey = sessionStorage.getItem('adminKey') || '';
let allKeys = [];
let selectedKey = null;

const $ = (id) => document.getElementById(id);

function fmtDuration(ms) {
  if (ms < 0) ms = 0;
  const totalMin = Math.floor(ms / 60000);
  const days = Math.floor(totalMin / 1440);
  const hours = Math.floor((totalMin % 1440) / 60);
  const mins = totalMin % 60;
  if (days > 0) return days + 'д ' + hours + 'ч';
  if (hours > 0) return hours + 'ч ' + mins + 'м';
  return mins + 'м';
}

function keyStatus(k) {
  if (k.revoked) return { active: false, label: 'Остановлен' };
  if (k.expiresAt && Date.now() > k.expiresAt) return { active: false, label: 'Истёк' };
  return { active: true, label: 'Активен' };
}

/* ---------- Вход ---------- */

async function doLogin() {
  const value = $('loginInput').value.trim();
  $('loginError').textContent = '';
  if (!value) return;

  $('loginBtn').disabled = true;
  try {
    const res = await fetch('/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-admin-key': value }
    });
    if (res.status === 200) {
      adminKey = value;
      sessionStorage.setItem('adminKey', adminKey);
      showApp();
    } else {
      $('loginError').textContent = 'Неверный пароль';
    }
  } catch (e) {
    $('loginError').textContent = 'Не удалось связаться с сервером';
  } finally {
    $('loginBtn').disabled = false;
  }
}

function showApp() {
  $('view-login').style.display = 'none';
  $('view-app').style.display = 'block';
}

$('loginBtn').addEventListener('click', doLogin);
$('loginInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') doLogin(); });

/* ---------- Создание ключей ---------- */

$('genInfinite').addEventListener('change', (e) => {
  const disabled = e.target.checked;
  $('genDurationValue').disabled = disabled;
  $('genDurationUnit').disabled = disabled;
});

$('generateBtn').addEventListener('click', async () => {
  const count = $('genCount').value;
  const infinite = $('genInfinite').checked;
  const durationValue = $('genDurationValue').value;
  const durationUnit = $('genDurationUnit').value;

  const body = infinite
    ? { count, infinite: true }
    : { count, durationValue, durationUnit };

  const res = await fetch('/admin/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-admin-key': adminKey },
    body: JSON.stringify(body)
  });
  const data = await res.json();
  const list = $('generatedList');
  list.classList.remove('hidden');
  list.textContent = data.status ? data.data.keys.join('\\n') : 'Ошибка: ' + data.msg;
});

/* ---------- Drawer управления ключами ---------- */

function openDrawer() {
  $('overlay').classList.add('open');
  $('drawer').classList.add('open');
  loadKeys();
}
function closeDrawer() {
  $('overlay').classList.remove('open');
  $('drawer').classList.remove('open');
}
$('openDrawerBtn').addEventListener('click', openDrawer);
$('closeDrawerBtn').addEventListener('click', closeDrawer);
$('overlay').addEventListener('click', closeDrawer);
$('refreshKeysBtn').addEventListener('click', loadKeys);

async function loadKeys() {
  const res = await fetch('/admin/keys', { headers: { 'x-admin-key': adminKey } });
  const data = await res.json();
  if (!data.status) return;
  allKeys = data.data.slice().sort((a, b) => b.createdAt - a.createdAt);
  selectedKey = null;
  renderKeyList();
  renderKeyDetails();
}

function renderKeyList() {
  const container = $('keyList');
  if (allKeys.length === 0) {
    container.innerHTML = '<div class="empty-note">Ключей пока нет</div>';
    return;
  }
  container.innerHTML = '';
  allKeys.forEach((k) => {
    const status = keyStatus(k);
    const item = document.createElement('div');
    item.className = 'key-item' + (selectedKey === k.key ? ' selected' : '');
    const remainingText = !k.expiresAt
      ? 'Бессрочный'
      : (status.active ? 'Осталось: ' + fmtDuration(k.expiresAt - Date.now()) : status.label);
    item.innerHTML =
      '<div class="key-row">' +
        '<div class="key-code">' + k.key + '</div>' +
        '<div class="badge ' + (status.active ? 'active' : 'inactive') + '">' + status.label + '</div>' +
      '</div>' +
      '<div class="remaining">' + remainingText + '</div>';
    item.addEventListener('click', () => {
      selectedKey = (selectedKey === k.key) ? null : k.key;
      renderKeyList();
      renderKeyDetails();
    });
    container.appendChild(item);
  });
}

function renderKeyDetails() {
  const container = $('keyDetails');
  if (!selectedKey) {
    container.innerHTML = '';
    return;
  }
  const k = allKeys.find((x) => x.key === selectedKey);
  if (!k) { container.innerHTML = ''; return; }
  const status = keyStatus(k);
  const remainingText = !k.expiresAt
    ? 'Бессрочный'
    : (status.active ? fmtDuration(k.expiresAt - Date.now()) : status.label);

  container.innerHTML =
    '<div class="key-details">' +
      '<div class="kd-key">' + k.key + '</div>' +
      '<div class="kd-row"><span>Статус</span><span>' + status.label + '</span></div>' +
      '<div class="kd-row"><span>Осталось</span><span>' + remainingText + '</span></div>' +
      '<div class="kd-row"><span>Устройство</span><span>' + (k.serial ? 'привязано' : 'не активирован') + '</span></div>' +
      '<div class="kd-actions">' +
        '<button class="secondary" id="stopKeyBtn" ' + (status.active ? '' : 'disabled') + '>Остановить</button>' +
        '<button class="danger" id="deleteKeyBtn">Удалить</button>' +
      '</div>' +
    '</div>';

  const stopBtn = $('stopKeyBtn');
  if (stopBtn) stopBtn.addEventListener('click', () => stopKey(k.key));
  $('deleteKeyBtn').addEventListener('click', () => deleteKey(k.key));
}

async function stopKey(key) {
  const res = await fetch('/admin/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-admin-key': adminKey },
    body: JSON.stringify({ key })
  });
  const data = await res.json();
  if (data.status) loadKeys();
}

async function deleteKey(key) {
  if (!confirm('Удалить ключ ' + key + ' безвозвратно?')) return;
  const res = await fetch('/admin/delete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-admin-key': adminKey },
    body: JSON.stringify({ key })
  });
  const data = await res.json();
  if (data.status) loadKeys();
}

/* ---------- Автовход, если ключ уже сохранён в этой вкладке ---------- */

(async function tryAutoLogin() {
  if (!adminKey) return;
  try {
    const res = await fetch('/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-admin-key': adminKey }
    });
    if (res.status === 200) showApp();
    else sessionStorage.removeItem('adminKey');
  } catch (e) {}
})();
</script>
</body>
</html>`;

app.get("/panel", (req, res) => {
  res.type("html").send(PANEL_HTML);
});

app.get("/", (req, res) => {
  res.send("License server is running. Admin panel: /panel");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`License server listening on port ${PORT}`);
});