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

  return res.json({ status: true, data: { token } });
});

/* ---------- Админ: генерация и управление ключами ---------- */

// Генерация N ключей. body: { count, expiresInDays? }
app.post("/admin/generate", requireAdmin, (req, res) => {
  const count = Math.min(parseInt(req.body.count, 10) || 1, 500);
  const expiresInDays = req.body.expiresInDays ? parseInt(req.body.expiresInDays, 10) : null;

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
      expiresAt: expiresInDays ? Date.now() + expiresInDays * 86400000 : null,
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

// Отозвать ключ
app.post("/admin/revoke", requireAdmin, (req, res) => {
  const db = readDb();
  const entry = db.keys.find((k) => k.key === (req.body.key || "").trim());
  if (!entry) return res.status(404).json({ status: false, msg: "Key not found" });
  entry.revoked = true;
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

/* ---------- Простая веб-панель для генерации ключей ---------- */
/* HTML зашит прямо в код сервера — не зависит от папки public/
   и от того, доехала ли она до GitHub/Render. */
const PANEL_HTML = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8" />
<title>SatanistVPN — панель ключей</title>
<style>
  body { font-family: monospace; background:#111; color:#eee; padding:24px; max-width:720px; margin:0 auto; }
  h1 { font-size:18px; }
  input, button, textarea { font-family: inherit; font-size:14px; padding:8px; margin:4px 0; }
  input[type=text], input[type=password], input[type=number] { width:100%; box-sizing:border-box; background:#222; color:#eee; border:1px solid #444; }
  button { background:#7a1f1f; color:#fff; border:none; cursor:pointer; }
  button:hover { background:#a02a2a; }
  #keys { white-space:pre-wrap; background:#1a1a1a; padding:12px; margin-top:12px; border:1px solid #333; min-height:60px; }
  .row { margin-bottom:14px; }
  label { display:block; margin-bottom:4px; opacity:.8; }
</style>
</head>
<body>
  <h1>Панель генерации ключей — SatanistVPN</h1>

  <div class="row">
    <label>Admin key (задан в ADMIN_KEY на Render)</label>
    <input type="password" id="adminKey" placeholder="admin key" />
  </div>

  <div class="row">
    <label>Количество ключей</label>
    <input type="number" id="count" value="1" min="1" max="500" />
  </div>

  <div class="row">
    <label>Срок действия (дней, пусто = бессрочно)</label>
    <input type="number" id="expires" placeholder="напр. 30" />
  </div>

  <button onclick="generate()">Сгенерировать</button>
  <button onclick="listKeys()">Показать все ключи</button>

  <div id="keys"></div>

<script>
async function generate() {
  const adminKey = document.getElementById('adminKey').value;
  const count = document.getElementById('count').value;
  const expiresInDays = document.getElementById('expires').value;

  const res = await fetch('/admin/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-admin-key': adminKey },
    body: JSON.stringify({ count, expiresInDays: expiresInDays || undefined })
  });
  const data = await res.json();
  document.getElementById('keys').textContent = data.status
    ? data.data.keys.join('\\n')
    : 'Ошибка: ' + data.msg;
}

async function listKeys() {
  const adminKey = document.getElementById('adminKey').value;
  const res = await fetch('/admin/keys', {
    headers: { 'x-admin-key': adminKey }
  });
  const data = await res.json();
  document.getElementById('keys').textContent = data.status
    ? JSON.stringify(data.data, null, 2)
    : 'Ошибка: ' + data.msg;
}
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
