# SatanistVPN — License Server

Свой сервер лицензионных ключей на замену modkey.host.

## Формат ключей

```
SATANIST-3H-Kvq82nmOAxP
```

## Локальный запуск

```bash
npm install
ADMIN_KEY=супер-секретный-пароль npm start
```

Сервер поднимется на `http://localhost:3000`.
Панель генерации ключей: `http://localhost:3000/panel`

## Деплой на Render

1. Залей этот проект в репозиторий на GitHub.
2. На [render.com](https://render.com) → **New +** → **Web Service** → выбери репозиторий.
3. Настройки:
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
4. В **Environment** добавь переменные:
   - `ADMIN_KEY` — свой секретный пароль для панели/API генерации (обязательно смени дефолтный!)
   - `PRODUCT_NAME` — по умолчанию `SatanistVPN` (можно не трогать)
   - `TOKEN_SALT` — любая случайная строка (соль для токена)
5. Деплой. Твой URL будет вида `https://satanistvpn-license.onrender.com`.

⚠️ **Важно про хранение данных**: бесплатный план Render не гарантирует
сохранность файлов на диске между редеплоями/перезапусками контейнера.
`data/keys.json` может обнулиться. Если ключи должны переживать редеплои —
подключи Render Disk (платно) или перенеси хранилище на Render Postgres
(нужно будет заменить чтение/запись JSON-файла на SQL-запросы).

## Подключение Android-приложения

В `LicenseApi.java` поменяй только эндпоинт:

```java
private static final String ENDPOINT = "https://<твой-домен>.onrender.com/connect";
```

Остальной код (`game=`, `user_key=`, `serial=`, разбор `status`/`data.token`/`msg`)
менять не нужно — сервер отвечает в том же формате.

## API

### `POST /connect` (публичный, дергает приложение)
Form-urlencoded: `game`, `user_key`, `serial`
→ `{ "status": true, "data": { "token": "..." } }` или `{ "status": false, "msg": "..." }`

### `POST /admin/generate` (требует заголовок `x-admin-key`)
JSON: `{ "count": 5, "expiresInDays": 30 }`
→ `{ "status": true, "data": { "keys": [...] } }`

### `GET /admin/keys` (требует `x-admin-key`)
→ список всех ключей с их статусом

### `POST /admin/revoke` (требует `x-admin-key`)
JSON: `{ "key": "SATANIST-..." }` — отзывает ключ

### `POST /admin/unbind` (требует `x-admin-key`)
JSON: `{ "key": "SATANIST-..." }` — отвязывает устройство, чтобы ключ можно было активировать заново
