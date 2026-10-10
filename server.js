const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || "change-this-secret-in-production";

const db = new sqlite3.Database(path.join(__dirname, "blueshield.sqlite"));
db.serialize(() => {
  db.run(`PRAGMA foreign_keys = ON`);
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS vpn_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    provider TEXT NOT NULL DEFAULT 'H1Cloud',
    access_key TEXT NOT NULL,
    subscription_url TEXT,
    client_name TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    plan TEXT NOT NULL DEFAULT 'Free',
    status TEXT NOT NULL DEFAULT 'Не активна',
    price INTEGER NOT NULL DEFAULT 0,
    period_months INTEGER NOT NULL DEFAULT 0,
    started_at TEXT,
    expires_at TEXT,
    auto_renew INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    plan_key TEXT NOT NULL,
    amount INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    error TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
});
// Миграции для существующих баз: новые колонки добавляются без потери данных.
async function migrate() {
  const cols = async table => (await dbAll(`PRAGMA table_info(${table})`)).map(c => c.name);
  const add = async (table, col, type) => {
    if (!(await cols(table)).includes(col)) await dbRun(`ALTER TABLE ${table} ADD COLUMN ${col} ${type}`);
  };
  await add("vpn_keys", "client_name", "TEXT");
  await add("vpn_keys", "sub_token", "TEXT");
  await add("users", "telegram_id", "TEXT");
  await add("users", "telegram_username", "TEXT");
  await add("users", "telegram_photo", "TEXT");
  await dbRun("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_telegram ON users(telegram_id) WHERE telegram_id IS NOT NULL");
  await dbRun("CREATE UNIQUE INDEX IF NOT EXISTS idx_vpn_keys_sub_token ON vpn_keys(sub_token) WHERE sub_token IS NOT NULL");
}
const ready = migrate().catch(e => { console.error("SQLite migration failed:", e.message); process.exit(1); });

app.use(express.json({ limit: "100kb", verify: (req, res, buf) => { req.rawBody = buf; } }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: __dirname }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 24 * 30
  }
}));

app.use(express.static(path.join(__dirname, "public")));
app.use("/admin", express.static(path.join(__dirname, "admin")));

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}
const TG_EMAIL_DOMAIN = "@telegram.local"; // служебный email для аккаунтов, созданных через Telegram
function publicUser(row) {
  const email = row.email && !row.email.endsWith(TG_EMAIL_DOMAIN) ? row.email : null;
  return {
    id: row.id, name: row.name, email, created_at: row.created_at,
    telegram: row.telegram_id ? { id: row.telegram_id, username: row.telegram_username || null, photo: row.telegram_photo || null } : null
  };
}
function getUserById(id) {
  return new Promise((resolve, reject) => {
    db.get("SELECT id,name,email,created_at,telegram_id,telegram_username,telegram_photo FROM users WHERE id=?", [id], (err, row) =>
      err ? reject(err) : resolve(row)
    );
  });
}
function getUserAuthByEmail(email) {
  return new Promise((resolve, reject) => {
    db.get("SELECT * FROM users WHERE email=?", [email], (err, row) =>
      err ? reject(err) : resolve(row)
    );
  });
}
function getSubscription(userId) {
  return new Promise((resolve, reject) => {
    db.get("SELECT * FROM subscriptions WHERE user_id=?", [userId], (err, row) =>
      err ? reject(err) : resolve(row || {
        plan: "Free", status: "Не активна", price: 0, period_months: 0,
        started_at: null, expires_at: null, auto_renew: 0
      })
    );
  });
}
async function getVpnKey(userId) {
  return new Promise((resolve, reject) => db.get(
    "SELECT provider, access_key, subscription_url, client_name, sub_token, updated_at FROM vpn_keys WHERE user_id=?",
    [userId], (err, row) => err ? reject(err) : resolve(row || null)
  ));
}
function newSubToken() { return crypto.randomBytes(18).toString("base64url"); }
function existingClientName(userId) {
  return `blueshield_${Number(userId)}`;
}

// ───────────────────────── H1Cloud API ─────────────────────────
function h1Config() {
  const baseUrl = (process.env.H1CLOUD_API_URL || "https://my.h1cloud.net").replace(/\/+$/, "");
  const token = String(process.env.H1CLOUD_API_TOKEN || "").trim();
  const serverId = String(process.env.H1CLOUD_SERVER_ID || "").trim();
  return { baseUrl, token, serverId };
}
function httpError(message, status) { const e = new Error(message); e.status = status; return e; }

async function h1Request(method, apiPath, body) {
  const { baseUrl, token } = h1Config();
  if (!token) throw httpError("H1Cloud не настроен: задайте H1CLOUD_API_TOKEN на сервере", 503);
  let response;
  try {
    response = await fetch(`${baseUrl}${apiPath}`, {
      method,
      headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json", "Accept": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(20000)
    });
  } catch (e) {
    console.error(`H1Cloud ${method} ${apiPath} network error:`, e.message);
    throw httpError("H1Cloud недоступен (сеть/таймаут). Попробуйте позже.", 502);
  }
  const payload = await response.json().catch(() => ({}));
  return { ok: response.ok && payload.ok !== false, status: response.status, payload };
}

function requireServerId() {
  const { serverId } = h1Config();
  if (!serverId) throw httpError("H1Cloud не настроен: задайте H1CLOUD_SERVER_ID на сервере", 503);
  // Документация H1Cloud описывает server ID как integer.
  if (!/^\d+$/.test(serverId))
    throw httpError("H1CLOUD_SERVER_ID должен быть числовым ID из GET /api/v1/servers (проверьте в админ-панели → «Проверить H1Cloud»)", 503);
  return serverId;
}

function extractLinks(payload) {
  const client = payload.client || payload.data || payload || {};
  const accessKey = client.link || client.vless_url || client.vlessUrl || client.uri;
  const subLinks = Array.isArray(client.sub_links) ? client.sub_links.filter(x => typeof x === "string" && x.trim()) : [];
  return {
    accessKey: typeof accessKey === "string" && accessKey.trim() ? accessKey.trim() : null,
    subscriptionUrl: subLinks[0] ? subLinks[0].trim() : null
  };
}

/**
 * Создаёт клиента H1Cloud или продлевает уже выданного.
 * plan — объект тарифа ({ days, ... }), а не строка.
 */
async function provisionH1Cloud(user, plan) {
  const serverId = requireServerId();
  const days = Number(plan && plan.days);
  if (!Number.isInteger(days) || days < 1) throw httpError("Некорректный срок VPN-тарифа", 500);

  const existingKey = await getVpnKey(user.id);
  if (existingKey) {
    // Продлеваем существующего клиента, чтобы у пользователя не менялся ключ.
    const name = existingKey.client_name || existingClientName(user.id);
    const r = await h1Request("PATCH", `/api/v1/servers/${serverId}/clients/${encodeURIComponent(name)}`, { days });
    if (r.ok) {
      const fresh = extractLinks(r.payload);
      return {
        accessKey: fresh.accessKey || existingKey.access_key,
        subscriptionUrl: fresh.subscriptionUrl || existingKey.subscription_url || null,
        clientName: name, renewed: true
      };
    }
    console.error("H1Cloud renew error:", r.status, r.payload && r.payload.error || "");
    throw httpError("Не удалось продлить существующий ключ H1Cloud. Проверьте клиента в панели H1Cloud.", 502);
  }

  const clientName = existingClientName(user.id);
  const r = await h1Request("POST", `/api/v1/servers/${serverId}/clients`, { name: clientName, gb: 0, days });
  if (!r.ok) {
    console.error("H1Cloud create error:", r.status, r.payload && r.payload.error || "");
    throw httpError("H1Cloud не смог выдать ключ. Проверьте ID сервера, API-токен и состояние сервера.",
      r.status === 401 || r.status === 403 ? 503 : 502);
  }
  const links = extractLinks(r.payload);
  if (!links.accessKey) throw httpError("H1Cloud ответил успешно, но в client.link нет ссылки подключения", 502);
  return { ...links, clientName, renewed: false };
}

// ───────────────────── Выдача доступа (единая точка) ─────────────────────
const plans = {
  "1": { plan: "Premium", price: 299, months: 1, days: 30 },
  "6": { plan: "Premium 6 месяцев", price: 1199, months: 6, days: 180 },
  "12": { plan: "Premium 12 месяцев", price: 1999, months: 12, days: 365 }
};
const DAY_MS = 24 * 60 * 60 * 1000;
const inFlight = new Set(); // защита от двойного клика / параллельных webhook'ов

function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => db.run(sql, params, function (err) { err ? reject(err) : resolve(this); }));
}
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows)));
}
function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => db.get(sql, params, (err, row) => err ? reject(err) : resolve(row)));
}

/**
 * Выдаёт/продлевает ключ H1Cloud и активирует подписку.
 * Вызывается из демо-покупки, из webhook'а оплаты и из админ-панели.
 */
async function grantAccess(userId, plan) {
  if (inFlight.has(userId)) throw httpError("Выдача ключа для этого аккаунта уже выполняется, подождите", 409);
  inFlight.add(userId);
  try {
    const user = await getUserById(userId);
    if (!user) throw httpError("Пользователь не найден", 404);

    // Сначала реальный ключ; подписку не активируем, если H1Cloud вернул ошибку.
    const provisioned = await provisionH1Cloud(user, plan);

    // Если подписка ещё активна — продлеваем от текущей даты окончания.
    const current = await getSubscription(userId);
    const now = new Date();
    const currentEnd = current.expires_at ? new Date(current.expires_at) : null;
    const stillActive = current.status === "Активна" && currentEnd && currentEnd > now;
    const base = stillActive ? currentEnd : now;
    const startedAt = stillActive && current.started_at ? current.started_at : now.toISOString();
    const expiresAt = new Date(base.getTime() + plan.days * DAY_MS).toISOString();

    await dbRun(`INSERT INTO vpn_keys(user_id,provider,access_key,subscription_url,client_name,sub_token,updated_at)
      VALUES(?, 'H1Cloud', ?, ?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(user_id) DO UPDATE SET provider='H1Cloud', access_key=excluded.access_key,
      subscription_url=excluded.subscription_url, client_name=excluded.client_name,
      sub_token=COALESCE(vpn_keys.sub_token, excluded.sub_token), updated_at=CURRENT_TIMESTAMP`,
      [userId, provisioned.accessKey, provisioned.subscriptionUrl, provisioned.clientName, newSubToken()]);
    await dbRun(`INSERT INTO subscriptions(user_id,plan,status,price,period_months,started_at,expires_at,auto_renew,updated_at)
      VALUES(?,?,?,?,?,?,?,0,CURRENT_TIMESTAMP)
      ON CONFLICT(user_id) DO UPDATE SET
      plan=excluded.plan,status=excluded.status,price=excluded.price,period_months=excluded.period_months,
      started_at=excluded.started_at,expires_at=excluded.expires_at,updated_at=CURRENT_TIMESTAMP`,
      [userId, plan.plan, "Активна", plan.price, plan.months, startedAt, expiresAt]);

    console.log(`H1Cloud: ${provisioned.renewed ? "продлён" : "выдан"} ключ user=${userId} +${plan.days}д до ${expiresAt}`);
    return provisioned;
  } finally {
    inFlight.delete(userId);
  }
}

async function accountPayload(userId) {
  const row = await getUserById(userId);
  if (!row) return null;
  let vpnKey = await getVpnKey(userId);
  if (vpnKey && !vpnKey.sub_token) {
    vpnKey.sub_token = newSubToken();
    await dbRun("UPDATE vpn_keys SET sub_token=? WHERE user_id=?", [vpnKey.sub_token, userId]);
  }
  const subPath = vpnKey ? `/sub/${vpnKey.sub_token}` : null;
  if (vpnKey) delete vpnKey.sub_token;
  return { user: publicUser(row), subscription: await getSubscription(userId), vpnKey, subPath };
}
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Требуется авторизация" });
  next();
}

app.post("/api/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");
    if (name.length < 2) return res.status(400).json({ error: "Введите имя минимум из 2 символов" });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Введите корректный email" });
    if (password.length < 6) return res.status(400).json({ error: "Пароль должен содержать минимум 6 символов" });
    if (email.endsWith(TG_EMAIL_DOMAIN)) return res.status(400).json({ error: "Этот email-домен недоступен для регистрации" });

    const existing = await getUserAuthByEmail(email);
    if (existing) return res.status(409).json({ error: "Аккаунт с таким email уже существует" });

    const hash = await bcrypt.hash(password, 12);
    const id = await new Promise((resolve, reject) => {
      db.run("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)", [name, email, hash], function(err) {
        err ? reject(err) : resolve(this.lastID);
      });
    });
    req.session.userId = id;
    req.session.save(async (err) => {
      if (err) return res.status(500).json({ error: "Не удалось сохранить сессию" });
      res.status(201).json(await accountPayload(id));
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Ошибка сервера при регистрации" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");
    const user = await getUserAuthByEmail(email);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Неверный email или пароль" });
    }
    req.session.userId = user.id;
    req.session.save(async (err) => {
      if (err) return res.status(500).json({ error: "Не удалось сохранить сессию" });
      res.json(await accountPayload(user.id));
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Ошибка сервера при входе" });
  }
});

app.get("/api/me", async (req, res) => {
  try {
    if (!req.session.userId) return res.json({ user: null, subscription: null });
    const payload = await accountPayload(req.session.userId);
    if (!payload) {
      req.session.destroy(() => {});
      return res.json({ user: null, subscription: null });
    }
    res.json(payload);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Не удалось получить аккаунт" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/vpn-key", requireAuth, async (req, res) => {
  try {
    const sub = await getSubscription(req.session.userId);
    if (sub.status !== "Активна" || !sub.expires_at || new Date(sub.expires_at) <= new Date())
      return res.status(403).json({ error: "Для получения ключа нужна активная подписка" });
    const key = await getVpnKey(req.session.userId);
    if (!key) return res.status(404).json({ error: "Ключ ещё не выдан. Обратитесь в поддержку или повторите после настройки H1Cloud." });
    res.json({ provider: key.provider, accessKey: key.access_key, subscriptionUrl: key.subscription_url, updatedAt: key.updated_at });
  } catch (e) { console.error(e); res.status(500).json({ error: "Не удалось получить VPN-ключ" }); }
});

app.get("/api/subscription", requireAuth, async (req, res) => {
  try { res.json(await getSubscription(req.session.userId)); }
  catch (e) { res.status(500).json({ error: "Не удалось получить подписку" }); }
});

// Покупка тарифа.
// DEMO_PURCHASES_ENABLED=true  → ключ выдаётся сразу (только для теста, без оплаты).
// Иначе создаётся заказ; ключ выдаётся автоматически после webhook'а об оплате.
app.post("/api/purchase", requireAuth, async (req, res) => {
  try {
    const planKey = String(req.body.months);
    const plan = plans[planKey];
    if (!plan) return res.status(400).json({ error: "Неизвестный тариф" });

    if (process.env.DEMO_PURCHASES_ENABLED === "true") {
      await grantAccess(req.session.userId, plan);
      return res.json({ ...(await accountPayload(req.session.userId)), demo: true });
    }

    const redirectTemplate = process.env.PAYMENT_REDIRECT_URL;
    if (!redirectTemplate || !process.env.PAYMENT_WEBHOOK_SECRET) {
      return res.status(503).json({ error: "Оплата ещё не подключена. Ключи выдаются только после подтверждённой оплаты." });
    }
    const orderId = crypto.randomUUID();
    await dbRun(`INSERT INTO orders(id,user_id,plan_key,amount,status) VALUES(?,?,?,?, 'pending')`,
      [orderId, req.session.userId, planKey, plan.price]);
    const redirect = redirectTemplate
      .replace(/\{order_id\}/g, encodeURIComponent(orderId))
      .replace(/\{amount\}/g, String(plan.price))
      .replace(/\{plan\}/g, encodeURIComponent(plan.plan));
    res.json({ orderId, redirect });
  } catch (e) {
    console.error(e.message);
    res.status(e.status || 500).json({ error: e.status ? e.message : "Не удалось оформить подписку" });
  }
});

// Webhook платёжной системы (или вашего платёжного шлюза).
// Тело: {"order_id":"...","status":"paid","amount":299}
// Заголовок X-Signature: sha256=<HMAC-SHA256(сырое тело, PAYMENT_WEBHOOK_SECRET) в hex>
app.post("/api/payments/webhook", async (req, res) => {
  const secret = process.env.PAYMENT_WEBHOOK_SECRET;
  if (!secret) return res.status(503).json({ error: "PAYMENT_WEBHOOK_SECRET не задан" });

  const given = String(req.get("X-Signature") || "").replace(/^sha256=/i, "").trim().toLowerCase();
  const expected = crypto.createHmac("sha256", secret).update(req.rawBody || Buffer.alloc(0)).digest("hex");
  const valid = given.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(given, "utf8"), Buffer.from(expected, "utf8"));
  if (!valid) return res.status(401).json({ error: "Неверная подпись" });

  try {
    const orderId = String(req.body.order_id || "");
    const status = String(req.body.status || "").toLowerCase();
    const order = await dbGet("SELECT * FROM orders WHERE id=?", [orderId]);
    if (!order) return res.status(404).json({ error: "Заказ не найден" });
    if (order.status === "fulfilled") return res.json({ ok: true, duplicate: true }); // идемпотентность
    if (!["paid", "succeeded", "success"].includes(status)) {
      await dbRun("UPDATE orders SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND status!='fulfilled'",
        [status === "canceled" || status === "cancelled" ? "canceled" : order.status, orderId]);
      return res.json({ ok: true, ignored: status });
    }
    if (Number(req.body.amount) !== Number(order.amount)) {
      console.error(`Webhook: сумма не совпадает order=${orderId} ${req.body.amount} != ${order.amount}`);
      return res.status(400).json({ error: "Сумма оплаты не совпадает с заказом" });
    }
    const plan = plans[order.plan_key];
    if (!plan) return res.status(400).json({ error: "Тариф заказа больше не существует" });

    // Атомарно «забираем» заказ, чтобы два одновременных webhook'а не выдали доступ дважды.
    const claim = await dbRun("UPDATE orders SET status='processing', updated_at=CURRENT_TIMESTAMP WHERE id=? AND status IN ('pending','failed')", [orderId]);
    if (claim.changes === 0) return res.status(409).json({ error: "Заказ уже обрабатывается" });

    try {
      await grantAccess(order.user_id, plan);
      await dbRun("UPDATE orders SET status='fulfilled', error=NULL, updated_at=CURRENT_TIMESTAMP WHERE id=?", [orderId]);
      res.json({ ok: true });
    } catch (e) {
      await dbRun("UPDATE orders SET status='failed', error=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", [String(e.message).slice(0, 500), orderId]);
      console.error(`Webhook: выдача не удалась order=${orderId}:`, e.message);
      // 5xx → платёжная система повторит webhook позже.
      res.status(502).json({ error: "Оплата получена, но ключ пока не выдан; будет повтор" });
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Ошибка обработки webhook" });
  }
});

// Admin area: credentials are supplied only through environment variables.
function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin === true) return next();
  return res.status(401).json({ error: "Требуется вход администратора" });
}
app.get("/api/admin/session", (req, res) => {
  res.json({ authenticated: !!(req.session && req.session.isAdmin === true) });
});
app.post("/api/admin/login", async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || "");
  if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) {
    return res.status(503).json({ error: "Задайте ADMIN_EMAIL и ADMIN_PASSWORD в окружении сервера" });
  }
  if (email !== normalizeEmail(process.env.ADMIN_EMAIL) || password !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: "Неверный email или пароль администратора" });
  }
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Не удалось создать защищённую сессию" });
    req.session.isAdmin = true;
    req.session.save(saveErr => saveErr ? res.status(500).json({ error: "Не удалось сохранить сессию" }) : res.json({ ok: true }));
  });
});
app.post("/api/admin/logout", requireAdmin, (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get("/api/admin/overview", requireAdmin, async (req, res) => {
  try {
    const users = await new Promise((resolve, reject) => db.all(`SELECT u.id,u.name,u.email,u.created_at,
      COALESCE(s.plan,'Free') AS plan,COALESCE(s.status,'Не активна') AS status,
      COALESCE(s.price,0) AS price,s.expires_at,
      CASE WHEN k.id IS NULL THEN 0 ELSE 1 END AS has_key
      FROM users u LEFT JOIN subscriptions s ON s.user_id=u.id LEFT JOIN vpn_keys k ON k.user_id=u.id ORDER BY u.id DESC LIMIT 500`, [], (e,r)=>e?reject(e):resolve(r)));
    const stats = await new Promise((resolve, reject) => db.get(`SELECT
      (SELECT COUNT(*) FROM users) AS users,
      (SELECT COUNT(*) FROM subscriptions WHERE status='Активна') AS activeSubscriptions,
      (SELECT COALESCE(SUM(price),0) FROM subscriptions WHERE status='Активна') AS subscriptionValue`, [], (e,r)=>e?reject(e):resolve(r)));
    res.json({ stats, users });
  } catch(e) { console.error(e); res.status(500).json({error:"Не удалось загрузить данные панели"}); }
});
app.patch("/api/admin/users/:id/subscription", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const status = String(req.body.status || "");
    if (!Number.isInteger(id) || id < 1 || !["Активна","Не активна","Приостановлена"].includes(status))
      return res.status(400).json({error:"Некорректные данные подписки"});
    const exists = await new Promise((resolve,reject)=>db.get("SELECT id FROM users WHERE id=?",[id],(e,r)=>e?reject(e):resolve(r)));
    if (!exists) return res.status(404).json({error:"Пользователь не найден"});
    await new Promise((resolve,reject)=>db.run(`INSERT INTO subscriptions(user_id,plan,status,price,period_months,updated_at)
      VALUES(?, 'Free', ?, 0, 0, CURRENT_TIMESTAMP)
      ON CONFLICT(user_id) DO UPDATE SET status=excluded.status, updated_at=CURRENT_TIMESTAMP`, [id,status], e=>e?reject(e):resolve()));
    res.json({ok:true});
  } catch(e) { console.error(e); res.status(500).json({error:"Не удалось обновить подписку"}); }
});

// Проверка подключения к H1Cloud: токен, список серверов, корректность H1CLOUD_SERVER_ID.
app.get("/api/admin/h1cloud/check", requireAdmin, async (req, res) => {
  try {
    const { serverId, token } = h1Config();
    if (!token) return res.json({ ok: false, message: "H1CLOUD_API_TOKEN не задан" });
    const r = await h1Request("GET", "/api/v1/servers");
    if (!r.ok) return res.json({ ok: false, message: `H1Cloud отклонил запрос (HTTP ${r.status}). Проверьте API-токен.` });
    const raw = Array.isArray(r.payload) ? r.payload : (r.payload.servers || r.payload.data || []);
    const servers = (Array.isArray(raw) ? raw : []).map(s => ({
      id: s.id, name: s.name || s.title || s.hostname || "", xui_enabled: s.xui_enabled === true
    }));
    const selected = servers.find(s => String(s.id) === serverId);
    let message;
    if (!serverId) message = "H1CLOUD_SERVER_ID не задан — выберите ID из списка";
    else if (!/^\d+$/.test(serverId)) message = `H1CLOUD_SERVER_ID="${serverId}" не числовой — выберите ID из списка`;
    else if (!selected) message = `Сервер ${serverId} не найден в аккаунте`;
    else if (!selected.xui_enabled) message = `У сервера ${serverId} не включён xui (xui_enabled=false)`;
    res.json({ ok: !!(selected && selected.xui_enabled), message: message || `Готово: сервер ${serverId} доступен`, serverId, servers,
      demo: process.env.DEMO_PURCHASES_ENABLED === "true",
      payments: !!(process.env.PAYMENT_WEBHOOK_SECRET && process.env.PAYMENT_REDIRECT_URL) });
  } catch (e) { res.json({ ok: false, message: e.message }); }
});

// Ручная выдача/продление ключа администратором (например, после оплаты вне сайта).
app.post("/api/admin/users/:id/grant", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const plan = plans[String(req.body.months)];
    if (!Number.isInteger(id) || id < 1 || !plan) return res.status(400).json({ error: "Некорректный пользователь или тариф" });
    await grantAccess(id, plan);
    res.json({ ok: true });
  } catch (e) {
    console.error(e.message);
    res.status(e.status || 500).json({ error: e.status ? e.message : "Не удалось выдать ключ" });
  }
});

// ───────────────────────── Telegram Login ─────────────────────────
// Настройка: создайте бота в @BotFather, выполните /setdomain и укажите домен сайта.
app.get("/api/config", (req, res) => {
  res.json({ telegramBot: process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_BOT_USERNAME
    ? String(process.env.TELEGRAM_BOT_USERNAME).replace(/^@/, "") : null });
});

function verifyTelegramAuth(data) {
  const botToken = process.env.TELEGRAM_BOT_TOKEN;
  if (!botToken) throw httpError("Вход через Telegram не настроен", 503);
  const { hash, ...fields } = data || {};
  if (typeof hash !== "string" || !/^[a-f0-9]{64}$/i.test(hash)) throw httpError("Некорректные данные Telegram", 400);
  const checkString = Object.keys(fields).filter(k => fields[k] !== undefined && fields[k] !== null)
    .sort().map(k => `${k}=${fields[k]}`).join("\n");
  const secret = crypto.createHash("sha256").update(botToken).digest();
  const expected = crypto.createHmac("sha256", secret).update(checkString).digest("hex");
  if (!crypto.timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(hash.toLowerCase(), "hex")))
    throw httpError("Подпись Telegram не прошла проверку", 401);
  const age = Math.floor(Date.now() / 1000) - Number(fields.auth_date);
  if (!Number.isFinite(age) || age > 86400 || age < -300) throw httpError("Данные входа Telegram устарели, попробуйте ещё раз", 401);
  if (!/^\d+$/.test(String(fields.id))) throw httpError("Некорректный Telegram ID", 400);
  return {
    id: String(fields.id),
    name: [fields.first_name, fields.last_name].filter(Boolean).join(" ").trim() || fields.username || "Пользователь Telegram",
    username: fields.username ? String(fields.username).slice(0, 64) : null,
    photo: typeof fields.photo_url === "string" && fields.photo_url.startsWith("https://") ? fields.photo_url.slice(0, 500) : null
  };
}

app.post("/api/auth/telegram", async (req, res) => {
  try {
    const tg = verifyTelegramAuth(req.body);
    const linked = await dbGet("SELECT id FROM users WHERE telegram_id=?", [tg.id]);

    // Уже вошли по email → привязываем Telegram к текущему аккаунту.
    if (req.session.userId) {
      if (linked && linked.id !== req.session.userId)
        return res.status(409).json({ error: "Этот Telegram уже привязан к другому аккаунту" });
      await dbRun("UPDATE users SET telegram_id=?, telegram_username=?, telegram_photo=? WHERE id=?",
        [tg.id, tg.username, tg.photo, req.session.userId]);
      return res.json(await accountPayload(req.session.userId));
    }

    let userId;
    if (linked) {
      userId = linked.id;
      await dbRun("UPDATE users SET telegram_username=?, telegram_photo=? WHERE id=?", [tg.username, tg.photo, userId]);
    } else {
      const randomPassword = await bcrypt.hash(crypto.randomBytes(32).toString("hex"), 10);
      const r = await dbRun("INSERT INTO users(name,email,password_hash,telegram_id,telegram_username,telegram_photo) VALUES(?,?,?,?,?,?)",
        [tg.name.slice(0, 80), `tg_${tg.id}${TG_EMAIL_DOMAIN}`, randomPassword, tg.id, tg.username, tg.photo]);
      userId = r.lastID;
    }
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: "Не удалось создать сессию" });
      req.session.userId = userId;
      req.session.save(async saveErr => {
        if (saveErr) return res.status(500).json({ error: "Не удалось сохранить сессию" });
        res.json(await accountPayload(userId));
      });
    });
  } catch (e) {
    if (!e.status) console.error(e);
    res.status(e.status || 500).json({ error: e.status ? e.message : "Ошибка входа через Telegram" });
  }
});

app.post("/api/auth/telegram/unlink", requireAuth, async (req, res) => {
  try {
    const u = await dbGet("SELECT email FROM users WHERE id=?", [req.session.userId]);
    if (u && u.email.endsWith(TG_EMAIL_DOMAIN))
      return res.status(400).json({ error: "Аккаунт создан через Telegram — отвязать его нельзя, иначе вы потеряете доступ" });
    await dbRun("UPDATE users SET telegram_id=NULL, telegram_username=NULL, telegram_photo=NULL WHERE id=?", [req.session.userId]);
    res.json(await accountPayload(req.session.userId));
  } catch (e) { console.error(e); res.status(500).json({ error: "Не удалось отвязать Telegram" }); }
});

// ───────────────────── Страница подключения /sub/:token ─────────────────────
// В браузере открывается страница с инструкцией, VPN-приложение (Happ, v2RayTun, Hiddify…)
// по той же ссылке получает подписку. Ссылка персональная, вход не требуется.
async function findBySubToken(token) {
  if (!/^[A-Za-z0-9_-]{16,64}$/.test(String(token))) return null;
  return dbGet(`SELECT k.user_id, k.access_key, k.subscription_url, u.name,
      s.plan, s.status, s.started_at, s.expires_at, s.period_months
    FROM vpn_keys k JOIN users u ON u.id=k.user_id LEFT JOIN subscriptions s ON s.user_id=k.user_id
    WHERE k.sub_token=?`, [token]);
}
function isActiveSub(row) {
  return row && row.status === "Активна" && row.expires_at && new Date(row.expires_at) > new Date();
}
const BRAND = process.env.BRAND_NAME || "BlueShield VPN";

app.get("/api/sub/:token", async (req, res) => {
  try {
    const row = await findBySubToken(req.params.token);
    if (!row) return res.status(404).json({ error: "Ссылка недействительна: возможно, её сбросили в личном кабинете. Войдите в кабинет, чтобы получить новую." });
    res.json({
      brand: BRAND, name: row.name, plan: row.plan || "—", active: !!isActiveSub(row),
      status: row.status || "Не активна", startedAt: row.started_at, expiresAt: row.expires_at,
      accessKey: isActiveSub(row) ? row.access_key : null,
      supportUrl: process.env.SUPPORT_URL || null
    });
  } catch (e) { console.error(e); res.status(500).json({ error: "Не удалось загрузить подписку" }); }
});

app.get("/sub/:token", async (req, res) => {
  const wantsPage = req.query.format !== "raw" && /text\/html/.test(String(req.get("Accept") || ""));
  if (wantsPage) return res.sendFile(path.join(__dirname, "public", "sub.html"));
  try {
    const row = await findBySubToken(req.params.token);
    if (!row) return res.status(404).type("text/plain").send("not found");
    const expire = row.expires_at ? Math.floor(new Date(row.expires_at).getTime() / 1000) : 0;
    res.set({
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
      "profile-title": "base64:" + Buffer.from(BRAND).toString("base64"),
      "profile-update-interval": "12",
      "subscription-userinfo": `upload=0; download=0; total=0; expire=${expire}`
    });
    if (process.env.SUPPORT_URL) res.set("support-url", process.env.SUPPORT_URL);
    if (!isActiveSub(row)) return res.status(403).send("");

    // Сначала пробуем отдать актуальную подписку H1Cloud (там могут быть все локации).
    if (row.subscription_url && /^https:\/\//.test(row.subscription_url)) {
      try {
        const up = await fetch(row.subscription_url, { headers: { "User-Agent": String(req.get("User-Agent") || "BlueShield") }, signal: AbortSignal.timeout(10000) });
        if (up.ok) {
          const body = await up.text();
          if (body.trim()) {
            const ui = up.headers.get("subscription-userinfo");
            if (ui) res.set("subscription-userinfo", ui);
            return res.send(body);
          }
        }
      } catch (e) { console.error("Subscription upstream error:", e.message); }
    }
    // Запасной вариант — стандартная base64-подписка из ключа.
    res.send(Buffer.from(row.access_key + "\n").toString("base64"));
  } catch (e) { console.error(e); res.status(500).type("text/plain").send(""); }
});

// Сброс персональной ссылки (если пользователь случайно ей поделился).
app.post("/api/sub/rotate", requireAuth, async (req, res) => {
  try {
    const r = await dbRun("UPDATE vpn_keys SET sub_token=? WHERE user_id=?", [newSubToken(), req.session.userId]);
    if (!r.changes) return res.status(404).json({ error: "Ключ ещё не выдан" });
    res.json(await accountPayload(req.session.userId));
  } catch (e) { console.error(e); res.status(500).json({ error: "Не удалось сбросить ссылку" }); }
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

ready.then(() => app.listen(PORT, () => console.log(`BlueShield VPN: http://localhost:${PORT}`)));
