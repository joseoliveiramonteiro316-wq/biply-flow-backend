require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.set("trust proxy", 1);
app.use(cors());
app.use(express.json({ limit: "150kb" }));

const PORT = process.env.PORT || 3000;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_PUBLISHABLE_KEY = process.env.SUPABASE_PUBLISHABLE_KEY;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;
const HEARTBEAT_LIMIT = Number(process.env.SITE_HEARTBEAT_SECONDS || 120);
const INFINITEPAY_HANDLE = process.env.INFINITEPAY_HANDLE || "jose-antonio-8lr";
const GRACE_DAYS = Number(process.env.GRACE_DAYS || 3);
const ADMIN_EMAILS = String(process.env.ADMIN_EMAILS || "")
  .split(",")
  .map(v => v.trim().toLowerCase())
  .filter(Boolean);

if (!SUPABASE_URL || !SUPABASE_PUBLISHABLE_KEY || !SUPABASE_SECRET_KEY) {
  console.error("ERRO: variaveis SUPABASE_URL / SUPABASE_PUBLISHABLE_KEY / SUPABASE_SECRET_KEY ausentes.");
}

const supabasePublic = createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }
});

const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SECRET_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }
});

function sha256(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function addDays(date, days) {
  return new Date(date.getTime() + Number(days) * 86400000);
}

function publicBaseUrl(req) {
  const proto = String(req.headers["x-forwarded-proto"] || req.protocol || "https")
    .split(",")[0]
    .trim();
  return `${proto}://${req.get("host")}`;
}

function moneyBR(cents) {
  return Number(cents || 0) / 100;
}

async function getUser(req) {
  const auth = String(req.headers.authorization || "");
  if (!auth.startsWith("Bearer ")) return null;
  const token = auth.substring(7);
  const { data, error } = await supabaseAdmin.auth.getUser(token);
  if (error || !data?.user) return null;
  return data.user;
}

async function requireAdmin(req, res, next) {
  try {
    const user = await getUser(req);
    if (!user) return res.status(401).json({ success: false, error: "not_authenticated" });
    const email = String(user.email || "").toLowerCase();
    if (!ADMIN_EMAILS.length) {
      return res.status(503).json({ success: false, error: "admin_not_configured" });
    }
    if (!ADMIN_EMAILS.includes(email)) {
      return res.status(403).json({ success: false, error: "admin_forbidden" });
    }
    req.adminUser = user;
    next();
  } catch (error) {
    console.error("requireAdmin", error);
    res.status(500).json({ success: false, error: "server_error" });
  }
}

async function getUserByEmail(email) {
  const target = String(email || "").trim().toLowerCase();
  if (!target) return null;
  let page = 1;
  const perPage = 100;
  while (true) {
    const { data, error } = await supabaseAdmin.auth.admin.listUsers({ page, perPage });
    if (error) throw error;
    const users = data?.users || [];
    const found = users.find(u => String(u.email || "").toLowerCase() === target);
    if (found) return found;
    if (users.length < perPage) return null;
    page += 1;
  }
}

async function getLicense(userId) {
  const { data, error } = await supabaseAdmin
    .from("licenses")
    .select("*")
    .eq("user_id", userId)
    .maybeSingle();
  if (error) throw error;
  return data;
}

function checkLicense(license) {
  if (!license) return { authorized: false, phase: "none", reason: "license_not_found" };
  if (license.status !== "active") return { authorized: false, phase: "blocked", reason: "blocked" };
  const now = new Date();
  const paid = license.paid_until ? new Date(license.paid_until) : new Date(0);
  const grace = license.grace_until ? new Date(license.grace_until) : new Date(0);
  if (now <= paid) return { authorized: true, phase: "paid" };
  if (now <= grace) return { authorized: true, phase: "grace" };
  return { authorized: false, phase: "expired", reason: "payment_overdue" };
}

async function getAppSettings() {
  const { data, error } = await supabaseAdmin
    .from("app_settings")
    .select("*")
    .eq("id", 1)
    .maybeSingle();
  if (error) throw error;
  return {
    id: 1,
    monthly_price_cents: Number(data?.monthly_price_cents ?? 2990),
    annual_price_cents: Number(data?.annual_price_cents ?? 29900),
    monthly_days: Number(data?.monthly_days ?? 30),
    annual_days: Number(data?.annual_days ?? 365),
    current_extension_version: String(data?.current_extension_version || "V7").toUpperCase(),
    allowed_extension_versions: Array.isArray(data?.allowed_extension_versions)
      ? data.allowed_extension_versions.map(v => String(v).toUpperCase())
      : ["V7"],
    updated_at: data?.updated_at || null
  };
}

async function getPlans() {
  const s = await getAppSettings();
  return {
    monthly: {
      code: "monthly",
      name: "Biply Flow Mensal",
      days: s.monthly_days,
      price_cents: s.monthly_price_cents
    },
    annual: {
      code: "annual",
      name: "Biply Flow Anual",
      days: s.annual_days,
      price_cents: s.annual_price_cents
    }
  };
}

async function ensureDevice(userId, installId, deviceName) {
  if (!installId) return { ok: false, reason: "device_required" };
  const hash = sha256(installId);
  const { data: devices, error } = await supabaseAdmin
    .from("extension_devices")
    .select("id, device_fingerprint_hash, active")
    .eq("user_id", userId)
    .eq("active", true);
  if (error) throw error;
  if (!devices || devices.length === 0) {
    const { error: insertError } = await supabaseAdmin.from("extension_devices").insert({
      user_id: userId,
      device_name: String(deviceName || "Chrome").slice(0, 120),
      device_fingerprint_hash: hash,
      token_hash: sha256(`${userId}:${installId}`),
      active: true,
      last_seen_at: new Date().toISOString()
    });
    if (insertError) throw insertError;
    return { ok: true, registered: true };
  }
  const match = devices.find(d => d.device_fingerprint_hash === hash);
  if (!match) return { ok: false, reason: "device_limit_reached" };
  await supabaseAdmin.from("extension_devices").update({ last_seen_at: new Date().toISOString() }).eq("id", match.id);
  return { ok: true, registered: false };
}

async function verifyInfinitePayPayment({ order_nsu, transaction_nsu, slug }) {
  const response = await fetch("https://api.checkout.infinitepay.io/payment_check", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ handle: INFINITEPAY_HANDLE, order_nsu, transaction_nsu, slug })
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`InfinitePay payment_check HTTP ${response.status}: ${JSON.stringify(result)}`);
  return result;
}

async function processInfinitePayPayment(order, payload, verified) {
  if (!verified?.paid) throw new Error("Pagamento nao confirmado pela InfinitePay.");
  if (Number(verified.amount) !== Number(order.amount_cents)) throw new Error("Valor confirmado nao corresponde ao pedido.");
  const transactionNsu = String(payload.transaction_nsu || "");
  if (!transactionNsu) throw new Error("transaction_nsu ausente.");

  const { data: existingPayment, error: existingPaymentError } = await supabaseAdmin
    .from("payments").select("id").eq("transaction_nsu", transactionNsu).maybeSingle();
  if (existingPaymentError) throw existingPaymentError;
  if (existingPayment) return { already_processed: true };

  const user = await getUserByEmail(order.customer_email);
  if (!user) throw new Error("Usuario do pedido nao encontrado.");

  const currentLicense = await getLicense(user.id);
  const now = new Date();
  let baseDate = now;
  if (currentLicense?.paid_until && new Date(currentLicense.paid_until) > now) baseDate = new Date(currentLicense.paid_until);

  const newPaidUntil = addDays(baseDate, Number(order.plan_days || 30));
  const newGraceUntil = addDays(newPaidUntil, GRACE_DAYS);

  if (currentLicense) {
    const { error } = await supabaseAdmin.from("licenses").update({
      status: "active",
      plan_name: order.plan_name,
      paid_until: newPaidUntil.toISOString(),
      grace_until: newGraceUntil.toISOString(),
      updated_at: now.toISOString()
    }).eq("user_id", user.id);
    if (error) throw error;
  } else {
    const { error } = await supabaseAdmin.from("licenses").insert({
      user_id: user.id,
      status: "active",
      plan_name: order.plan_name,
      paid_until: newPaidUntil.toISOString(),
      grace_until: newGraceUntil.toISOString()
    });
    if (error) throw error;
  }

  const { error: paymentError } = await supabaseAdmin.from("payments").insert({
    user_id: user.id,
    order_nsu: order.order_nsu,
    transaction_nsu: transactionNsu,
    amount_cents: order.amount_cents,
    capture_method: payload.capture_method || verified.capture_method || null,
    raw_payload: { webhook: payload, payment_check: verified }
  });
  if (paymentError) throw paymentError;

  const { error: orderError } = await supabaseAdmin.from("orders").update({
    status: "paid",
    infinitepay_slug: payload.invoice_slug || payload.slug || null,
    transaction_nsu: transactionNsu,
    capture_method: payload.capture_method || verified.capture_method || null,
    receipt_url: payload.receipt_url || null,
    paid_at: now.toISOString()
  }).eq("id", order.id);
  if (orderError) throw orderError;

  return { already_processed: false, paid_until: newPaidUntil.toISOString(), grace_until: newGraceUntil.toISOString() };
}

async function listUsersForAdmin({ page = 1, perPage = 25, q = "" }) {
  const query = String(q || "").trim().toLowerCase();
  if (!query) {
    const { data, error } = await supabaseAdmin.auth.admin.listUsers({ page, perPage });
    if (error) throw error;
    return { users: data?.users || [], total: Number(data?.total ?? 0), page, perPage };
  }

  const matched = [];
  let scanPage = 1;
  const scanPerPage = 100;
  while (true) {
    const { data, error } = await supabaseAdmin.auth.admin.listUsers({ page: scanPage, perPage: scanPerPage });
    if (error) throw error;
    const users = data?.users || [];
    for (const user of users) {
      const email = String(user.email || "").toLowerCase();
      const id = String(user.id || "").toLowerCase();
      if (email.includes(query) || id.includes(query)) matched.push(user);
    }
    if (users.length < scanPerPage) break;
    scanPage += 1;
  }
  const start = (page - 1) * perPage;
  return { users: matched.slice(start, start + perPage), total: matched.length, page, perPage };
}

async function hydrateAdminUsers(users) {
  const ids = users.map(u => u.id);
  if (!ids.length) return [];

  const [licensesRes, sessionsRes, devicesRes] = await Promise.all([
    supabaseAdmin.from("licenses").select("*").in("user_id", ids),
    supabaseAdmin.from("web_sessions").select("user_id,last_heartbeat_at").in("user_id", ids),
    supabaseAdmin.from("extension_devices").select("user_id,device_name,active,last_seen_at").in("user_id", ids)
  ]);
  if (licensesRes.error) throw licensesRes.error;
  if (sessionsRes.error) throw sessionsRes.error;
  if (devicesRes.error) throw devicesRes.error;

  const licenses = new Map((licensesRes.data || []).map(x => [x.user_id, x]));
  const sessions = new Map((sessionsRes.data || []).map(x => [x.user_id, x]));
  const deviceGroups = new Map();
  for (const d of devicesRes.data || []) {
    if (!deviceGroups.has(d.user_id)) deviceGroups.set(d.user_id, []);
    deviceGroups.get(d.user_id).push(d);
  }

  return users.map(u => {
    const license = licenses.get(u.id) || null;
    const session = sessions.get(u.id) || null;
    const devices = deviceGroups.get(u.id) || [];
    const state = checkLicense(license);
    const heartbeatAge = session?.last_heartbeat_at
      ? Math.floor((Date.now() - new Date(session.last_heartbeat_at).getTime()) / 1000)
      : null;
    const online = heartbeatAge !== null && heartbeatAge <= HEARTBEAT_LIMIT;
    const lastDevice = devices
      .filter(d => d.active)
      .sort((a, b) => new Date(b.last_seen_at || 0) - new Date(a.last_seen_at || 0))[0] || null;
    return {
      id: u.id,
      email: u.email,
      created_at: u.created_at,
      last_sign_in_at: u.last_sign_in_at,
      email_confirmed_at: u.email_confirmed_at,
      license,
      phase: state.phase,
      authorized: state.authorized,
      online,
      heartbeat_age_seconds: heartbeatAge,
      last_extension_seen_at: lastDevice?.last_seen_at || null,
      device_name: lastDevice?.device_name || null
    };
  });
}

app.get("/", async (req, res) => {
  try {
    const s = await getAppSettings();
    res.json({
      system: "Biply Flow",
      status: "online",
      version: s.current_extension_version,
      payments: "InfinitePay",
      plans: {
        monthly: { price: moneyBR(s.monthly_price_cents), days: s.monthly_days },
        annual: { price: moneyBR(s.annual_price_cents), days: s.annual_days }
      }
    });
  } catch (error) {
    console.error(error);
    res.json({ system: "Biply Flow", status: "online", payments: "InfinitePay" });
  }
});

app.get("/health", (req, res) => res.json({ ok: true, service: "biply-flow-backend" }));

app.get("/api/public/settings", async (req, res) => {
  try {
    const s = await getAppSettings();
    res.json({
      success: true,
      monthly_price_cents: s.monthly_price_cents,
      annual_price_cents: s.annual_price_cents,
      monthly_days: s.monthly_days,
      annual_days: s.annual_days,
      current_extension_version: s.current_extension_version,
      allowed_extension_versions: s.allowed_extension_versions
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: "server_error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (!email || !password) return res.status(400).json({ success: false, error: "email_password_required" });
    const { data, error } = await supabasePublic.auth.signInWithPassword({ email, password });
    if (error || !data?.session) return res.status(401).json({ success: false, error: "invalid_credentials" });
    res.json({ success: true, access_token: data.session.access_token, refresh_token: data.session.refresh_token, expires_in: data.session.expires_in });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: "server_error" });
  }
});

app.post("/api/signup", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (!email || !password) return res.status(400).json({ success: false, error: "email_password_required" });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ success: false, error: "invalid_email" });
    if (password.length < 6) return res.status(400).json({ success: false, error: "password_too_short" });

    // Cria a conta pelo backend para que o cliente apareca imediatamente no ADM,
    // sem precisar cadastrar manualmente no painel do Supabase.
    const { data: created, error: createError } = await supabaseAdmin.auth.admin.createUser({
      email,
      password,
      email_confirm: true
    });

    if (createError) {
      const msg = String(createError.message || "").toLowerCase();
      if (msg.includes("already") || msg.includes("registered") || msg.includes("exists")) {
        return res.status(409).json({ success: false, error: "email_already_registered" });
      }
      console.error("signup createUser", createError);
      return res.status(400).json({ success: false, error: "signup_failed", details: createError.message });
    }

    // Faz o primeiro login automaticamente. A conta nasce sem licenca ativa.
    const { data: loginData, error: loginError } = await supabasePublic.auth.signInWithPassword({ email, password });
    if (loginError || !loginData?.session) {
      return res.json({ success: true, created: true, user_id: created?.user?.id || null, login_required: true });
    }

    res.json({
      success: true,
      created: true,
      user_id: created?.user?.id || loginData.user?.id || null,
      access_token: loginData.session.access_token,
      refresh_token: loginData.session.refresh_token,
      expires_in: loginData.session.expires_in
    });
  } catch (error) {
    console.error("signup", error);
    res.status(500).json({ success: false, error: "server_error" });
  }
});

app.post("/api/token/refresh", async (req, res) => {
  try {
    const refresh_token = String(req.body.refresh_token || "");
    if (!refresh_token) return res.status(400).json({ success: false, error: "refresh_token_required" });
    const { data, error } = await supabasePublic.auth.refreshSession({ refresh_token });
    if (error || !data?.session) return res.status(401).json({ success: false, error: "invalid_refresh_token" });
    res.json({ success: true, access_token: data.session.access_token, refresh_token: data.session.refresh_token, expires_in: data.session.expires_in });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: "server_error" });
  }
});

app.get("/api/license", async (req, res) => {
  try {
    const user = await getUser(req);
    if (!user) return res.status(401).json({ authorized: false, reason: "not_authenticated" });
    const license = await getLicense(user.id);
    const state = checkLicense(license);
    res.json({ email: user.email, ...state, paid_until: license?.paid_until, grace_until: license?.grace_until });
  } catch (error) {
    console.error(error);
    res.status(500).json({ authorized: false, reason: "server_error" });
  }
});

app.post("/api/session/heartbeat", async (req, res) => {
  try {
    const user = await getUser(req);
    if (!user) return res.status(401).json({ authorized: false, reason: "not_authenticated" });
    const license = await getLicense(user.id);
    const state = checkLicense(license);
    if (!state.authorized) return res.status(403).json(state);
    const now = new Date().toISOString();
    const { error } = await supabaseAdmin.from("web_sessions").upsert({ user_id: user.id, last_heartbeat_at: now, updated_at: now }, { onConflict: "user_id" });
    if (error) throw error;
    res.json({ authorized: true, phase: state.phase, paid_until: license.paid_until, grace_until: license.grace_until });
  } catch (error) {
    console.error(error);
    res.status(500).json({ authorized: false, reason: "server_error" });
  }
});

app.post("/api/checkout/create", async (req, res) => {
  try {
    const user = await getUser(req);
    if (!user) return res.status(401).json({ success: false, error: "not_authenticated" });
    const plans = await getPlans();
    const requestedPlan = String(req.body.plan || "monthly").trim().toLowerCase();
    const plan = plans[requestedPlan];
    if (!plan) return res.status(400).json({ success: false, error: "invalid_plan" });

    const orderNsu = `BIPLY-${plan.code.toUpperCase()}-${Date.now()}-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;
    const { error: orderInsertError } = await supabaseAdmin.from("orders").insert({
      order_nsu: orderNsu,
      customer_email: user.email,
      amount_cents: plan.price_cents,
      plan_name: plan.name,
      plan_days: plan.days,
      status: "pending"
    });
    if (orderInsertError) throw orderInsertError;

    const baseUrl = publicBaseUrl(req);
    const checkoutPayload = {
      handle: INFINITEPAY_HANDLE,
      redirect_url: `${baseUrl}/pagamento-concluido?pedido=${encodeURIComponent(orderNsu)}`,
      webhook_url: `${baseUrl}/api/webhooks/infinitepay`,
      order_nsu: orderNsu,
      items: [{ quantity: 1, price: plan.price_cents, description: `${plan.name} - ${plan.days} dias` }]
    };

    const response = await fetch("https://api.checkout.infinitepay.io/links", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(checkoutPayload)
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok || !result?.url) {
      console.error("InfinitePay checkout:", result);
      return res.status(502).json({ success: false, error: "infinitepay_checkout_error", details: result });
    }
    res.json({ success: true, checkout_url: result.url, order_nsu: orderNsu, plan: plan.code, plan_name: plan.name, plan_days: plan.days, amount_cents: plan.price_cents });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: "server_error" });
  }
});

app.post("/api/webhooks/infinitepay", async (req, res) => {
  try {
    const payload = req.body || {};
    const orderNsu = String(payload.order_nsu || "");
    const transactionNsu = String(payload.transaction_nsu || "");
    const slug = String(payload.invoice_slug || payload.slug || "");
    if (!orderNsu || !transactionNsu || !slug) return res.status(400).json({ success: false, message: "Dados incompletos" });
    const { data: order, error: orderError } = await supabaseAdmin.from("orders").select("*").eq("order_nsu", orderNsu).maybeSingle();
    if (orderError) throw orderError;
    if (!order) return res.status(400).json({ success: false, message: "Pedido nao encontrado" });
    const verified = await verifyInfinitePayPayment({ order_nsu: orderNsu, transaction_nsu: transactionNsu, slug });
    if (!verified?.paid) return res.status(400).json({ success: false, message: "Pagamento nao confirmado" });
    await processInfinitePayPayment(order, payload, verified);
    return res.status(200).json({ success: true, message: null });
  } catch (error) {
    console.error("Webhook InfinitePay:", error);
    return res.status(400).json({ success: false, message: "Falha ao validar pagamento" });
  }
});

app.post("/api/version/check", async (req, res) => {
  try {
    const s = await getAppSettings();
    const version = String(req.body.version || "").trim().toUpperCase();
    const allowed = s.allowed_extension_versions.includes(version);
    res.json({ allowed, version, current_version: s.current_extension_version, allowed_versions: s.allowed_extension_versions, update_available: version !== s.current_extension_version, reason: allowed ? "ok" : "version_blocked" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ allowed: false, reason: "server_error" });
  }
});

app.post("/api/extension/validate", async (req, res) => {
  try {
    const user = await getUser(req);
    if (!user) return res.status(401).json({ authorized: false, reason: "not_authenticated" });
    const s = await getAppSettings();
    const version = String(req.body.version || "").trim().toUpperCase();
    if (!s.allowed_extension_versions.includes(version)) {
      return res.status(403).json({ authorized: false, reason: "version_blocked", current_version: s.current_extension_version, allowed_versions: s.allowed_extension_versions });
    }
    const license = await getLicense(user.id);
    const state = checkLicense(license);
    if (!state.authorized) return res.status(403).json({ ...state, paid_until: license?.paid_until, grace_until: license?.grace_until, current_version: s.current_extension_version });

    const device = await ensureDevice(user.id, String(req.body.install_id || ""), String(req.body.device_name || ""));
    if (!device.ok) return res.status(403).json({ authorized: false, reason: device.reason, paid_until: license.paid_until, grace_until: license.grace_until });

    const { data: session, error: sessionError } = await supabaseAdmin.from("web_sessions").select("last_heartbeat_at").eq("user_id", user.id).maybeSingle();
    if (sessionError) throw sessionError;
    if (!session) return res.status(403).json({ authorized: false, reason: "site_not_open", paid_until: license.paid_until, grace_until: license.grace_until });
    const ageSeconds = (Date.now() - new Date(session.last_heartbeat_at).getTime()) / 1000;
    if (ageSeconds > HEARTBEAT_LIMIT) return res.status(403).json({ authorized: false, reason: "site_not_open", paid_until: license.paid_until, grace_until: license.grace_until });

    res.json({ authorized: true, phase: state.phase, version, current_version: s.current_extension_version, paid_until: license.paid_until, grace_until: license.grace_until, device_registered: !!device.registered, heartbeat_age_seconds: Math.floor(ageSeconds) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ authorized: false, reason: "server_error" });
  }
});

// ---------------- ADMIN API ----------------
app.get("/api/admin/me", requireAdmin, async (req, res) => {
  res.json({ success: true, email: req.adminUser.email });
});

app.get("/api/admin/dashboard", requireAdmin, async (req, res) => {
  try {
    const page = Math.max(1, Number(req.query.page || 1));
    const perPage = Math.min(100, Math.max(10, Number(req.query.per_page || 25)));
    const q = String(req.query.q || "");

    const base = await listUsersForAdmin({ page, perPage, q });
    const clients = await hydrateAdminUsers(base.users);
    const nowIso = new Date().toISOString();
    const onlineCutoff = new Date(Date.now() - HEARTBEAT_LIMIT * 1000).toISOString();

    const [activeCount, blockedCount, onlineCount] = await Promise.all([
      supabaseAdmin.from("licenses").select("user_id", { count: "exact", head: true }).eq("status", "active").gte("grace_until", nowIso),
      supabaseAdmin.from("licenses").select("user_id", { count: "exact", head: true }).neq("status", "active"),
      supabaseAdmin.from("web_sessions").select("user_id", { count: "exact", head: true }).gte("last_heartbeat_at", onlineCutoff)
    ]);

    res.json({
      success: true,
      stats: {
        clients: base.total,
        active: activeCount.count || 0,
        blocked: blockedCount.count || 0,
        online: onlineCount.count || 0
      },
      page: base.page,
      per_page: base.perPage,
      total: base.total,
      clients
    });
  } catch (error) {
    console.error("admin dashboard", error);
    res.status(500).json({ success: false, error: "server_error", details: error.message });
  }
});

app.get("/api/admin/settings", requireAdmin, async (req, res) => {
  try {
    res.json({ success: true, settings: await getAppSettings() });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: "server_error" });
  }
});

app.put("/api/admin/settings", requireAdmin, async (req, res) => {
  try {
    const monthlyPrice = Math.max(0, Math.round(Number(req.body.monthly_price_cents)));
    const annualPrice = Math.max(0, Math.round(Number(req.body.annual_price_cents)));
    const monthlyDays = Math.max(1, Math.round(Number(req.body.monthly_days)));
    const annualDays = Math.max(1, Math.round(Number(req.body.annual_days)));
    const currentVersion = String(req.body.current_extension_version || "V7").trim().toUpperCase();
    let allowed = Array.isArray(req.body.allowed_extension_versions)
      ? req.body.allowed_extension_versions
      : String(req.body.allowed_extension_versions || "").split(",");
    allowed = [...new Set(allowed.map(v => String(v).trim().toUpperCase()).filter(Boolean))];
    if (!allowed.includes(currentVersion)) allowed.push(currentVersion);

    if (![monthlyPrice, annualPrice, monthlyDays, annualDays].every(Number.isFinite)) {
      return res.status(400).json({ success: false, error: "invalid_settings" });
    }

    const payload = {
      monthly_price_cents: monthlyPrice,
      annual_price_cents: annualPrice,
      monthly_days: monthlyDays,
      annual_days: annualDays,
      current_extension_version: currentVersion,
      allowed_extension_versions: allowed,
      updated_at: new Date().toISOString()
    };
    const { data, error } = await supabaseAdmin.from("app_settings").update(payload).eq("id", 1).select("*").single();
    if (error) throw error;
    res.json({ success: true, settings: data });
  } catch (error) {
    console.error("admin settings", error);
    res.status(500).json({ success: false, error: "server_error", details: error.message });
  }
});

app.post("/api/admin/users/:id/block", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id);
    const license = await getLicense(id);
    if (!license) return res.status(404).json({ success: false, error: "license_not_found" });
    const { error } = await supabaseAdmin.from("licenses").update({ status: "blocked", updated_at: new Date().toISOString() }).eq("user_id", id);
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: "server_error" });
  }
});

app.post("/api/admin/users/:id/activate", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id);
    const userResult = await supabaseAdmin.auth.admin.getUserById(id);
    const user = userResult.data?.user;
    if (!user) return res.status(404).json({ success: false, error: "user_not_found" });
    const license = await getLicense(id);
    const now = new Date();
    if (license) {
      const update = { status: "active", updated_at: now.toISOString() };
      if (!license.paid_until) {
        update.paid_until = addDays(now, 30).toISOString();
        update.grace_until = addDays(addDays(now, 30), GRACE_DAYS).toISOString();
      }
      const { error } = await supabaseAdmin.from("licenses").update(update).eq("user_id", id);
      if (error) throw error;
    } else {
      const { error } = await supabaseAdmin.from("licenses").insert({
        user_id: id,
        status: "active",
        plan_name: "Ativacao Admin",
        paid_until: addDays(now, 30).toISOString(),
        grace_until: addDays(addDays(now, 30), GRACE_DAYS).toISOString()
      });
      if (error) throw error;
    }
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: "server_error", details: error.message });
  }
});

app.post("/api/admin/users/:id/renew", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id);
    const plans = await getPlans();
    const planCode = String(req.body.plan || "monthly").toLowerCase();
    const plan = plans[planCode];
    if (!plan) return res.status(400).json({ success: false, error: "invalid_plan" });

    const license = await getLicense(id);
    const now = new Date();
    let base = now;
    if (license?.paid_until && new Date(license.paid_until) > now) base = new Date(license.paid_until);
    const paidUntil = addDays(base, plan.days);
    const graceUntil = addDays(paidUntil, GRACE_DAYS);
    const payload = { status: "active", plan_name: plan.name, paid_until: paidUntil.toISOString(), grace_until: graceUntil.toISOString(), updated_at: now.toISOString() };

    if (license) {
      const { error } = await supabaseAdmin.from("licenses").update(payload).eq("user_id", id);
      if (error) throw error;
    } else {
      const { error } = await supabaseAdmin.from("licenses").insert({ user_id: id, ...payload });
      if (error) throw error;
    }
    res.json({ success: true, paid_until: paidUntil.toISOString(), grace_until: graceUntil.toISOString() });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: "server_error" });
  }
});

app.put("/api/admin/users/:id/dates", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id);
    const paid = new Date(String(req.body.paid_until || ""));
    if (Number.isNaN(paid.getTime())) return res.status(400).json({ success: false, error: "invalid_paid_until" });
    const grace = req.body.grace_until ? new Date(String(req.body.grace_until)) : addDays(paid, GRACE_DAYS);
    if (Number.isNaN(grace.getTime())) return res.status(400).json({ success: false, error: "invalid_grace_until" });
    const license = await getLicense(id);
    const payload = { status: "active", paid_until: paid.toISOString(), grace_until: grace.toISOString(), updated_at: new Date().toISOString() };
    if (license) {
      const { error } = await supabaseAdmin.from("licenses").update(payload).eq("user_id", id);
      if (error) throw error;
    } else {
      const { error } = await supabaseAdmin.from("licenses").insert({ user_id: id, plan_name: "Ajuste Admin", ...payload });
      if (error) throw error;
    }
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: "server_error" });
  }
});

app.post("/api/admin/users/:id/reset-device", requireAdmin, async (req, res) => {
  try {
    const { error } = await supabaseAdmin.from("extension_devices").update({ active: false }).eq("user_id", String(req.params.id)).eq("active", true);
    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: "server_error" });
  }
});

app.post("/api/admin/users/:id/delete", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id);
    if (id === req.adminUser.id) return res.status(400).json({ success: false, error: "cannot_delete_self" });
    const userRes = await supabaseAdmin.auth.admin.getUserById(id);
    const user = userRes.data?.user;
    if (!user) return res.status(404).json({ success: false, error: "user_not_found" });

    // Limpa dados operacionais ligados ao cliente. Historico de pedidos pode permanecer por email.
    for (const table of ["web_sessions", "extension_devices", "licenses", "payments"]) {
      const { error } = await supabaseAdmin.from(table).delete().eq("user_id", id);
      if (error) throw error;
    }
    const { error: authError } = await supabaseAdmin.auth.admin.deleteUser(id);
    if (authError) throw authError;
    res.json({ success: true });
  } catch (error) {
    console.error("delete user", error);
    res.status(500).json({ success: false, error: "delete_failed", details: error.message });
  }
});

app.get("/cadastro", (req, res) => {
  res.redirect(302, "/cliente?modo=cadastro");
});

app.get("/cliente", (req, res) => {
  res.set("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Biply Flow - Area do Cliente</title>
<style>*{box-sizing:border-box}body{margin:0;font-family:Arial,sans-serif;background:#07111f;color:#fff}.wrap{width:min(560px,92%);margin:45px auto}.card{background:#10243b;border:1px solid #24425f;border-radius:18px;padding:22px}h1{margin:0 0 7px}p{color:#aec0d3;line-height:1.45}.passwordWrap{position:relative}input,button{width:100%;padding:13px;border-radius:10px;margin:7px 0;font-size:16px}input{background:#081725;color:white;border:1px solid #31536f}.passwordWrap input{padding-right:52px}.eye{position:absolute;right:8px;top:12px;width:42px;height:42px;margin:0;background:transparent;color:#d7e4f2;font-size:20px}button{border:0;background:#35e59a;color:#04101a;font-weight:800;cursor:pointer}.secondary{background:#173653;color:white}.status{margin-top:15px;padding:13px;border-radius:10px;background:#081725;white-space:pre-wrap}.ok{color:#8dffca}.bad{color:#ff9aa5}.warn{color:#ffe18b}.hidden{display:none}.plans{display:grid;grid-template-columns:1fr;gap:12px;margin-top:16px}.plan{background:#081725;border:1px solid #31536f;border-radius:14px;padding:15px}.plan h3{margin:0 0 6px}.price{font-size:24px;font-weight:900;margin:6px 0}.save{color:#8dffca;font-size:13px}.pay{background:#27d3ff}.textLink{display:inline;width:auto;padding:0;margin:0;background:transparent;color:#8dffca;text-decoration:underline;border:0;font-size:13px;cursor:pointer;touch-action:manipulation}button{touch-action:manipulation}</style>
</head><body><div class="wrap"><div class="card"><h1>Biply Flow</h1><p>Entre e mantenha esta pagina aberta enquanto estiver usando a extensao.</p>
<div id="loginBox"><div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px"><button id="modeLogin" type="button">Entrar</button><button id="modeSignup" type="button" class="secondary">Criar conta</button></div><input id="email" type="email" placeholder="E-mail" autocomplete="email"><div class="passwordWrap"><input id="password" type="password" placeholder="Senha" autocomplete="current-password"><button id="eye" class="eye" type="button">&#128065;</button></div><div id="confirmWrap" class="passwordWrap hidden"><input id="confirmPassword" type="password" placeholder="Confirme a senha" autocomplete="new-password"></div><button id="login">Entrar</button><p id="accountHelp" style="font-size:13px;margin:5px 0 0">Ainda nao tem conta? <button id="accountModeLink" type="button" class="textLink">Criar conta</button></p></div>
<div id="onlineBox" class="hidden"><p id="account"></p><div class="plans"><div class="plan"><h3>Plano Mensal</h3><div id="monthlyPrice" class="price">Carregando...</div><div id="monthlyDays"></div><button id="payMonthly" class="pay">PAGAR MENSAL</button></div><div class="plan"><h3>Plano Anual</h3><div id="annualPrice" class="price">Carregando...</div><div id="annualDays"></div><button id="payAnnual" class="pay">PAGAR ANUAL</button></div></div><button id="logout" class="secondary">Sair</button></div><div id="status" class="status">Aguardando login...</div></div></div>
<script>
let accessToken=null,refreshToken=null,timer=null;const statusEl=document.getElementById("status"),loginBox=document.getElementById("loginBox"),onlineBox=document.getElementById("onlineBox"),account=document.getElementById("account");function setStatus(text,cls=""){statusEl.className="status "+cls;statusEl.textContent=text}function brl(c){return new Intl.NumberFormat("pt-BR",{style:"currency",currency:"BRL"}).format(Number(c||0)/100)}async function loadSettings(){try{const r=await fetch("/api/public/settings");const j=await r.json();if(j.success){monthlyPrice.textContent=brl(j.monthly_price_cents);annualPrice.textContent=brl(j.annual_price_cents);monthlyDays.textContent=j.monthly_days+" dias de acesso";annualDays.textContent=j.annual_days+" dias de acesso"}}catch(e){}}
loadSettings();let authMode=new URLSearchParams(location.search).get("modo")==="cadastro"?"signup":"login";const modeLogin=document.getElementById("modeLogin"),modeSignup=document.getElementById("modeSignup"),confirmWrap=document.getElementById("confirmWrap"),loginBtn=document.getElementById("login"),accountHelp=document.getElementById("accountHelp");function renderAccountHelp(signup){accountHelp.innerHTML=signup?'Ja possui conta? <button id="accountModeLink" type="button" class="textLink">Entrar</button>':'Ainda nao tem conta? <button id="accountModeLink" type="button" class="textLink">Criar conta</button>';const link=document.getElementById("accountModeLink");if(link)link.onclick=()=>setAuthMode(signup?"login":"signup")}function setAuthMode(mode){authMode=mode;const signup=mode==="signup";confirmWrap.classList.toggle("hidden",!signup);loginBtn.textContent=signup?"Criar minha conta":"Entrar";modeLogin.className=signup?"secondary":"";modeSignup.className=signup?"":"secondary";renderAccountHelp(signup);setStatus(signup?"Crie sua conta. O acesso sera liberado apos pagamento ou ativacao pelo administrador.":"Aguardando login...")}modeLogin.onclick=()=>setAuthMode("login");modeSignup.onclick=()=>setAuthMode("signup");setAuthMode(authMode);document.getElementById("eye").onclick=()=>{const p=document.getElementById("password");p.type=p.type==="password"?"text":"password"};async function refresh(){if(!refreshToken)return false;const r=await fetch("/api/token/refresh",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({refresh_token:refreshToken})});const j=await r.json().catch(()=>({}));if(!r.ok||!j.access_token)return false;accessToken=j.access_token;refreshToken=j.refresh_token||refreshToken;return true}async function heartbeat(retry=true){if(!accessToken)return;let r=await fetch("/api/session/heartbeat",{method:"POST",headers:{Authorization:"Bearer "+accessToken}});if(r.status===401&&retry&&await refresh())return heartbeat(false);const j=await r.json().catch(()=>({}));if(!r.ok||!j.authorized){setStatus("Acesso nao autorizado: "+(j.reason||"erro"),"bad");return}const phase=j.phase==="grace"?"TOLERANCIA":"ATIVO";setStatus("SITE CONECTADO - "+phase+"\\nPago ate: "+new Date(j.paid_until).toLocaleString("pt-BR")+"\\nTolerancia ate: "+new Date(j.grace_until).toLocaleString("pt-BR")+"\\n\\nMantenha esta pagina aberta.",j.phase==="grace"?"warn":"ok")}
document.getElementById("login").onclick=async()=>{const email=document.getElementById("email").value.trim(),password=document.getElementById("password").value;if(authMode==="signup"){const confirmPassword=document.getElementById("confirmPassword").value;if(!email||!password){setStatus("Preencha e-mail e senha.","bad");return}if(password.length<6){setStatus("A senha precisa ter pelo menos 6 caracteres.","bad");return}if(password!==confirmPassword){setStatus("As senhas nao conferem.","bad");return}setStatus("Criando sua conta...");const r=await fetch("/api/signup",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email,password})});const j=await r.json().catch(()=>({}));if(!r.ok){if(j.error==="email_already_registered")setStatus("Este e-mail ja possui cadastro. Clique em Entrar.","bad");else if(j.error==="invalid_email")setStatus("Digite um e-mail valido.","bad");else setStatus("Nao foi possivel criar a conta: "+(j.details||j.error||"erro"),"bad");return}if(j.access_token){accessToken=j.access_token;refreshToken=j.refresh_token||null;document.getElementById("password").value="";document.getElementById("confirmPassword").value="";loginBox.classList.add("hidden");onlineBox.classList.remove("hidden");account.textContent=email;setStatus("Conta criada com sucesso. Seu cadastro ja esta disponivel para o administrador.\\n\\nSem licenca ativa: escolha um plano ou aguarde a liberacao do seu periodo de teste.","ok");await heartbeat();timer=setInterval(heartbeat,30000);return}setStatus("Conta criada com sucesso. Clique em Entrar para acessar.","ok");setAuthMode("login");return}setStatus("Entrando...");const r=await fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email,password})});const j=await r.json().catch(()=>({}));if(!r.ok||!j.access_token){setStatus("E-mail ou senha invalidos.","bad");return}accessToken=j.access_token;refreshToken=j.refresh_token||null;document.getElementById("password").value="";loginBox.classList.add("hidden");onlineBox.classList.remove("hidden");account.textContent=email;await heartbeat();timer=setInterval(heartbeat,30000)};async function createCheckout(plan){if(!accessToken){setStatus("Faca login primeiro.","bad");return}setStatus("Criando pagamento InfinitePay...");let r=await fetch("/api/checkout/create",{method:"POST",headers:{Authorization:"Bearer "+accessToken,"Content-Type":"application/json"},body:JSON.stringify({plan})});if(r.status===401&&await refresh())r=await fetch("/api/checkout/create",{method:"POST",headers:{Authorization:"Bearer "+accessToken,"Content-Type":"application/json"},body:JSON.stringify({plan})});const j=await r.json().catch(()=>({}));if(!r.ok||!j.checkout_url){setStatus("Nao foi possivel abrir o pagamento.","bad");return}location.href=j.checkout_url}document.getElementById("payMonthly").onclick=()=>createCheckout("monthly");document.getElementById("payAnnual").onclick=()=>createCheckout("annual");document.getElementById("logout").onclick=()=>{accessToken=null;refreshToken=null;if(timer)clearInterval(timer);timer=null;onlineBox.classList.add("hidden");loginBox.classList.remove("hidden");setStatus("Sessao encerrada.")};
</script></body></html>`);
});

app.get("/admin", (req, res) => {
  res.set("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Biply Flow - Admin</title>
<style>*{box-sizing:border-box}body{margin:0;font-family:Arial,sans-serif;background:#06111e;color:#eef7ff}button,input,select{font:inherit}.wrap{width:min(1180px,95%);margin:28px auto}.top{display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap}.card{background:#0d2135;border:1px solid #24435d;border-radius:16px;padding:16px;margin-top:14px}.login{max-width:440px;margin:60px auto}.hidden{display:none!important}input,select{background:#081725;color:white;border:1px solid #31536f;border-radius:9px;padding:11px;min-height:44px}button{border:0;border-radius:9px;padding:11px 14px;min-height:44px;background:#35e59a;color:#04101a;font-weight:800;cursor:pointer}.secondary{background:#173653;color:white}.danger{background:#ef5a67;color:white}.warn{background:#ffd36a;color:#2a2100}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.stat{background:#081725;border:1px solid #24435d;border-radius:12px;padding:14px}.stat b{display:block;font-size:27px;margin-top:5px}.toolbar{display:flex;gap:8px;flex-wrap:wrap}.toolbar input{flex:1;min-width:190px}.settings{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}.field label{display:block;color:#a9bfd1;font-size:13px;margin-bottom:5px}.field input{width:100%}.tableWrap{overflow:auto;border-radius:12px}.clients{width:100%;border-collapse:collapse;min-width:980px}.clients th,.clients td{text-align:left;border-bottom:1px solid #20394e;padding:10px;vertical-align:top}.clients th{color:#9fb6c9;font-size:12px;text-transform:uppercase}.badge{display:inline-block;padding:5px 8px;border-radius:999px;font-size:12px;font-weight:800}.b-active{background:#123c30;color:#8dffca}.b-grace{background:#4b3d13;color:#ffe18b}.b-blocked,.b-expired{background:#4b1f25;color:#ff9aa5}.b-none{background:#263645;color:#c5d3df}.online{color:#8dffca;font-weight:800}.offline{color:#8ea4b6}.actions{display:flex;gap:5px;flex-wrap:wrap}.actions button{padding:7px 9px;min-height:34px;font-size:12px}.muted{color:#9fb6c9}.msg{white-space:pre-wrap;margin-top:10px}.ok{color:#8dffca}.bad{color:#ff9aa5}@media(max-width:760px){.grid{grid-template-columns:repeat(2,1fr)}.settings{grid-template-columns:1fr}.wrap{width:96%}}</style>
</head><body><div class="wrap">
<div id="loginView" class="card login"><h1>Biply Flow Admin</h1><p class="muted">Entre com a conta definida como administradora no Render.</p><input id="aEmail" type="email" placeholder="E-mail" style="width:100%;margin:6px 0"><input id="aPass" type="password" placeholder="Senha" style="width:100%;margin:6px 0"><button id="aLogin" style="width:100%;margin-top:6px">Entrar no painel</button><div id="loginMsg" class="msg"></div></div>
<div id="panel" class="hidden"><div class="top"><div><h1 style="margin:0">Biply Flow Admin</h1><div id="adminEmail" class="muted"></div></div><button id="logout" class="secondary">Sair</button></div>
<div class="grid"><div class="stat">Clientes<b id="sClients">0</b></div><div class="stat">Ativos<b id="sActive">0</b></div><div class="stat">Bloqueados<b id="sBlocked">0</b></div><div class="stat">Online<b id="sOnline">0</b></div></div>
<div class="card"><h2>Precos, planos e versoes</h2><div class="settings"><div class="field"><label>Mensal (R$)</label><input id="mPrice" type="number" min="0" step="0.01"></div><div class="field"><label>Dias mensal</label><input id="mDays" type="number" min="1"></div><div class="field"><label>Anual (R$)</label><input id="aPrice" type="number" min="0" step="0.01"></div><div class="field"><label>Dias anual</label><input id="aDays" type="number" min="1"></div><div class="field"><label>Versao atual</label><input id="curVersion"></div><div class="field"><label>Versoes permitidas (separadas por virgula)</label><input id="allowedVersions"></div></div><button id="saveSettings" style="margin-top:10px">Salvar configuracoes</button><div id="settingsMsg" class="msg"></div></div>
<div class="card"><div class="toolbar"><input id="search" placeholder="Buscar por e-mail ou ID"><button id="searchBtn">Buscar</button><button id="clearBtn" class="secondary">Limpar</button></div><div class="tableWrap" style="margin-top:10px"><table class="clients"><thead><tr><th>Cliente</th><th>Status</th><th>Plano / vencimento</th><th>Conexao</th><th>Acoes</th></tr></thead><tbody id="rows"></tbody></table></div><div class="toolbar" style="justify-content:space-between;margin-top:10px"><button id="prev" class="secondary">Anterior</button><div id="pageInfo" class="muted"></div><button id="next" class="secondary">Proxima</button></div><div id="dashMsg" class="msg"></div></div>
</div></div>
<script>
let token=null,refreshToken=null,page=1,total=0,perPage=25,q="";const $=id=>document.getElementById(id);function esc(s){return String(s??"").replace(/[&<>\"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]))}function fmtDate(v){if(!v)return"-";const d=new Date(v);return Number.isNaN(d.getTime())?"-":d.toLocaleString("pt-BR")}function setMsg(id,text,bad=false){$(id).className="msg "+(bad?"bad":"ok");$(id).textContent=text}async function api(path,opt={}){opt.headers={...(opt.headers||{}),Authorization:"Bearer "+token};if(opt.body&&!opt.headers["Content-Type"])opt.headers["Content-Type"]="application/json";let r=await fetch(path,opt);if(r.status===401&&refreshToken){const rr=await fetch("/api/token/refresh",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({refresh_token:refreshToken})});const jj=await rr.json().catch(()=>({}));if(rr.ok&&jj.access_token){token=jj.access_token;refreshToken=jj.refresh_token||refreshToken;opt.headers.Authorization="Bearer "+token;r=await fetch(path,opt)}}const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error||j.details||"erro");return j}
$("aLogin").onclick=async()=>{try{setMsg("loginMsg","Entrando...");const r=await fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:$("aEmail").value.trim(),password:$("aPass").value})});const j=await r.json();if(!r.ok||!j.access_token)throw new Error("E-mail ou senha invalidos");token=j.access_token;refreshToken=j.refresh_token||null;const me=await api("/api/admin/me");$("adminEmail").textContent=me.email;$("loginView").classList.add("hidden");$("panel").classList.remove("hidden");await loadSettings();await loadDash()}catch(e){setMsg("loginMsg",e.message,true)}};
$("logout").onclick=()=>{token=null;refreshToken=null;$("panel").classList.add("hidden");$("loginView").classList.remove("hidden")};
async function loadSettings(){try{const j=await api("/api/admin/settings");const s=j.settings;$("mPrice").value=(s.monthly_price_cents/100).toFixed(2);$("aPrice").value=(s.annual_price_cents/100).toFixed(2);$("mDays").value=s.monthly_days;$("aDays").value=s.annual_days;$("curVersion").value=s.current_extension_version;$("allowedVersions").value=s.allowed_extension_versions.join(", ")}catch(e){setMsg("settingsMsg",e.message,true)}}
$("saveSettings").onclick=async()=>{try{const body={monthly_price_cents:Math.round(Number($("mPrice").value)*100),annual_price_cents:Math.round(Number($("aPrice").value)*100),monthly_days:Number($("mDays").value),annual_days:Number($("aDays").value),current_extension_version:$("curVersion").value,allowed_extension_versions:$("allowedVersions").value.split(",")};await api("/api/admin/settings",{method:"PUT",body:JSON.stringify(body)});setMsg("settingsMsg","Configuracoes salvas.");await loadSettings()}catch(e){setMsg("settingsMsg",e.message,true)}};
function phaseLabel(p){return p==="paid"?"ATIVO":p==="grace"?"TOLERANCIA":p==="blocked"?"BLOQUEADO":p==="expired"?"VENCIDO":"SEM LICENCA"}function phaseClass(p){return "b-"+(p||"none")}
async function loadDash(){try{$("dashMsg").textContent="Carregando...";const j=await api("/api/admin/dashboard?page="+page+"&per_page="+perPage+"&q="+encodeURIComponent(q));total=j.total||0;$("sClients").textContent=j.stats.clients;$("sActive").textContent=j.stats.active;$("sBlocked").textContent=j.stats.blocked;$("sOnline").textContent=j.stats.online;const rows=j.clients.map(c=>{const l=c.license||{};return '<tr><td><b>'+esc(c.email||"sem e-mail")+'</b><br><span class="muted">'+esc(c.id)+'</span></td><td><span class="badge '+phaseClass(c.phase)+'">'+phaseLabel(c.phase)+'</span></td><td>'+esc(l.plan_name||"-")+'<br><span class="muted">Pago ate: '+fmtDate(l.paid_until)+'<br>Tolerancia: '+fmtDate(l.grace_until)+'</span></td><td><span class="'+(c.online?"online":"offline")+'">'+(c.online?"ONLINE":"OFFLINE")+'</span><br><span class="muted">Extensao: '+fmtDate(c.last_extension_seen_at)+(c.device_name?" · "+esc(c.device_name):"")+'</span></td><td><div class="actions"><button data-act="activate" data-id="'+c.id+'">Ativar</button><button class="warn" data-act="renewM" data-id="'+c.id+'">+ Mensal</button><button class="warn" data-act="renewA" data-id="'+c.id+'">+ Anual</button><button class="secondary" data-act="dates" data-id="'+c.id+'" data-paid="'+esc(l.paid_until||"")+'">Data</button><button class="secondary" data-act="device" data-id="'+c.id+'">Liberar aparelho</button><button class="danger" data-act="block" data-id="'+c.id+'">Bloquear</button><button class="danger" data-act="delete" data-id="'+c.id+'" data-email="'+esc(c.email||"")+'">Excluir</button></div></td></tr>'}).join("");$("rows").innerHTML=rows||'<tr><td colspan="5">Nenhum cliente encontrado.</td></tr>';const pages=Math.max(1,Math.ceil(total/perPage));$("pageInfo").textContent="Pagina "+page+" de "+pages+" · "+total+" cliente(s)";$("prev").disabled=page<=1;$("next").disabled=page>=pages;$("dashMsg").textContent=""}catch(e){setMsg("dashMsg",e.message,true)}}
$("searchBtn").onclick=()=>{q=$("search").value.trim();page=1;loadDash()};$("clearBtn").onclick=()=>{$("search").value="";q="";page=1;loadDash()};$("prev").onclick=()=>{if(page>1){page--;loadDash()}};$("next").onclick=()=>{if(page<Math.ceil(total/perPage)){page++;loadDash()}};
$("rows").addEventListener("click",async e=>{const b=e.target.closest("button[data-act]");if(!b)return;const id=b.dataset.id,act=b.dataset.act;try{if(act==="activate")await api("/api/admin/users/"+id+"/activate",{method:"POST"});if(act==="block"&&confirm("Bloquear este cliente agora?"))await api("/api/admin/users/"+id+"/block",{method:"POST"});if(act==="renewM"&&confirm("Adicionar um plano mensal a este cliente?"))await api("/api/admin/users/"+id+"/renew",{method:"POST",body:JSON.stringify({plan:"monthly"})});if(act==="renewA"&&confirm("Adicionar um plano anual a este cliente?"))await api("/api/admin/users/"+id+"/renew",{method:"POST",body:JSON.stringify({plan:"annual"})});if(act==="device"&&confirm("Liberar o aparelho atual para permitir novo dispositivo?"))await api("/api/admin/users/"+id+"/reset-device",{method:"POST"});if(act==="dates"){const current=b.dataset.paid?new Date(b.dataset.paid).toISOString().slice(0,10):"";const v=prompt("Nova data de vencimento (AAAA-MM-DD):",current);if(v){const d=new Date(v+"T23:59:59-03:00");await api("/api/admin/users/"+id+"/dates",{method:"PUT",body:JSON.stringify({paid_until:d.toISOString()})})}}if(act==="delete"){const email=b.dataset.email||id;if(confirm("EXCLUSAO DEFINITIVA de "+email+". Continuar?")&&confirm("Tem certeza? Esta acao nao pode ser desfeita."))await api("/api/admin/users/"+id+"/delete",{method:"POST"})}await loadDash()}catch(err){setMsg("dashMsg",err.message,true)}});
</script></body></html>`);
});

app.get("/pagamento-concluido", (req, res) => {
  res.set("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Biply Flow - Pagamento</title><style>body{margin:0;font-family:Arial,sans-serif;background:#07111f;color:white}.card{width:min(520px,92%);margin:60px auto;background:#10243b;border:1px solid #24425f;border-radius:18px;padding:24px}a{display:block;text-align:center;padding:13px;border-radius:10px;background:#35e59a;color:#04101a;font-weight:bold;text-decoration:none;margin-top:18px}</style></head><body><div class="card"><h2>Biply Flow</h2><p>Pagamento enviado. Aguarde alguns segundos para a confirmacao automatica.</p><a href="/cliente">Voltar para minha conta</a></div></body></html>`);
});

app.listen(PORT, () => {
  console.log(`Biply Flow online na porta ${PORT}`);
  console.log(`InfinitePay configurada: ${INFINITEPAY_HANDLE}`);
  console.log(`Painel admin: ${ADMIN_EMAILS.length ? "configurado" : "PENDENTE - defina ADMIN_EMAILS no Render"}`);
});
