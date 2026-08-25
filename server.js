require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.use(cors());
app.use(express.json({ limit: "100kb" }));

const PORT = process.env.PORT || 3000;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_PUBLISHABLE_KEY = process.env.SUPABASE_PUBLISHABLE_KEY;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;

const CURRENT_VERSION = process.env.CURRENT_VERSION || "V7";
const MIN_VERSION = process.env.MIN_VERSION || "V7";
const ALLOWED_VERSIONS = (process.env.ALLOWED_VERSIONS || "V7")
  .split(",")
  .map(v => v.trim().toUpperCase())
  .filter(Boolean);

const HEARTBEAT_LIMIT = Number(process.env.SITE_HEARTBEAT_SECONDS || 120);

// InfinitePay - configuracao inicial. Depois o preco ira para o Painel Admin.
const INFINITEPAY_HANDLE = "jose-antonio-8lr";
const PLAN_PRICE_CENTS = 2990; // R$ 29,90
const PLAN_DAYS = 30;
const GRACE_DAYS = 3;
const PLAN_NAME = "Biply Flow Mensal";

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
    .split(",")[0].trim();
  return `${proto}://${req.get("host")}`;
}

async function getUserByEmail(email) {
  let page = 1;
  while (page <= 20) {
    const { data, error } = await supabaseAdmin.auth.admin.listUsers({ page, perPage: 100 });
    if (error) throw error;
    const found = (data.users || []).find(
      u => String(u.email || "").toLowerCase() === String(email || "").toLowerCase()
    );
    if (found) return found;
    if ((data.users || []).length < 100) break;
    page++;
  }
  return null;
}

async function verifyInfinitePayPayment({ order_nsu, transaction_nsu, slug }) {
  const response = await fetch("https://api.checkout.infinitepay.io/payment_check", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      handle: INFINITEPAY_HANDLE,
      order_nsu,
      transaction_nsu,
      slug
    })
  });

  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(`InfinitePay payment_check HTTP ${response.status}`);
  }
  return result;
}

async function processInfinitePayPayment(order, payload, verified) {
  if (!verified?.paid) throw new Error("Pagamento nao confirmado.");
  if (Number(verified.amount) !== Number(order.amount_cents)) {
    throw new Error("Valor do pagamento diverge do pedido.");
  }

  const transactionNsu = String(payload.transaction_nsu || "");
  if (!transactionNsu) throw new Error("transaction_nsu ausente.");

  const { data: existing, error: existingError } = await supabaseAdmin
    .from("payments")
    .select("id")
    .eq("transaction_nsu", transactionNsu)
    .maybeSingle();
  if (existingError) throw existingError;
  if (existing) return { already_processed: true };

  const user = await getUserByEmail(order.customer_email);
  if (!user) throw new Error("Usuario do pedido nao encontrado.");

  const currentLicense = await getLicense(user.id);
  const now = new Date();
  let base = now;
  if (currentLicense?.paid_until && new Date(currentLicense.paid_until) > now) {
    base = new Date(currentLicense.paid_until);
  }

  const paidUntil = addDays(base, Number(order.plan_days || PLAN_DAYS));
  const graceUntil = addDays(paidUntil, GRACE_DAYS);

  if (currentLicense) {
    const { error } = await supabaseAdmin
      .from("licenses")
      .update({
        status: "active",
        plan_name: order.plan_name || PLAN_NAME,
        paid_until: paidUntil.toISOString(),
        grace_until: graceUntil.toISOString(),
        updated_at: now.toISOString()
      })
      .eq("user_id", user.id);
    if (error) throw error;
  } else {
    const { error } = await supabaseAdmin.from("licenses").insert({
      user_id: user.id,
      status: "active",
      plan_name: order.plan_name || PLAN_NAME,
      paid_until: paidUntil.toISOString(),
      grace_until: graceUntil.toISOString()
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

  const { error: orderError } = await supabaseAdmin
    .from("orders")
    .update({
      status: "paid",
      infinitepay_slug: payload.invoice_slug || payload.slug || null,
      transaction_nsu: transactionNsu,
      capture_method: payload.capture_method || verified.capture_method || null,
      receipt_url: payload.receipt_url || null,
      paid_at: now.toISOString()
    })
    .eq("id", order.id);
  if (orderError) throw orderError;

  return {
    already_processed: false,
    paid_until: paidUntil.toISOString(),
    grace_until: graceUntil.toISOString()
  };
}

async function getUser(req) {
  const auth = String(req.headers.authorization || "");
  if (!auth.startsWith("Bearer ")) return null;

  const token = auth.substring(7);
  const { data, error } = await supabaseAdmin.auth.getUser(token);
  if (error || !data?.user) return null;
  return data.user;
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
  if (!license) return { authorized: false, reason: "license_not_found" };
  if (license.status !== "active") return { authorized: false, reason: "blocked" };

  const now = new Date();
  const paid = new Date(license.paid_until);
  const grace = new Date(license.grace_until);

  if (now <= paid) return { authorized: true, phase: "paid" };
  if (now <= grace) return { authorized: true, phase: "grace" };

  return { authorized: false, phase: "expired", reason: "payment_overdue" };
}

async function ensureDevice(userId, installId, deviceName) {
  if (!installId) return { ok:false, reason:"device_required" };

  const hash = sha256(installId);

  const { data: devices, error } = await supabaseAdmin
    .from("extension_devices")
    .select("id, device_fingerprint_hash, active")
    .eq("user_id", userId)
    .eq("active", true);

  if (error) throw error;

  if (!devices || devices.length === 0) {
    const { error: insertError } = await supabaseAdmin
      .from("extension_devices")
      .insert({
        user_id: userId,
        device_name: String(deviceName || "Chrome").slice(0, 120),
        device_fingerprint_hash: hash,
        token_hash: sha256(`${userId}:${installId}`),
        active: true,
        last_seen_at: new Date().toISOString()
      });

    if (insertError) throw insertError;
    return { ok:true, registered:true };
  }

  const match = devices.find(d => d.device_fingerprint_hash === hash);
  if (!match) return { ok:false, reason:"device_limit_reached" };

  await supabaseAdmin
    .from("extension_devices")
    .update({ last_seen_at: new Date().toISOString() })
    .eq("id", match.id);

  return { ok:true, registered:false };
}

app.get("/", (req, res) => {
  res.json({
    system: "Biply Flow",
    status: "online",
    version: CURRENT_VERSION,
    payments: "InfinitePay"
  });
});

app.get("/health", (req, res) => {
  res.json({ ok: true, service: "biply-flow-backend" });
});

app.post("/api/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({ success:false, error:"email_password_required" });
    }

    const { data, error } = await supabasePublic.auth.signInWithPassword({ email, password });

    if (error || !data?.session) {
      return res.status(401).json({ success:false, error:"invalid_credentials" });
    }

    res.json({
      success: true,
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      expires_in: data.session.expires_in
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success:false, error:"server_error" });
  }
});

app.post("/api/token/refresh", async (req, res) => {
  try {
    const refresh_token = String(req.body.refresh_token || "");
    if (!refresh_token) {
      return res.status(400).json({ success:false, error:"refresh_token_required" });
    }

    const { data, error } = await supabasePublic.auth.refreshSession({ refresh_token });
    if (error || !data?.session) {
      return res.status(401).json({ success:false, error:"invalid_refresh_token" });
    }

    res.json({
      success: true,
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      expires_in: data.session.expires_in
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success:false, error:"server_error" });
  }
});

app.get("/api/license", async (req, res) => {
  try {
    const user = await getUser(req);
    if (!user) {
      return res.status(401).json({ authorized:false, reason:"not_authenticated" });
    }

    const license = await getLicense(user.id);
    const state = checkLicense(license);

    res.json({
      email: user.email,
      ...state,
      paid_until: license?.paid_until,
      grace_until: license?.grace_until
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ authorized:false, reason:"server_error" });
  }
});

app.post("/api/session/heartbeat", async (req, res) => {
  try {
    const user = await getUser(req);
    if (!user) return res.status(401).json({ authorized:false, reason:"not_authenticated" });

    const license = await getLicense(user.id);
    const state = checkLicense(license);
    if (!state.authorized) return res.status(403).json(state);

    const now = new Date().toISOString();

    const { error } = await supabaseAdmin
      .from("web_sessions")
      .upsert({
        user_id: user.id,
        last_heartbeat_at: now,
        updated_at: now
      }, { onConflict:"user_id" });

    if (error) throw error;

    res.json({
      authorized: true,
      phase: state.phase,
      paid_until: license.paid_until,
      grace_until: license.grace_until
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ authorized:false, reason:"server_error" });
  }
});

app.post("/api/checkout/create", async (req, res) => {
  try {
    const user = await getUser(req);
    if (!user) {
      return res.status(401).json({ success:false, error:"not_authenticated" });
    }

    const orderNsu = `BIPLY-${Date.now()}-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;
    const { error: orderError } = await supabaseAdmin.from("orders").insert({
      order_nsu: orderNsu,
      customer_email: user.email,
      amount_cents: PLAN_PRICE_CENTS,
      plan_name: PLAN_NAME,
      plan_days: PLAN_DAYS,
      status: "pending"
    });
    if (orderError) throw orderError;

    const baseUrl = publicBaseUrl(req);
    const response = await fetch("https://api.checkout.infinitepay.io/links", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        handle: INFINITEPAY_HANDLE,
        redirect_url: `${baseUrl}/pagamento-concluido`,
        webhook_url: `${baseUrl}/api/webhooks/infinitepay`,
        order_nsu: orderNsu,
        items: [{
          quantity: 1,
          price: PLAN_PRICE_CENTS,
          description: `${PLAN_NAME} - ${PLAN_DAYS} dias`
        }]
      })
    });

    const result = await response.json().catch(() => ({}));
    if (!response.ok || !result?.url) {
      console.error("InfinitePay checkout:", result);
      return res.status(502).json({ success:false, error:"infinitepay_checkout_error" });
    }

    res.json({ success:true, checkout_url:result.url, order_nsu:orderNsu });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success:false, error:"server_error" });
  }
});

app.post("/api/webhooks/infinitepay", async (req, res) => {
  try {
    const payload = req.body || {};
    const orderNsu = String(payload.order_nsu || "");
    const transactionNsu = String(payload.transaction_nsu || "");
    const slug = String(payload.invoice_slug || payload.slug || "");

    if (!orderNsu || !transactionNsu || !slug) {
      return res.status(400).json({ success:false, message:"Dados incompletos" });
    }

    const { data: order, error } = await supabaseAdmin
      .from("orders")
      .select("*")
      .eq("order_nsu", orderNsu)
      .maybeSingle();
    if (error) throw error;
    if (!order) return res.status(400).json({ success:false, message:"Pedido nao encontrado" });

    // Nao confiamos apenas no webhook: confirmamos direto na InfinitePay.
    const verified = await verifyInfinitePayPayment({
      order_nsu: orderNsu,
      transaction_nsu: transactionNsu,
      slug
    });

    if (!verified?.paid) {
      return res.status(400).json({ success:false, message:"Pagamento nao confirmado" });
    }

    await processInfinitePayPayment(order, payload, verified);
    return res.status(200).json({ success:true, message:null });
  } catch (error) {
    console.error("Webhook InfinitePay:", error);
    return res.status(400).json({ success:false, message:"Falha ao validar pagamento" });
  }
});

app.post("/api/payment/verify-return", async (req, res) => {
  try {
    const orderNsu = String(req.body.order_nsu || "");
    const transactionNsu = String(req.body.transaction_nsu || "");
    const slug = String(req.body.slug || "");
    if (!orderNsu) return res.status(400).json({ paid:false, error:"order_required" });

    const { data: order, error } = await supabaseAdmin
      .from("orders")
      .select("*")
      .eq("order_nsu", orderNsu)
      .maybeSingle();
    if (error) throw error;
    if (!order) return res.status(404).json({ paid:false, error:"order_not_found" });
    if (order.status === "paid") return res.json({ paid:true, already_processed:true });
    if (!transactionNsu || !slug) return res.json({ paid:false, pending:true });

    const verified = await verifyInfinitePayPayment({
      order_nsu: orderNsu,
      transaction_nsu: transactionNsu,
      slug
    });
    if (!verified?.paid) return res.json({ paid:false });

    const result = await processInfinitePayPayment(order, {
      order_nsu: orderNsu,
      transaction_nsu: transactionNsu,
      invoice_slug: slug,
      capture_method: req.body.capture_method || null,
      receipt_url: req.body.receipt_url || null
    }, verified);

    res.json({ paid:true, ...result });
  } catch (error) {
    console.error(error);
    res.status(500).json({ paid:false, error:"server_error" });
  }
});

app.post("/api/version/check", (req, res) => {
  const version = String(req.body.version || "").trim().toUpperCase();
  const allowed = ALLOWED_VERSIONS.includes(version);

  res.json({
    allowed,
    version,
    current_version: CURRENT_VERSION,
    minimum_version: MIN_VERSION,
    allowed_versions: ALLOWED_VERSIONS,
    update_available: version !== CURRENT_VERSION,
    reason: allowed ? "ok" : "version_blocked"
  });
});

app.post("/api/extension/validate", async (req, res) => {
  try {
    const user = await getUser(req);
    if (!user) {
      return res.status(401).json({ authorized:false, reason:"not_authenticated" });
    }

    const version = String(req.body.version || "").trim().toUpperCase();
    if (!ALLOWED_VERSIONS.includes(version)) {
      return res.status(403).json({
        authorized:false,
        reason:"version_blocked",
        current_version: CURRENT_VERSION,
        allowed_versions: ALLOWED_VERSIONS
      });
    }

    const license = await getLicense(user.id);
    const state = checkLicense(license);

    if (!state.authorized) {
      return res.status(403).json({
        ...state,
        paid_until: license?.paid_until,
        grace_until: license?.grace_until,
        current_version: CURRENT_VERSION
      });
    }

    const device = await ensureDevice(
      user.id,
      String(req.body.install_id || ""),
      String(req.body.device_name || "")
    );

    if (!device.ok) {
      return res.status(403).json({
        authorized:false,
        reason:device.reason,
        paid_until: license.paid_until,
        grace_until: license.grace_until
      });
    }

    const { data: session, error: sessionError } = await supabaseAdmin
      .from("web_sessions")
      .select("last_heartbeat_at")
      .eq("user_id", user.id)
      .maybeSingle();

    if (sessionError) throw sessionError;

    if (!session) {
      return res.status(403).json({
        authorized:false,
        reason:"site_not_open",
        paid_until: license.paid_until,
        grace_until: license.grace_until
      });
    }

    const ageSeconds =
      (Date.now() - new Date(session.last_heartbeat_at).getTime()) / 1000;

    if (ageSeconds > HEARTBEAT_LIMIT) {
      return res.status(403).json({
        authorized:false,
        reason:"site_not_open",
        paid_until: license.paid_until,
        grace_until: license.grace_until
      });
    }

    res.json({
      authorized: true,
      phase: state.phase,
      version,
      current_version: CURRENT_VERSION,
      paid_until: license.paid_until,
      grace_until: license.grace_until,
      device_registered: !!device.registered,
      heartbeat_age_seconds: Math.floor(ageSeconds)
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ authorized:false, reason:"server_error" });
  }
});

app.get("/cliente", (req, res) => {
  res.set("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Biply Flow - Area do Cliente</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:Arial,sans-serif;background:#07111f;color:#fff}
.wrap{width:min(520px,92%);margin:45px auto}.card{background:#10243b;border:1px solid #24425f;border-radius:18px;padding:22px}
h1{margin:0 0 7px}p{color:#aec0d3;line-height:1.45}
input,button{width:100%;padding:13px;border-radius:10px;margin:7px 0;font-size:16px}
input{background:#081725;color:white;border:1px solid #31536f}.passwordWrap{position:relative}.passwordWrap input{padding-right:52px}
.eye{position:absolute;right:8px;top:12px;width:42px;height:42px;margin:0;background:transparent;color:#d7e4f2;font-size:20px}
button{border:0;background:#35e59a;color:#04101a;font-weight:800;cursor:pointer}.secondary{background:#173653;color:white}.pay{background:#27d3ff}
.status{margin-top:15px;padding:13px;border-radius:10px;background:#081725;white-space:pre-wrap}.ok{color:#8dffca}.bad{color:#ff9aa5}.warn{color:#ffe18b}.hidden{display:none}
.price{font-weight:800;margin:12px 0;color:#fff}
</style>
</head>
<body>
<div class="wrap"><div class="card">
<h1>Biply Flow</h1>
<p>Entre e mantenha esta pagina aberta enquanto estiver usando a extensao.</p>
<div id="loginBox">
<input id="email" type="email" placeholder="E-mail" autocomplete="email">
<div class="passwordWrap"><input id="password" type="password" placeholder="Senha" autocomplete="current-password"><button id="eye" class="eye" type="button">&#128065;</button></div>
<button i
