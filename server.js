require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.set("trust proxy", 1);
app.use(cors());
app.use(express.json({ limit: "100kb" }));

const PORT = process.env.PORT || 3000;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_PUBLISHABLE_KEY = process.env.SUPABASE_PUBLISHABLE_KEY;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;

const CURRENT_VERSION = process.env.CURRENT_VERSION || "V7";
const ALLOWED_VERSIONS = (process.env.ALLOWED_VERSIONS || "V7")
  .split(",")
  .map(v => v.trim().toUpperCase())
  .filter(Boolean);

const HEARTBEAT_LIMIT = Number(process.env.SITE_HEARTBEAT_SECONDS || 120);

const INFINITEPAY_HANDLE = "jose-antonio-8lr";

const PLANS = {
  monthly: {
    code: "monthly",
    name: "Biply Flow Mensal",
    days: 30,
    price_cents: 2990
  },
  annual: {
    code: "annual",
    name: "Biply Flow Anual",
    days: 365,
    price_cents: 29900
  }
};

const GRACE_DAYS = 3;

const supabasePublic = createClient(
  SUPABASE_URL,
  SUPABASE_PUBLISHABLE_KEY,
  { auth: { persistSession: false, autoRefreshToken: false } }
);

const supabaseAdmin = createClient(
  SUPABASE_URL,
  SUPABASE_SECRET_KEY,
  { auth: { persistSession: false, autoRefreshToken: false } }
);

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

async function getUser(req) {
  const auth = String(req.headers.authorization || "");
  if (!auth.startsWith("Bearer ")) return null;

  const token = auth.substring(7);
  const { data, error } = await supabaseAdmin.auth.getUser(token);

  if (error || !data?.user) return null;
  return data.user;
}

async function getUserByEmail(email) {
  for (let page = 1; page <= 20; page++) {
    const { data, error } = await supabaseAdmin.auth.admin.listUsers({
      page,
      perPage: 100
    });

    if (error) throw error;

    const found = (data.users || []).find(
      u => String(u.email || "").toLowerCase() === String(email || "").toLowerCase()
    );

    if (found) return found;
    if ((data.users || []).length < 100) break;
  }

  return null;
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
  if (!installId) return { ok: false, reason: "device_required" };

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

    return { ok: true, registered: true };
  }

  const match = devices.find(d => d.device_fingerprint_hash === hash);

  if (!match) return { ok: false, reason: "device_limit_reached" };

  await supabaseAdmin
    .from("extension_devices")
    .update({ last_seen_at: new Date().toISOString() })
    .eq("id", match.id);

  return { ok: true, registered: false };
}

async function verifyInfinitePayPayment({ order_nsu, transaction_nsu, slug }) {
  const response = await fetch(
    "https://api.checkout.infinitepay.io/payment_check",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        handle: INFINITEPAY_HANDLE,
        order_nsu,
        transaction_nsu,
        slug
      })
    }
  );

  const result = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      `InfinitePay payment_check HTTP ${response.status}: ${JSON.stringify(result)}`
    );
  }

  return result;
}

async function processInfinitePayPayment(order, payload, verified) {
  if (!verified?.paid) throw new Error("Pagamento nao confirmado pela InfinitePay.");

  if (Number(verified.amount) !== Number(order.amount_cents)) {
    throw new Error("Valor confirmado nao corresponde ao pedido.");
  }

  const transactionNsu = String(payload.transaction_nsu || "");

  if (!transactionNsu) throw new Error("transaction_nsu ausente.");

  const { data: existingPayment, error: existingPaymentError } =
    await supabaseAdmin
      .from("payments")
      .select("id")
      .eq("transaction_nsu", transactionNsu)
      .maybeSingle();

  if (existingPaymentError) throw existingPaymentError;

  if (existingPayment) return { already_processed: true };

  const user = await getUserByEmail(order.customer_email);
  if (!user) throw new Error("Usuario do pedido nao encontrado.");

  const currentLicense = await getLicense(user.id);
  const now = new Date();

  let baseDate = now;

  if (currentLicense?.paid_until && new Date(currentLicense.paid_until) > now) {
    baseDate = new Date(currentLicense.paid_until);
  }

  const newPaidUntil = addDays(baseDate, Number(order.plan_days || 30));
  const newGraceUntil = addDays(newPaidUntil, GRACE_DAYS);

  if (currentLicense) {
    const { error } = await supabaseAdmin
      .from("licenses")
      .update({
        status: "active",
        plan_name: order.plan_name,
        paid_until: newPaidUntil.toISOString(),
        grace_until: newGraceUntil.toISOString(),
        updated_at: now.toISOString()
      })
      .eq("user_id", user.id);

    if (error) throw error;
  } else {
    const { error } = await supabaseAdmin
      .from("licenses")
      .insert({
        user_id: user.id,
        status: "active",
        plan_name: order.plan_name,
        paid_until: newPaidUntil.toISOString(),
        grace_until: newGraceUntil.toISOString()
      });

    if (error) throw error;
  }

  const { error: paymentError } = await supabaseAdmin
    .from("payments")
    .insert({
      user_id: user.id,
      order_nsu: order.order_nsu,
      transaction_nsu: transactionNsu,
      amount_cents: order.amount_cents,
      capture_method: payload.capture_method || verified.capture_method || null,
      raw_payload: {
        webhook: payload,
        payment_check: verified
      }
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
    paid_until: newPaidUntil.toISOString(),
    grace_until: newGraceUntil.toISOString()
  };
}

app.get("/", (req, res) => {
  res.json({
    system: "Biply Flow",
    status: "online",
    version: CURRENT_VERSION,
    payments: "InfinitePay",
    plans: {
      monthly: { price: 29.90, days: 30 },
      annual: { price: 299.00, days: 365 }
    }
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
      return res.status(400).json({ success: false, error: "email_password_required" });
    }

    const { data, error } = await supabasePublic.auth.signInWithPassword({
      email,
      password
    });

    if (error || !data?.session) {
      return res.status(401).json({ success: false, error: "invalid_credentials" });
    }

    res.json({
      success: true,
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      expires_in: data.session.expires_in
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: "server_error" });
  }
});

app.post("/api/token/refresh", async (req, res) => {
  try {
    const refresh_token = String(req.body.refresh_token || "");

    if (!refresh_token) {
      return res.status(400).json({ success: false, error: "refresh_token_required" });
    }

    const { data, error } = await supabasePublic.auth.refreshSession({
      refresh_token
    });

    if (error || !data?.session) {
      return res.status(401).json({ success: false, error: "invalid_refresh_token" });
    }

    res.json({
      success: true,
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      expires_in: data.session.expires_in
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: "server_error" });
  }
});

app.get("/api/license", async (req, res) => {
  try {
    const user = await getUser(req);

    if (!user) {
      return res.status(401).json({ authorized: false, reason: "not_authenticated" });
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
    res.status(500).json({ authorized: false, reason: "server_error" });
  }
});

app.post("/api/session/heartbeat", async (req, res) => {
  try {
    const user = await getUser(req);

    if (!user) {
      return res.status(401).json({ authorized: false, reason: "not_authenticated" });
    }

    const license = await getLicense(user.id);
    const state = checkLicense(license);

    if (!state.authorized) return res.status(403).json(state);

    const now = new Date().toISOString();

    const { error } = await supabaseAdmin
      .from("web_sessions")
      .upsert(
        {
          user_id: user.id,
          last_heartbeat_at: now,
          updated_at: now
        },
        { onConflict: "user_id" }
      );

    if (error) throw error;

    res.json({
      authorized: true,
      phase: state.phase,
      paid_until: license.paid_until,
      grace_until: license.grace_until
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ authorized: false, reason: "server_error" });
  }
});

app.post("/api/checkout/create", async (req, res) => {
  try {
    const user = await getUser(req);

    if (!user) {
      return res.status(401).json({ success: false, error: "not_authenticated" });
    }

    const requestedPlan = String(req.body.plan || "monthly").trim().toLowerCase();
    const plan = PLANS[requestedPlan];

    if (!plan) {
      return res.status(400).json({ success: false, error: "invalid_plan" });
    }

    const orderNsu =
      `BIPLY-${plan.code.toUpperCase()}-${Date.now()}-${crypto.randomBytes(4)
        .toString("hex")
        .toUpperCase()}`;

    const { error: orderInsertError } = await supabaseAdmin
      .from("orders")
      .insert({
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
      items: [
        {
          quantity: 1,
          price: plan.price_cents,
          description: `${plan.name} - ${plan.days} dias`
        }
      ]
    };

    const response = await fetch("https://api.checkout.infinitepay.io/links", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(checkoutPayload)
    });

    const result = await response.json().catch(() => ({}));

    if (!response.ok || !result?.url) {
      console.error("InfinitePay checkout:", result);

      return res.status(502).json({
        success: false,
        error: "infinitepay_checkout_error",
        details: result
      });
    }

    res.json({
      success: true,
      checkout_url: result.url,
      order_nsu: orderNsu,
      plan: plan.code,
      plan_name: plan.name,
      plan_days: plan.days,
      amount_cents: plan.price_cents
    });
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

    if (!orderNsu || !transactionNsu || !slug) {
      return res.status(400).json({ success: false, message: "Dados incompletos" });
    }

    const { data: order, error: orderError } = await supabaseAdmin
      .from("orders")
      .select("*")
      .eq("order_nsu", orderNsu)
      .maybeSingle();

    if (orderError) throw orderError;

    if (!order) {
      return res.status(400).json({ success: false, message: "Pedido nao encontrado" });
    }

    const verified = await verifyInfinitePayPayment({
      order_nsu: orderNsu,
      transaction_nsu: transactionNsu,
      slug
    });

    if (!verified?.paid) {
      return res.status(400).json({ success: false, message: "Pagamento nao confirmado" });
    }

    await processInfinitePayPayment(order, payload, verified);

    return res.status(200).json({ success: true, message: null });
  } catch (error) {
    console.error("Webhook InfinitePay:", error);
    return res.status(400).json({ success: false, message: "Falha ao validar pagamento" });
  }
});

app.post("/api/version/check", (req, res) => {
  const version = String(req.body.version || "").trim().toUpperCase();
  const allowed = ALLOWED_VERSIONS.includes(version);

  res.json({
    allowed,
    version,
    current_version: CURRENT_VERSION,
    allowed_versions: ALLOWED_VERSIONS,
    update_available: version !== CURRENT_VERSION,
    reason: allowed ? "ok" : "version_blocked"
  });
});

app.post("/api/extension/validate", async (req, res) => {
  try {
    const user = await getUser(req);

    if (!user) {
      return res.status(401).json({ authorized: false, reason: "not_authenticated" });
    }

    const version = String(req.body.version || "").trim().toUpperCase();

    if (!ALLOWED_VERSIONS.includes(version)) {
      return res.status(403).json({
        authorized: false,
        reason: "version_blocked",
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
        authorized: false,
        reason: device.reason,
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
        authorized: false,
        reason: "site_not_open",
        paid_until: license.paid_until,
        grace_until: license.grace_until
      });
    }

    const ageSeconds =
      (Date.now() - new Date(session.last_heartbeat_at).getTime()) / 1000;

    if (ageSeconds > HEARTBEAT_LIMIT) {
      return res.status(403).json({
        authorized: false,
        reason: "site_not_open",
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
    res.status(500).json({ authorized: false, reason: "server_error" });
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
*{box-sizing:border-box}
body{margin:0;font-family:Arial,sans-serif;background:#07111f;color:#fff}
.wrap{width:min(560px,92%);margin:45px auto}
.card{background:#10243b;border:1px solid #24425f;border-radius:18px;padding:22px}
h1{margin:0 0 7px}
p{color:#aec0d3;line-height:1.45}
.passwordWrap{position:relative}
input,button{width:100%;padding:13px;border-radius:10px;margin:7px 0;font-size:16px}
input{background:#081725;color:white;border:1px solid #31536f}
.passwordWrap input{padding-right:52px}
.eye{position:absolute;right:8px;top:12px;width:42px;height:42px;margin:0;background:transparent;color:#d7e4f2;font-size:20px}
button{border:0;background:#35e59a;color:#04101a;font-weight:800;cursor:pointer}
.secondary{background:#173653;color:white}
.status{margin-top:15px;padding:13px;border-radius:10px;background:#081725;white-space:pre-wrap}
.ok{color:#8dffca}
.bad{color:#ff9aa5}
.warn{color:#ffe18b}
.hidden{display:none}
.plans{display:grid;grid-template-columns:1fr;gap:12px;margin-top:16px}
.plan{background:#081725;border:1px solid #31536f;border-radius:14px;padding:15px}
.plan h3{margin:0 0 6px}
.price{font-size:24px;font-weight:900;margin:6px 0}
.save{color:#8dffca;font-size:13px}
.pay{background:#27d3ff}
</style>
</head>
<body>
<div class="wrap">
<div class="card">

<h1>Biply Flow</h1>
<p>Entre e mantenha esta pagina aberta enquanto estiver usando a extensao.</p>

<div id="loginBox">
<input id="email" type="email" placeholder="E-mail" autocomplete="email">

<div class="passwordWrap">
<input id="password" type="password" placeholder="Senha" autocomplete="current-password">
<button id="eye" class="eye" type="button" title="Mostrar ou ocultar senha">&#128065;</button>
</div>

<button id="login">Entrar</button>
</div>

<div id="onlineBox" class="hidden">

<p id="account"></p>

<div class="plans">

<div class="plan">
<h3>Plano Mensal</h3>
<div class="price">R$ 29,90</div>
<div>30 dias de acesso</div>
<button id="payMonthly" class="pay">PAGAR MENSAL</button>
</div>

<div class="plan">
<h3>Plano Anual</h3>
<div class="price">R$ 299,00</div>
<div>365 dias de acesso</div>
<div class="save">Economize R$ 59,80 no ano</div>
<button id="payAnnual" class="pay">PAGAR ANUAL</button>
</div>

</div>

<button id="logout" class="secondary">Sair</button>

</div>

<div id="status" class="status">Aguardando login...</div>

</div>
</div>

<script>
let accessToken=null;
let refreshToken=null;
let timer=null;

const statusEl=document.getElementById("status");
const loginBox=document.getElementById("loginBox");
const onlineBox=document.getElementById("onlineBox");
const account=document.getElementById("account");

function setStatus(text,cls=""){
  statusEl.className="status "+cls;
  statusEl.textContent=text;
}

document.getElementById("eye").onclick=()=>{
  const p=document.getElementById("password");
  p.type=p.type==="password"?"text":"password";
};

async function refresh(){
  if(!refreshToken)return false;

  const r=await fetch("/api/token/refresh",{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({refresh_token:refreshToken})
  });

  const j=await r.json().catch(()=>({}));

  if(!r.ok||!j.access_token)return false;

  accessToken=j.access_token;
  refreshToken=j.refresh_token||refreshToken;
  return true;
}

async function heartbeat(retry=true){
  if(!accessToken)return;

  let r=await fetch("/api/session/heartbeat",{
    method:"POST",
    headers:{Authorization:"Bearer "+accessToken}
  });

  if(r.status===401&&retry&&await refresh()){
    return heartbeat(false);
  }

  const j=await r.json().catch(()=>({}));

  if(!r.ok||!j.authorized){
    setStatus("Acesso nao autorizado: "+(j.reason||"erro"),"bad");
    return;
  }

  const phase=j.phase==="grace"?"TOLERANCIA":"ATIVO";
  const cls=j.phase==="grace"?"warn":"ok";

  setStatus(
    "SITE CONECTADO - "+phase+
    "\\nPago ate: "+new Date(j.paid_until).toLocaleString("pt-BR")+
    "\\nTolerancia ate: "+new Date(j.grace_until).toLocaleString("pt-BR")+
    "\\n\\nMantenha esta pagina aberta.",
    cls
  );
}

document.getElementById("login").onclick=async()=>{
  const email=document.getElementById("email").value.trim();
  const password=document.getElementById("password").value;

  setStatus("Entrando...");

  const r=await fetch("/api/login",{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({email,password})
  });

  const j=await r.json().catch(()=>({}));

  if(!r.ok||!j.access_token){
    setStatus("E-mail ou senha invalidos.","bad");
    return;
  }

  accessToken=j.access_token;
  refreshToken=j.refresh_token||null;

  document.getElementById("password").value="";

  loginBox.classList.add("hidden");
  onlineBox.classList.remove("hidden");

  account.textContent=email;

  await heartbeat();
  timer=setInterval(heartbeat,30000);
};

async function createCheckout(plan){
  if(!accessToken){
    setStatus("Faca login primeiro.","bad");
    return;
  }

  setStatus("Criando pagamento InfinitePay...");

  let r=await fetch("/api/checkout/create",{
    method:"POST",
    headers:{
      Authorization:"Bearer "+accessToken,
      "Content-Type":"application/json"
    },
    body:JSON.stringify({plan})
  });

  if(r.status===401&&await refresh()){
    r=await fetch("/api/checkout/create",{
      method:"POST",
      headers:{
        Authorization:"Bearer "+accessToken,
        "Content-Type":"application/json"
      },
      body:JSON.stringify({plan})
    });
  }

  const j=await r.json().catch(()=>({}));

  if(!r.ok||!j.checkout_url){
    setStatus("Nao foi possivel abrir o pagamento.","bad");
    return;
  }

  location.href=j.checkout_url;
}

document.getElementById("payMonthly").onclick=()=>createCheckout("monthly");
document.getElementById("payAnnual").onclick=()=>createCheckout("annual");

document.getElementById("logout").onclick=()=>{
  accessToken=null;
  refreshToken=null;

  if(timer)clearInterval(timer);
  timer=null;

  onlineBox.classList.add("hidden");
  loginBox.classList.remove("hidden");

  setStatus("Sessao encerrada.");
};
</script>
</body>
</html>`);
});

app.get("/pagamento-concluido", (req, res) => {
  res.set("Content-Type", "text/html; charset=utf-8");

  res.send(`<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Biply Flow - Pagamento</title>
<style>
body{margin:0;font-family:Arial,sans-serif;background:#07111f;color:white}
.card{width:min(520px,92%);margin:60px auto;background:#10243b;border:1px solid #24425f;border-radius:18px;padding:24px}
a{display:block;text-align:center;padding:13px;border-radius:10px;background:#35e59a;color:#04101a;font-weight:bold;text-decoration:none;margin-top:18px}
</style>
</head>
<body>
<div class="card">
<h2>Biply Flow</h2>
<p>Pagamento enviado. Aguarde alguns segundos para a confirmacao automatica.</p>
<a href="/cliente">Voltar para minha conta</a>
</div>
</body>
</html>`);
});

app.listen(PORT, () => {
  console.log(`Biply Flow online na porta ${PORT}`);
  console.log(`InfinitePay configurada: ${INFINITEPAY_HANDLE}`);
  console.log("Planos ativos: mensal R$ 29,90 / anual R$ 299,00");
});
