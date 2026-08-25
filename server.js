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

const supabasePublic = createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }
});

const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SECRET_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }
});

function sha256(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
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
    version: CURRENT_VERSION
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
  res.type("html").send(`<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Biply Flow â€” Ãrea do Cliente</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:Arial,sans-serif;background:#07111f;color:#fff}
.wrap{width:min(520px,92%);margin:45px auto}.card{background:#10243b;border:1px solid #24425f;border-radius:18px;padding:22px}
h1{margin:0 0 7px}p{color:#aec0d3;line-height:1.45}
input,button{width:100%;padding:13px;border-radius:10px;margin:7px 0;font-size:16px}
input{background:#081725;color:white;border:1px solid #31536f}
button{border:0;background:#35e59a;color:#04101a;font-weight:800;cursor:pointer}
.secondary{background:#173653;color:white}.status{margin-top:15px;padding:13px;border-radius:10px;background:#081725;white-space:pre-wrap}
.ok{color:#8dffca}.bad{color:#ff9aa5}.warn{color:#ffe18b}.hidden{display:none}
</style>
</head>
<body>
<div class="wrap"><div class="card">
<h1>Biply Flow</h1>
<p>Entre e mantenha esta pÃ¡gina aberta enquanto estiver usando a extensÃ£o.</p>

<div id="loginBox">
<input id="email" type="email" placeholder="E-mail" autocomplete="email">
<input id="password" type="password" placeholder="Senha" autocomplete="current-password">
<button id="login">Entrar</button>
</div>

<div id="onlineBox" class="hidden">
<p id="account"></p>
<button id="logout" class="secondary">Sair</button>
</div>

<div id="status" class="status">Aguardando login...</div>
</div></div>

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

async function refresh(){
 if(!refreshToken) return false;
 const r=await fetch("/api/token/refresh",{
  method:"POST",
  headers:{"Content-Type":"application/json"},
  body:JSON.stringify({refresh_token:refreshToken})
 });
 const j=await r.json().catch(()=>({}));
 if(!r.ok||!j.access_token) return false;
 accessToken=j.access_token;
 refreshToken=j.refresh_token||refreshToken;
 return true;
}

async function heartbeat(retry=true){
 if(!accessToken) return;
 let r=await fetch("/api/session/heartbeat",{
  method:"POST",
  headers:{Authorization:"Bearer "+accessToken}
 });
 if(r.status===401&&retry&&await refresh()) return heartbeat(false);
 const j=await r.json().catch(()=>({}));
 if(!r.ok||!j.authorized){
  setStatus("Acesso nÃ£o autorizado: "+(j.reason||"erro"),"bad");
  return;
 }
 const phase=j.phase==="grace"?"TOLERÃ‚NCIA":"ATIVO";
 const cls=j.phase==="grace"?"warn":"ok";
 setStatus(
  "SITE CONECTADO â€” "+phase+
  "\\nPago atÃ©: "+new Date(j.paid_until).toLocaleString("pt-BR")+
  "\\nTolerÃ¢ncia atÃ©: "+new Date(j.grace_until).toLocaleString("pt-BR")+
  "\\n\\nMantenha esta pÃ¡gina aberta.",
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
  setStatus("E-mail ou senha invÃ¡lidos.","bad");return;
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

document.getElementById("logout").onclick=()=>{
 accessToken=null;refreshToken=null;
 if(timer)clearInterval(timer);
 timer=null;
 onlineBox.classList.add("hidden");
 loginBox.classList.remove("hidden");
 setStatus("SessÃ£o encerrada.");
};
</script>
</body>
</html>`);
});

app.get("/teste-login", (req, res) => {
  res.type("html").send(`<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Teste Biply Flow</title></head><body style="font-family:Arial;padding:30px">
<h2>Biply Flow â€” Teste de Login</h2>
<p>A pÃ¡gina principal para uso normal agora Ã© <a href="/cliente">/cliente</a>.</p>
</body></html>`);
});

app.listen(PORT, () => {
  console.log(`Biply Flow online na porta ${PORT}`);
});
