require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

const supabasePublic = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_PUBLISHABLE_KEY
);

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY
);

const CURRENT_VERSION = process.env.CURRENT_VERSION || "V7";
const MIN_VERSION = process.env.MIN_VERSION || "V7";

const ALLOWED_VERSIONS = (
  process.env.ALLOWED_VERSIONS || "V7"
)
  .split(",")
  .map(v => v.trim().toUpperCase());

const HEARTBEAT_LIMIT = Number(
  process.env.SITE_HEARTBEAT_SECONDS || 120
);

async function getUser(req) {
  const auth = req.headers.authorization || "";

  if (!auth.startsWith("Bearer ")) {
    return null;
  }

  const token = auth.substring(7);

  const { data, error } =
    await supabaseAdmin.auth.getUser(token);

  if (error || !data?.user) {
    return null;
  }

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
  if (!license) {
    return {
      authorized: false,
      reason: "license_not_found"
    };
  }

  if (license.status !== "active") {
    return {
      authorized: false,
      reason: "blocked"
    };
  }

  const now = new Date();
  const paid = new Date(license.paid_until);
  const grace = new Date(license.grace_until);

  if (now <= paid) {
    return {
      authorized: true,
      phase: "paid"
    };
  }

  if (now <= grace) {
    return {
      authorized: true,
      phase: "grace"
    };
  }

  return {
    authorized: false,
    phase: "expired",
    reason: "payment_overdue"
  };
}

app.get("/", (req, res) => {
  res.json({
    system: "Biply Flow",
    status: "online",
    version: CURRENT_VERSION
  });
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "biply-flow-backend"
  });
});

app.post("/api/login", async (req, res) => {
  try {
    const email =
      String(req.body.email || "")
        .trim()
        .toLowerCase();

    const password =
      String(req.body.password || "");

    const { data, error } =
      await supabasePublic.auth.signInWithPassword({
        email,
        password
      });

    if (error || !data?.session) {
      return res.status(401).json({
        success: false,
        error: "invalid_credentials"
      });
    }

    res.json({
      success: true,
      access_token: data.session.access_token
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      error: "server_error"
    });
  }
});

app.get("/api/license", async (req, res) => {
  try {
    const user = await getUser(req);

    if (!user) {
      return res.status(401).json({
        authorized: false,
        reason: "not_authenticated"
      });
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

    res.status(500).json({
      authorized: false,
      reason: "server_error"
    });
  }
});

app.post("/api/session/heartbeat", async (req, res) => {
  try {
    const user = await getUser(req);

    if (!user) {
      return res.status(401).json({
        authorized: false
      });
    }

    const license = await getLicense(user.id);
    const state = checkLicense(license);

    if (!state.authorized) {
      return res.status(403).json(state);
    }

    const now = new Date().toISOString();

    const { error } = await supabaseAdmin
      .from("web_sessions")
      .upsert({
        user_id: user.id,
        last_heartbeat_at: now,
        updated_at: now
      });

    if (error) throw error;

    res.json({
      authorized: true,
      phase: state.phase
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      authorized: false,
      reason: "server_error"
    });
  }
});

app.post("/api/version/check", (req, res) => {
  const version =
    String(req.body.version || "")
      .trim()
      .toUpperCase();

  const allowed =
    ALLOWED_VERSIONS.includes(version);

  res.json({
    allowed,
    version,
    current_version: CURRENT_VERSION,
    minimum_version: MIN_VERSION,
    allowed_versions: ALLOWED_VERSIONS,
    update_available:
      version !== CURRENT_VERSION
  });
});

app.post("/api/extension/validate", async (req, res) => {
  try {
    const user = await getUser(req);

    if (!user) {
      return res.status(401).json({
        authorized: false,
        reason: "not_authenticated"
      });
    }

    const version =
      String(req.body.version || "")
        .trim()
        .toUpperCase();

    if (!ALLOWED_VERSIONS.includes(version)) {
      return res.status(403).json({
        authorized: false,
        reason: "version_blocked",
        current_version: CURRENT_VERSION
      });
    }

    const license = await getLicense(user.id);
    const state = checkLicense(license);

    if (!state.authorized) {
      return res.status(403).json(state);
    }

    const { data: session } = await supabaseAdmin
      .from("web_sessions")
      .select("last_heartbeat_at")
      .eq("user_id", user.id)
      .maybeSingle();

    if (!session) {
      return res.status(403).json({
        authorized: false,
        reason: "site_not_open"
      });
    }

    const age =
      (Date.now() -
        new Date(session.last_heartbeat_at).getTime()) /
      1000;

    if (age > HEARTBEAT_LIMIT) {
      return res.status(403).json({
        authorized: false,
        reason: "site_not_open"
      });
    }

    res.json({
      authorized: true,
      phase: state.phase,
      version,
      current_version: CURRENT_VERSION,
      paid_until: license.paid_until,
      grace_until: license.grace_until
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      authorized: false,
      reason: "server_error"
    });
  }
});

app.listen(PORT, () => {
  console.log(
    `Biply Flow online na porta ${PORT}`
  );
});
