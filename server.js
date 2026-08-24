require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();

const PORT = process.env.PORT || 3000;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_PUBLISHABLE_KEY =
  process.env.SUPABASE_PUBLISHABLE_KEY;

const SUPABASE_SECRET_KEY =
  process.env.SUPABASE_SECRET_KEY;

/*
========================================
VERSÕES DA EXTENSÃO
========================================

Hoje:
V7 = versão oficial

Futuramente você poderá alterar no Render:

CURRENT_VERSION=V8
MIN_VERSION=V7
ALLOWED_VERSIONS=V7,V8

Exemplo para bloquear V7:

CURRENT_VERSION=V8
MIN_VERSION=V8
ALLOWED_VERSIONS=V8
*/

const CURRENT_VERSION =
  process.env.CURRENT_VERSION || "V7";

const MIN_VERSION =
  process.env.MIN_VERSION || "V7";

const ALLOWED_VERSIONS =
  (process.env.ALLOWED_VERSIONS || "V7")
    .split(",")
    .map(v => v.trim().toUpperCase());

const SITE_HEARTBEAT_SECONDS =
  Number(process.env.SITE_HEARTBEAT_SECONDS || 120);

if (
  !SUPABASE_URL ||
  !SUPABASE_PUBLISHABLE_KEY ||
  !SUPABASE_SECRET_KEY
) {
  console.warn(
    "ATENÇÃO: variáveis do Supabase ainda não configuradas."
  );
}

const supabasePublic = createClient(
  SUPABASE_URL || "http://localhost",
  SUPABASE_PUBLISHABLE_KEY || "missing",
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
);

const supabaseAdmin = createClient(
  SUPABASE_URL || "http://localhost",
  SUPABASE_SECRET_KEY || "missing",
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
);

app.use(cors());
app.use(express.json({ limit: "100kb" }));

function sha256(value) {
  return crypto
    .createHash("sha256")
    .update(String(value))
    .digest("hex");
}

function licenseStatus(license) {

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

  const paidUntil =
    new Date(license.paid_until);

  const graceUntil =
    new Date(license.grace_until);

  if (now <= paidUntil) {
    return {
      authorized: true,
      phase: "paid",
      paid_until: license.paid_until,
      grace_until: license.grace_until
    };
  }

  if (now <= graceUntil) {
    return {
      authorized
