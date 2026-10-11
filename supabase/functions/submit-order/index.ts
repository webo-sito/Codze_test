// Supabase Edge Function: submit-order
// Required function secrets: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
// TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, ALLOWED_ORIGIN, RATE_LIMIT_SALT
// Optional: TURNSTILE_SECRET (when enabled, client must send turnstileToken).
import { createClient } from "npm:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
const BOT_TOKEN = Deno.env.get("TELEGRAM_BOT_TOKEN") ?? "";
const CHAT_ID = Deno.env.get("TELEGRAM_CHAT_ID") ?? "";
const ALLOWED_ORIGIN = Deno.env.get("ALLOWED_ORIGIN") ?? "";
const RATE_LIMIT_SALT = Deno.env.get("RATE_LIMIT_SALT") ?? "";
const TURNSTILE_SECRET = Deno.env.get("TURNSTILE_SECRET") ?? "";

const supabase = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});
const corsHeaders = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Headers": "content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Vary": "Origin",
};

function json(body: Record<string, unknown>, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}
function text(value: unknown, max: number): string {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}
function validEmail(value: string) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(value);
}
function validPhone(value: string) {
  const digits = value.replace(/\D/g, "");
  return /^[+\d][\d\s().-]*$/.test(value) && digits.length >= 7 && digits.length <= 15;
}
async function sha256(value: string) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function verifyTurnstile(token: string, ip: string) {
  if (!TURNSTILE_SECRET) return true; // Optional until enabled by setting the server secret.
  if (!token) return false;
  const body = new URLSearchParams({ secret: TURNSTILE_SECRET, response: token });
  if (ip) body.set("remoteip", ip);
  try {
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body,
    });
    const result = await res.json();
    return res.ok && result.success === true;
  } catch {
    return false;
  }
}

Deno.serve(async (req) => {
  if (!SUPABASE_URL || !SERVICE_ROLE_KEY || !ALLOWED_ORIGIN || !RATE_LIMIT_SALT) {
    return json({ ok: false, error: "service_unavailable" }, 503);
  }
  const origin = req.headers.get("origin") ?? "";
  if (origin !== ALLOWED_ORIGIN) return json({ ok: false, error: "not_allowed" }, 403);
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
  if (req.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);

  const contentType = req.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().includes("application/json")) {
    return json({ ok: false, error: "invalid_content_type" }, 415);
  }
  const contentLength = Number(req.headers.get("content-length") ?? "0");
  if (contentLength > 12_000) return json({ ok: false, error: "payload_too_large" }, 413);

  let input: Record<string, unknown>;
  try {
    const raw = await req.text();
    if (raw.length > 12_000) return json({ ok: false, error: "payload_too_large" }, 413);
    input = JSON.parse(raw);
    if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("invalid");
  } catch {
    return json({ ok: false, error: "invalid_request" }, 400);
  }

  // Quiet honeypot field. Bots that fill it receive a generic response.
  if (text(input.website, 200)) return json({ ok: true, id: null, notification: "pending" });

  const name = text(input.name, 80);
  const contact_method = text(input.method ?? input.contact_method, 20);
  const contact = text(input.detail ?? input.contact, 80);
  const project_type = text(input.project ?? input.project_type, 20);
  const message = text(input.about ?? input.message, 600);
  const turnstileToken = text(input.turnstileToken, 2048);

  if (name.length < 2 || !["email", "whatsapp", "phone"].includes(contact_method) ||
      !contact || !["cards", "web", "menus", "brand", "other"].includes(project_type) ||
      message.length < 10) {
    return json({ ok: false, error: "invalid_fields" }, 400);
  }
  if (contact_method === "email" ? !validEmail(contact) : !validPhone(contact)) {
    return json({ ok: false, error: "invalid_contact" }, 400);
  }

  const ip = req.headers.get("cf-connecting-ip") ?? req.headers.get("x-real-ip") ?? "";
  if (!await verifyTurnstile(turnstileToken, ip)) {
    return json({ ok: false, error: "verification_failed" }, 400);
  }

  // Store only a salted SHA-256 IP fingerprint; never persist raw IP addresses.
  const ipHash = await sha256(RATE_LIMIT_SALT + ":" + (ip || "unknown"));
  const now = new Date();
  const { data: prior, error: readLimitError } = await supabase
    .from("codze_rate_limits").select("window_started_at,request_count").eq("ip_hash", ipHash).maybeSingle();
  if (readLimitError) return json({ ok: false, error: "service_unavailable" }, 503);

  if (prior && (now.getTime() - new Date(prior.window_started_at).getTime()) < 15 * 60 * 1000 &&
      prior.request_count >= 5) {
    return json({ ok: false, error: "rate_limited" }, 429);
  }
  const windowActive = prior && (now.getTime() - new Date(prior.window_started_at).getTime()) < 15 * 60 * 1000;
  const limitRow = {
    ip_hash: ipHash,
    window_started_at: windowActive ? prior.window_started_at : now.toISOString(),
    request_count: windowActive ? prior.request_count + 1 : 1,
    updated_at: now.toISOString(),
  };
  const { error: limitWriteError } = await supabase.from("codze_rate_limits").upsert(limitRow, { onConflict: "ip_hash" });
  if (limitWriteError) return json({ ok: false, error: "service_unavailable" }, 503);

  const { data: order, error: insertError } = await supabase.from("codze_orders").insert({
    name, contact_method, contact, project_type, message,
    notify_status: "pending", notify_attempts: 0,
  }).select("id,created_at").single();

  if (insertError || !order) {
    // Do not return database details to the public client.
    return json({ ok: false, error: "save_failed" }, 500);
  }

  // Telegram is attempted only after Supabase confirms the inserted order and ID.
  let notifyStatus: "sent" | "failed" = "failed";
  let errorCode = "telegram_request_failed";
  if (BOT_TOKEN && CHAT_ID) {
    const telegramText = [
      "New CODZE inquiry",
      "Order: " + order.id,
      "Name: " + name,
      "Contact method: " + contact_method,
      "Contact: " + contact,
      "Project: " + project_type,
      "Message: " + message,
      "Received: " + order.created_at,
    ].join("\n");
    try {
      const tg = await fetch("https://api.telegram.org/bot" + BOT_TOKEN + "/sendMessage", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: CHAT_ID, text: telegramText, disable_web_page_preview: true }),
        signal: AbortSignal.timeout(8000),
      });
      const tgResult = await tg.json();
      if (tg.ok && tgResult.ok === true) {
        notifyStatus = "sent";
        errorCode = "";
      } else {
        errorCode = "telegram_rejected";
      }
    } catch {
      errorCode = "telegram_network_error";
    }
  } else {
    errorCode = "telegram_not_configured";
  }

  const { error: updateError } = await supabase.from("codze_orders").update({
    notify_status: notifyStatus,
    notify_attempts: 1,
    notify_error_code: errorCode || null,
  }).eq("id", order.id);
  if (updateError) {
    // The order is still saved; status remains pending if this status update failed.
    return json({ ok: true, id: order.id, notification: "pending" });
  }
  return json({ ok: true, id: order.id, notification: notifyStatus === "sent" ? "sent" : "failed" });
});
