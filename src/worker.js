// Villa Concierge — Cloudflare Worker backend
//
// Replaces the two Claude artifact capabilities the app used to depend on
// (`db` and `sample`), which only work when the page is framed inside a
// Claude client and not for a real guest opening a public link. Everything
// here is a normal HTTP API backed by D1, plus a direct call to the
// Anthropic Messages API for the concierge replies.
//
// Routes:
//   Auth (no bearer token required):
//     POST   /api/auth/signup                   { email, password } -> { token, manager }
//     POST   /api/auth/login                    { email, password } -> { token, manager }
//     POST   /api/auth/logout
//
//   Manager (require Authorization: Bearer <session token> from signup/login).
//   Each manager only sees/manages their own villas; the very first account
//   ever created is an admin and can see every manager's villas:
//     GET    /api/auth/me                       -> { manager }
//     GET    /api/villas
//     POST   /api/villas                       { name }
//     PATCH  /api/villas/:id                    { name }
//     DELETE /api/villas/:id
//     GET    /api/villas/:id/knowledge
//     POST   /api/villas/:id/knowledge          { category, title, content, fields, photo }
//     PATCH  /api/villas/:id/knowledge/:itemId  { title, content, fields, photo }
//     DELETE /api/villas/:id/knowledge/:itemId
//     GET    /api/villas/:id/conversations
//     PATCH  /api/villas/:id/conversations/:cid { handled }
//     POST   /api/villas/:id/conversations/:cid/reply { message } — owner
//            replies in their own name, no AI call
//
//   Public (no auth — this is what a guest's browser calls):
//     GET    /api/villas/:id                    -> { id, name, slug, createdAt }
//     POST   /api/villas/:id/chat               { sessionId, message } -> { reply, answered, topic }
//
// The knowledge base itself (WiFi passwords, etc.) is NEVER sent to the
// guest's browser — it's only read server-side, here, to build the prompt.

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };

function json(data, status) {
  return new Response(JSON.stringify(data), { status: status || 200, headers: JSON_HEADERS });
}
function err(status, message) {
  return json({ error: message }, status);
}
function nowIso() {
  return new Date().toISOString();
}
function newId(prefix) {
  return (prefix ? prefix + "_" : "") + crypto.randomUUID().replace(/-/g, "");
}
function slugify(s) {
  const stripped = (s || "")
    .toLowerCase()
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");
  return stripped || "villa";
}

// ---------------------------------------------------------------------
// Manager accounts — auth (PBKDF2 password hashing + opaque session
// tokens stored in D1; replaces the old single shared MANAGER_PASSWORD).
// ---------------------------------------------------------------------
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

function bytesToHex(bytes) {
  return Array.from(bytes).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
}
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}
function randomHex(numBytes) {
  const arr = new Uint8Array(numBytes);
  crypto.getRandomValues(arr);
  return bytesToHex(arr);
}
async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: hexToBytes(saltHex), iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return bytesToHex(new Uint8Array(bits));
}
function bearerToken(request) {
  const auth = request.headers.get("authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}
async function createSession(env, managerId) {
  const token = randomHex(32);
  const ts = nowIso();
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  await env.DB.prepare("INSERT INTO sessions (token, manager_id, created_at, expires_at) VALUES (?, ?, ?, ?)")
    .bind(token, managerId, ts, expiresAt)
    .run();
  return token;
}
async function getAuthedManager(request, env) {
  const token = bearerToken(request);
  if (!token) return null;
  const row = await env.DB.prepare(
    "SELECT managers.id as id, managers.email as email, managers.phone as phone, managers.notify_email as notify_email, managers.notify_whatsapp as notify_whatsapp, managers.is_admin as is_admin, sessions.expires_at as expires_at " +
      "FROM sessions JOIN managers ON managers.id = sessions.manager_id WHERE sessions.token = ?"
  )
    .bind(token)
    .first();
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) return null;
  return {
    id: row.id,
    email: row.email,
    phone: row.phone || "",
    notifyEmail: row.notify_email === null || row.notify_email === undefined ? true : !!row.notify_email,
    notifyWhatsapp: row.notify_whatsapp === null || row.notify_whatsapp === undefined ? true : !!row.notify_whatsapp,
    isAdmin: !!row.is_admin,
  };
}
async function updateManagerProfile(env, managerId, body) {
  const raw = String(body.phone || "").trim();
  if (raw && !/^\+[1-9]\d{7,14}$/.test(raw)) {
    return err(400, "phone must be in international format, e.g. +33612345678");
  }
  const notifyEmail = body.notifyEmail === undefined ? true : !!body.notifyEmail;
  const notifyWhatsapp = body.notifyWhatsapp === undefined ? true : !!body.notifyWhatsapp;
  await env.DB.prepare("UPDATE managers SET phone = ?, notify_email = ?, notify_whatsapp = ? WHERE id = ?")
    .bind(raw || null, notifyEmail ? 1 : 0, notifyWhatsapp ? 1 : 0, managerId)
    .run();
  return json({ ok: true, phone: raw, notifyEmail: notifyEmail, notifyWhatsapp: notifyWhatsapp });
}
async function requireAuth(request, env) {
  const manager = await getAuthedManager(request, env);
  if (!manager) return { manager: null, errorResponse: err(401, "unauthorized") };
  return { manager: manager, errorResponse: null };
}
async function loadVillaForManager(env, villaId, manager) {
  const row = await env.DB.prepare("SELECT * FROM villas WHERE id = ?").bind(villaId).first();
  if (!row) return { villa: null, errorResponse: err(404, "villa not found") };
  if (!manager.isAdmin && row.manager_id !== manager.id) {
    return { villa: null, errorResponse: err(403, "forbidden") };
  }
  return { villa: row, errorResponse: null };
}
async function signup(env, body) {
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return err(400, "a valid email is required");
  if (password.length < 8) return err(400, "password must be at least 8 characters");
  const existing = await env.DB.prepare("SELECT id FROM managers WHERE email = ?").bind(email).first();
  if (existing) return err(409, "an account with this email already exists");
  // The very first manager to sign up becomes the admin (Maxime's global
  // account); everyone after that is a regular, villa-scoped manager.
  const countRow = await env.DB.prepare("SELECT COUNT(*) as n FROM managers").first();
  const isAdmin = countRow && countRow.n === 0 ? 1 : 0;
  const salt = randomHex(16);
  const hash = await hashPassword(password, salt);
  const id = newId("mgr");
  const ts = nowIso();
  await env.DB.prepare(
    "INSERT INTO managers (id, email, password_hash, password_salt, is_admin, created_at) VALUES (?, ?, ?, ?, ?, ?)"
  )
    .bind(id, email, hash, salt, isAdmin, ts)
    .run();
  const token = await createSession(env, id);
  return json({ token: token, manager: { id: id, email: email, phone: "", notifyEmail: true, notifyWhatsapp: true, isAdmin: !!isAdmin } }, 201);
}
async function login(env, body) {
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  const row = await env.DB.prepare("SELECT * FROM managers WHERE email = ?").bind(email).first();
  if (!row) return err(401, "invalid email or password");
  const hash = await hashPassword(password, row.password_salt);
  if (hash !== row.password_hash) return err(401, "invalid email or password");
  const token = await createSession(env, row.id);
  return json({
    token: token,
    manager: {
      id: row.id,
      email: row.email,
      phone: row.phone || "",
      notifyEmail: row.notify_email === null || row.notify_email === undefined ? true : !!row.notify_email,
      notifyWhatsapp: row.notify_whatsapp === null || row.notify_whatsapp === undefined ? true : !!row.notify_whatsapp,
      isAdmin: !!row.is_admin,
    },
  });
}
async function logout(env, request) {
  const token = bearerToken(request);
  if (token) await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
  return json({ ok: true });
}

async function readJson(request) {
  try {
    return await request.json();
  } catch (e) {
    return {};
  }
}

// ---------------------------------------------------------------------
// Knowledge base -> concierge system prompt (ported from the client code)
// ---------------------------------------------------------------------
const CATEGORY_LABELS = {
  general: "Informations générales",
  location: "Adresse et localisation",
  checkinout: "Check-in / Check-out",
  wifi: "WiFi",
  rules: "Règles de la villa",
  pets: "Animaux de compagnie",
  equipment: "Équipements",
  appliances: "Appareils électroménagers",
  ac: "Climatisation",
  entertainment: "TV / Divertissement",
  pool: "Piscine",
  services: "Services disponibles",
  housekeeping: "Housekeeping",
  recommendations: "Recommandations locales",
  supermarkets: "Supermarchés",
  beaches: "Plages",
  transport: "Transports",
  contacts: "Contacts importants",
  emergency: "Informations d'urgence",
  custom: "Questions personnalisées",
};
const CATEGORY_ORDER = Object.keys(CATEGORY_LABELS);

function localeLanguageName(locale) {
  if (!locale) return "";
  try {
    const dn = new Intl.DisplayNames(["en"], { type: "language" });
    return dn.of(locale) || "";
  } catch (e) {
    return "";
  }
}

function buildSystemPrompt(villa, items, locale) {
  const byCat = {};
  for (const c of CATEGORY_ORDER) byCat[c] = [];
  for (const it of items) {
    if (!byCat[it.category]) byCat[it.category] = [];
    byCat[it.category].push(it);
  }
  const lines = [];
  lines.push(
    `You are the virtual concierge for the villa "${villa.name}" in Bali, Indonesia. You help guests only using the information listed below.`
  );
  lines.push("");
  lines.push("RULES:");
  lines.push(
    "- Use only the information below about this villa. Never invent, assume or guess any detail about the villa, its equipment, its policies, or its surroundings."
  );
  lines.push(
    "- If the guest asks something that is not covered below, say clearly and politely that you don't have that information. Their question is automatically forwarded to the villa manager the moment you say this, so state that as a fact that has already happened (e.g. \"I've passed your question on to the manager, who will get back to you\") — never phrase it as something you could do or are offering to do (never say \"I can pass this along\" or \"let me relay this\"). Never guess to fill a gap."
  );
  const langName = localeLanguageName(locale);
  lines.push(
    langName
      ? "- Always reply in the same language the guest is writing in. For the guest's very first message, if the language isn't clear from the text alone (e.g. a short greeting or a single word), default to " +
          langName +
          " — the guest's device language. The moment the guest actually writes in a different language, switch to match them for the rest of the conversation."
      : "- Always reply in the same language the guest is writing in. If it's ambiguous, reply in English."
  );
  lines.push(
    "- Sound like a warm, attentive on-site concierge: concise and natural, short answers over long paragraphs. Never mention that you are an AI, a bot, or a language model."
  );
  lines.push("- Ordinary conversational messages (greetings, thanks, small talk) can be answered naturally even if not covered below.");
  lines.push("");
  lines.push("VILLA INFORMATION:");
  let hasAny = false;
  for (const c of CATEGORY_ORDER) {
    const list = byCat[c] || [];
    if (!list.length) continue;
    hasAny = true;
    lines.push("");
    lines.push("## " + CATEGORY_LABELS[c]);
    for (const it of list) {
      const title = String(it.title || "").slice(0, 200);
      const content = String(it.content || "").slice(0, 1200);
      lines.push("- " + title + ": " + content);
    }
  }
  if (!hasAny) lines.push("(No information has been entered for this villa yet.)");
  lines.push("");
  lines.push(
    'Respond ONLY with a compact JSON object on one line, no markdown fences: {"reply": string (your message to the guest, written in the guest\'s own language), "answered": boolean (true only if your reply used the villa information above; false if you said you don\'t have the information), "topic": one short string, one of [' +
      CATEGORY_ORDER.join(", ") +
      ", other]}"
  );
  return lines.join("\n").slice(0, 24000);
}

function parseLenientJson(text) {
  const raw = (text || "").trim();
  try {
    return JSON.parse(raw);
  } catch (e) {}
  const fence = raw.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) {
    try {
      return JSON.parse(fence[1].trim());
    } catch (e) {}
  }
  const firstObj = raw.indexOf("{");
  const lastObj = raw.lastIndexOf("}");
  if (firstObj !== -1 && lastObj > firstObj) {
    try {
      return JSON.parse(raw.slice(firstObj, lastObj + 1));
    } catch (e) {}
  }
  return null;
}

async function askClaude(env, systemPrompt, turns) {
  if (!env.ANTHROPIC_API_KEY) {
    const e = new Error("Server is missing ANTHROPIC_API_KEY.");
    e.code = "not_configured";
    throw e;
  }
  const resp = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "x-api-key": env.ANTHROPIC_API_KEY,
      "anthropic-version": "2023-06-01",
      "content-type": "application/json",
    },
    body: JSON.stringify({
      model: "claude-haiku-4-5-20251001",
      max_tokens: 1024,
      system: systemPrompt,
      messages: turns,
    }),
  });
  if (!resp.ok) {
    const bodyText = await resp.text().catch(() => "");
    const e = new Error("Anthropic API error " + resp.status + ": " + bodyText.slice(0, 500));
    e.code = resp.status === 429 ? "rate_limited" : "upstream_error";
    throw e;
  }
  const data = await resp.json();
  const text = (data.content || []).map((b) => b.text || "").join("");
  if (!text.trim()) {
    const e = new Error("Empty completion");
    e.code = "empty_completion";
    throw e;
  }
  return text;
}

// ---------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------

async function listVillas(env, manager) {
  const stmt = manager.isAdmin
    ? env.DB.prepare(
        "SELECT villas.*, managers.email as owner_email FROM villas LEFT JOIN managers ON managers.id = villas.manager_id ORDER BY villas.created_at DESC"
      )
    : env.DB.prepare("SELECT * FROM villas WHERE manager_id = ? ORDER BY created_at DESC").bind(manager.id);
  const { results } = await stmt.all();
  return json(results.map(rowToVilla));
}
function rowToVilla(r) {
  const out = { id: r.id, name: r.name, slug: r.slug, createdAt: r.created_at, updatedAt: r.updated_at };
  if (r.owner_email) out.ownerEmail = r.owner_email;
  return out;
}

async function createVilla(env, manager, body) {
  const name = (body.name || "").trim();
  if (!name) return err(400, "name is required");
  const id = newId("villa");
  const ts = nowIso();
  await env.DB.prepare(
    "INSERT INTO villas (id, name, slug, manager_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
  )
    .bind(id, name, slugify(name), manager.id, ts, ts)
    .run();
  return json({ id, name, slug: slugify(name), createdAt: ts, updatedAt: ts }, 201);
}

async function getVillaPublic(env, villaId) {
  const row = await env.DB.prepare("SELECT id, name, slug, created_at FROM villas WHERE id = ?")
    .bind(villaId)
    .first();
  if (!row) return err(404, "villa not found");
  return json({ id: row.id, name: row.name, slug: row.slug, createdAt: row.created_at });
}

async function updateVilla(env, villaId, body) {
  const name = (body.name || "").trim();
  if (!name) return err(400, "name is required");
  const ts = nowIso();
  const res = await env.DB.prepare("UPDATE villas SET name = ?, slug = ?, updated_at = ? WHERE id = ?")
    .bind(name, slugify(name), ts, villaId)
    .run();
  if (!res.meta.changes) return err(404, "villa not found");
  return json({ ok: true });
}

async function deleteVilla(env, villaId) {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM knowledge_items WHERE villa_id = ?").bind(villaId),
    env.DB.prepare("DELETE FROM conversations WHERE villa_id = ?").bind(villaId),
    env.DB.prepare("DELETE FROM villas WHERE id = ?").bind(villaId),
  ]);
  return json({ ok: true });
}

async function listKnowledge(env, villaId) {
  const { results } = await env.DB.prepare(
    "SELECT * FROM knowledge_items WHERE villa_id = ? ORDER BY item_order ASC"
  )
    .bind(villaId)
    .all();
  return json(results.map(rowToKnowledge));
}
function rowToKnowledge(r) {
  let fields = {};
  try {
    fields = JSON.parse(r.fields_json || "{}");
  } catch (e) {}
  return {
    id: r.id,
    category: r.category,
    title: r.title,
    content: r.content,
    fields,
    photo: r.photo || null,
    order: r.item_order,
    createdAt: r.created_at,
  };
}

async function addKnowledge(env, villaId, body) {
  const id = newId("kb");
  const ts = nowIso();
  await env.DB.prepare(
    "INSERT INTO knowledge_items (id, villa_id, category, title, content, fields_json, photo, item_order, created_at) VALUES (?,?,?,?,?,?,?,?,?)"
  )
    .bind(
      id,
      villaId,
      body.category || "general",
      body.title || "(sans titre)",
      body.content || "",
      JSON.stringify(body.fields || {}),
      body.photo || null,
      typeof body.order === "number" ? body.order : Date.now(),
      ts
    )
    .run();
  return json({ id }, 201);
}

async function updateKnowledge(env, villaId, itemId, body) {
  const res = await env.DB.prepare(
    "UPDATE knowledge_items SET title = ?, content = ?, fields_json = ?, photo = ? WHERE id = ? AND villa_id = ?"
  )
    .bind(
      body.title || "(sans titre)",
      body.content || "",
      JSON.stringify(body.fields || {}),
      body.photo || null,
      itemId,
      villaId
    )
    .run();
  if (!res.meta.changes) return err(404, "item not found");
  return json({ ok: true });
}

async function deleteKnowledge(env, villaId, itemId) {
  await env.DB.prepare("DELETE FROM knowledge_items WHERE id = ? AND villa_id = ?").bind(itemId, villaId).run();
  return json({ ok: true });
}

async function listConversations(env, villaId) {
  const { results } = await env.DB.prepare(
    "SELECT * FROM conversations WHERE villa_id = ? ORDER BY updated_at DESC LIMIT 200"
  )
    .bind(villaId)
    .all();
  return json(results.map(rowToConversation));
}
function rowToConversation(r) {
  let messages = [];
  try {
    messages = JSON.parse(r.messages_json || "[]");
  } catch (e) {}
  return {
    id: r.id,
    sessionId: r.session_id,
    startedAt: r.started_at,
    updatedAt: r.updated_at,
    messages,
    needsHuman: !!r.needs_human,
    handled: !!r.handled,
  };
}

async function addManagerReply(env, villaId, convoId, body) {
  const message = String(body.message || "").trim().slice(0, 4000);
  if (!message) return err(400, "message is required");
  const row = await env.DB.prepare("SELECT * FROM conversations WHERE id = ? AND villa_id = ?")
    .bind(convoId, villaId)
    .first();
  if (!row) return err(404, "conversation not found");
  let messages = [];
  try {
    messages = JSON.parse(row.messages_json || "[]");
  } catch (e) {}
  const managerMsg = { role: "manager", content: message, ts: nowIso() };
  const newMessages = messages.concat([managerMsg]);
  const ts = nowIso();
  // A reply from the manager counts as the conversation having been taken
  // care of by a human, so clear the "needs attention" flag. `handled` stays
  // a separate, manually-toggled marker.
  await env.DB.prepare("UPDATE conversations SET messages_json = ?, updated_at = ?, needs_human = 0 WHERE id = ?")
    .bind(JSON.stringify(newMessages), ts, row.id)
    .run();
  return json({ ok: true });
}

async function updateConversationHandled(env, villaId, convoId, body) {
  const res = await env.DB.prepare(
    "UPDATE conversations SET handled = ? WHERE id = ? AND villa_id = ?"
  )
    .bind(body.handled ? 1 : 0, convoId, villaId)
    .run();
  if (!res.meta.changes) return err(404, "conversation not found");
  return json({ ok: true });
}

async function getSession(env, villaId, sessionId) {
  const row = await env.DB.prepare(
    "SELECT messages_json FROM conversations WHERE villa_id = ? AND session_id = ?"
  )
    .bind(villaId, sessionId)
    .first();
  if (!row) return json({ messages: [] });
  let messages = [];
  try {
    messages = JSON.parse(row.messages_json || "[]");
  } catch (e) {}
  return json({ messages });
}

function escapeHtml(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}

// Best-effort email to the manager when the concierge can't answer a guest
// on its own. Silently does nothing if RESEND_API_KEY isn't configured yet,
// so it never breaks the guest's chat.
async function sendManagerAlertEmail(env, toEmail, villaName, question, conversationUrl) {
  if (!env.RESEND_API_KEY || !toEmail) return;
  try {
    await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        authorization: "Bearer " + env.RESEND_API_KEY,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        from: env.RESEND_FROM || "Villa Concierge <onboarding@resend.dev>",
        to: [toEmail],
        subject: "Question d'un guest — " + villaName,
        html:
          "<p>Un guest de <strong>" + escapeHtml(villaName) + "</strong> a posé une question à laquelle le concierge virtuel n'a pas pu répondre seul :</p>" +
          '<blockquote style="margin:12px 0;padding:10px 14px;background:#f4f4f5;border-left:3px solid #999;">' +
          escapeHtml(question) +
          "</blockquote>" +
          '<p><a href="' + conversationUrl + '">Voir la conversation et répondre</a></p>',
      }),
    });
  } catch (e) {
    // Notification failures should never break the guest-facing chat.
  }
}

// WhatsApp template variables can't contain newlines, can't start/end with
// whitespace, and shouldn't run on forever — clean the guest's question up
// before it goes into {{2}}.
function sanitizeWhatsAppVariable(value, maxLen) {
  var cleaned = String(value == null ? "" : value)
    .replace(/[\r\n\t]+/g, " ")
    .replace(/ {2,}/g, " ")
    .trim();
  if (maxLen && cleaned.length > maxLen) cleaned = cleaned.slice(0, maxLen - 1) + "…";
  return cleaned;
}

async function sendManagerWhatsAppAlert(env, toPhone, villaName, question, convoId) {
  if (
    !env.TWILIO_ACCOUNT_SID ||
    !env.TWILIO_AUTH_TOKEN ||
    !env.TWILIO_WHATSAPP_FROM ||
    !env.TWILIO_WHATSAPP_CONTENT_SID ||
    !toPhone
  ) {
    console.log("WhatsApp alert skipped — missing config:", {
      hasAccountSid: !!env.TWILIO_ACCOUNT_SID,
      hasAuthToken: !!env.TWILIO_AUTH_TOKEN,
      hasFromNumber: !!env.TWILIO_WHATSAPP_FROM,
      hasContentSid: !!env.TWILIO_WHATSAPP_CONTENT_SID,
      hasToPhone: !!toPhone,
    });
    return;
  }
  try {
    const form = new URLSearchParams({
      From: "whatsapp:" + env.TWILIO_WHATSAPP_FROM,
      To: "whatsapp:" + toPhone,
      ContentSid: env.TWILIO_WHATSAPP_CONTENT_SID,
      // "3" is only the conversation id here — the WhatsApp button URL is
      // "https://.../c/{{3}}" and the Worker's /c/:id route redirects to
      // the real, longer app link. WhatsApp button variables can't contain
      // a full URL of their own.
      ContentVariables: JSON.stringify({
        "1": sanitizeWhatsAppVariable(villaName, 80),
        "2": sanitizeWhatsAppVariable(question, 300),
        "3": sanitizeWhatsAppVariable(convoId, 100),
      }),
    });
    const auth = btoa(env.TWILIO_ACCOUNT_SID + ":" + env.TWILIO_AUTH_TOKEN);
    const res = await fetch("https://api.twilio.com/2010-04-01/Accounts/" + env.TWILIO_ACCOUNT_SID + "/Messages.json", {
      method: "POST",
      headers: {
        authorization: "Basic " + auth,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: form.toString(),
    });
    if (!res.ok) {
      const text = await res.text().catch(function () { return ""; });
      console.error("WhatsApp alert rejected by Twilio:", res.status, text);
    } else {
      console.log("WhatsApp alert sent to", toPhone);
    }
  } catch (e) {
    console.error("WhatsApp alert threw:", e && e.message);
  }
}

async function notifyManagerUnanswered(env, villa, question, convoId, baseUrl) {
  try {
    let contact = null;
    if (villa.manager_id) {
      contact = await env.DB.prepare("SELECT email, phone, notify_email, notify_whatsapp FROM managers WHERE id = ?").bind(villa.manager_id).first();
    }
    if (!contact) {
      // Villas created before manager accounts existed have no manager_id —
      // fall back to notifying the admin account instead of no one.
      contact = await env.DB.prepare("SELECT email, phone, notify_email, notify_whatsapp FROM managers WHERE is_admin = 1 ORDER BY created_at ASC LIMIT 1").first();
    }
    if (!contact || !baseUrl) return;
    const conversationUrl = baseUrl + "/app#screen=villa&villa=" + villa.id + "&tab=conversations&convo=" + convoId;
    const wantsEmail = contact.notify_email === null || contact.notify_email === undefined ? true : !!contact.notify_email;
    const wantsWhatsapp = contact.notify_whatsapp === null || contact.notify_whatsapp === undefined ? true : !!contact.notify_whatsapp;
    await Promise.all([
      contact.email && wantsEmail ? sendManagerAlertEmail(env, contact.email, villa.name, question, conversationUrl) : Promise.resolve(),
      contact.phone && wantsWhatsapp ? sendManagerWhatsAppAlert(env, contact.phone, villa.name, question, convoId) : Promise.resolve(),
    ]);
  } catch (e) {
    // Best-effort — never let this break the guest's chat.
  }
}

async function chat(env, villaId, body, baseUrl) {
  const sessionId = String(body.sessionId || "").slice(0, 200);
  const message = String(body.message || "").trim().slice(0, 4000);
  const locale = String(body.locale || "").slice(0, 35);
  if (!sessionId || !message) return err(400, "sessionId and message are required");

  const villa = await env.DB.prepare("SELECT id, name, manager_id FROM villas WHERE id = ?").bind(villaId).first();
  if (!villa) return err(404, "villa not found");

  const { results: items } = await env.DB.prepare(
    "SELECT category, title, content FROM knowledge_items WHERE villa_id = ? ORDER BY item_order ASC"
  )
    .bind(villaId)
    .all();

  let convoRow = await env.DB.prepare(
    "SELECT * FROM conversations WHERE villa_id = ? AND session_id = ?"
  )
    .bind(villaId, sessionId)
    .first();
  let messages = convoRow ? JSON.parse(convoRow.messages_json || "[]") : [];
  const convoId = convoRow ? convoRow.id : newId("convo");

  const userMsg = { role: "user", content: message, ts: nowIso() };
  const historyForPrompt = messages.slice(-16);
  const turns = historyForPrompt
    .concat([userMsg])
    .map((m) => ({ role: m.role, content: m.content }));

  const systemPrompt = buildSystemPrompt(villa, items, locale);

  let reply, answered, topic;
  try {
    const raw = await askClaude(env, systemPrompt, turns);
    const result = parseLenientJson(raw);
    reply =
      result && typeof result.reply === "string" && result.reply.trim()
        ? result.reply
        : raw || "Sorry, I didn't quite catch that — could you rephrase?";
    answered = !!(result && result.answered);
    topic = (result && result.topic) || "other";
  } catch (e) {
    return err(e.code === "rate_limited" ? 429 : 502, e.message || "The concierge is unavailable right now.");
  }

  const assistantMsg = { role: "assistant", content: reply, ts: nowIso(), answered, topic };
  const newMessages = messages.concat([userMsg, assistantMsg]);
  const ts = nowIso();

  if (convoRow) {
    // The flag reflects only the latest exchange: it clears the moment the
    // AI manages to answer on its own, and is set again the moment it asks
    // for the manager's help — it is not sticky across turns.
    await env.DB.prepare(
      "UPDATE conversations SET messages_json = ?, updated_at = ?, needs_human = ? WHERE id = ?"
    )
      .bind(JSON.stringify(newMessages), ts, answered ? 0 : 1, convoId)
      .run();
  } else {
    await env.DB.prepare(
      "INSERT INTO conversations (id, villa_id, session_id, started_at, updated_at, messages_json, needs_human, handled) VALUES (?,?,?,?,?,?,?,0)"
    )
      .bind(convoId, villaId, sessionId, ts, ts, JSON.stringify(newMessages), answered ? 0 : 1)
      .run();
  }

  // Let the manager know by email the moment the concierge can't answer on
  // its own, with the guest's question and a direct link to the conversation.
  if (!answered) {
    await notifyManagerUnanswered(env, villa, message, convoId, baseUrl);
  }

  return json({ reply, answered, topic });
}

// ---------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Short link sent in WhatsApp manager alerts. A WhatsApp button URL
    // can only carry one dynamic value, appended at the very end of a
    // fixed base URL, so the template links here with just the
    // conversation id and this route resolves it to the real app screen.
    if (path.indexOf("/c/") === 0) {
      const shortConvoId = path.slice(3);
      const convoRow = shortConvoId
        ? await env.DB.prepare("SELECT villa_id FROM conversations WHERE id = ?").bind(shortConvoId).first()
        : null;
      const dest = convoRow
        ? url.origin + "/app#screen=villa&villa=" + convoRow.villa_id + "&tab=conversations&convo=" + shortConvoId
        : url.origin;
      return Response.redirect(dest, 302);
    }

    if (!path.startsWith("/api/")) {
      return env.ASSETS.fetch(request);
    }

    try {
      const parts = path.split("/").filter(Boolean); // ["api", "villas", ":id", ...]

      // /api/auth/signup   { email, password }
      if (parts[1] === "auth" && parts[2] === "signup" && request.method === "POST") {
        return await signup(env, await readJson(request));
      }
      // /api/auth/login    { email, password }
      if (parts[1] === "auth" && parts[2] === "login" && request.method === "POST") {
        return await login(env, await readJson(request));
      }
      // /api/auth/logout
      if (parts[1] === "auth" && parts[2] === "logout" && request.method === "POST") {
        return await logout(env, request);
      }
      // /api/auth/me  -> current manager, or 401
      //   PATCH { phone } -> update the current manager's WhatsApp number
      if (parts[1] === "auth" && parts[2] === "me") {
        const auth = await requireAuth(request, env);
        if (auth.errorResponse) return auth.errorResponse;
        if (request.method === "GET") return json({ manager: auth.manager });
        if (request.method === "PATCH") return await updateManagerProfile(env, auth.manager.id, await readJson(request));
        return err(405, "method not allowed");
      }

      if (parts[1] === "villas") {
        const villaId = parts[2];

        // /api/villas
        if (!villaId) {
          if (request.method === "GET") {
            const auth = await requireAuth(request, env);
            return auth.errorResponse || (await listVillas(env, auth.manager));
          }
          if (request.method === "POST") {
            const auth = await requireAuth(request, env);
            return auth.errorResponse || (await createVilla(env, auth.manager, await readJson(request)));
          }
          return err(405, "method not allowed");
        }

        const sub = parts[3];

        // /api/villas/:id
        if (!sub) {
          if (request.method === "GET") return await getVillaPublic(env, villaId);
          if (request.method === "PATCH") {
            const auth = await requireAuth(request, env);
            if (auth.errorResponse) return auth.errorResponse;
            const owns = await loadVillaForManager(env, villaId, auth.manager);
            if (owns.errorResponse) return owns.errorResponse;
            return await updateVilla(env, villaId, await readJson(request));
          }
          if (request.method === "DELETE") {
            const auth = await requireAuth(request, env);
            if (auth.errorResponse) return auth.errorResponse;
            const owns = await loadVillaForManager(env, villaId, auth.manager);
            if (owns.errorResponse) return owns.errorResponse;
            return await deleteVilla(env, villaId);
          }
          return err(405, "method not allowed");
        }

        // /api/villas/:id/chat  (public)
        if (sub === "chat" && request.method === "POST") {
          return await chat(env, villaId, await readJson(request), url.origin);
        }

        // /api/villas/:id/session/:sessionId  (public, read-only — lets a
        // guest resume their own conversation after a page reload)
        if (sub === "session" && parts[4] && request.method === "GET") {
          return await getSession(env, villaId, parts[4]);
        }

        // /api/villas/:id/knowledge[...]  (manager only, own villas)
        if (sub === "knowledge") {
          const auth = await requireAuth(request, env);
          if (auth.errorResponse) return auth.errorResponse;
          const owns = await loadVillaForManager(env, villaId, auth.manager);
          if (owns.errorResponse) return owns.errorResponse;
          const itemId = parts[4];
          if (!itemId) {
            if (request.method === "GET") return await listKnowledge(env, villaId);
            if (request.method === "POST") return await addKnowledge(env, villaId, await readJson(request));
            return err(405, "method not allowed");
          }
          if (request.method === "PATCH") return await updateKnowledge(env, villaId, itemId, await readJson(request));
          if (request.method === "DELETE") return await deleteKnowledge(env, villaId, itemId);
          return err(405, "method not allowed");
        }

        // /api/villas/:id/conversations[...]  (manager only, own villas)
        if (sub === "conversations") {
          const auth = await requireAuth(request, env);
          if (auth.errorResponse) return auth.errorResponse;
          const owns = await loadVillaForManager(env, villaId, auth.manager);
          if (owns.errorResponse) return owns.errorResponse;
          const convoId = parts[4];
          if (!convoId) {
            if (request.method === "GET") return await listConversations(env, villaId);
            return err(405, "method not allowed");
          }
          const convoSub = parts[5];
          if (!convoSub) {
            if (request.method === "PATCH") return await updateConversationHandled(env, villaId, convoId, await readJson(request));
            return err(405, "method not allowed");
          }
          if (convoSub === "reply" && request.method === "POST") {
            return await addManagerReply(env, villaId, convoId, await readJson(request));
          }
          return err(404, "not found");
        }
      }

      return err(404, "not found");
    } catch (e) {
      return err(500, (e && e.message) || "internal error");
    }
  },
};
