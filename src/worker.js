// Villa Concierge — Cloudflare Worker backend
//
// Replaces the two Claude artifact capabilities the app used to depend on
// (`db` and `sample`), which only work when the page is framed inside a
// Claude client and not for a real guest opening a public link. Everything
// here is a normal HTTP API backed by D1, plus a direct call to the
// Anthropic Messages API for the concierge replies.
//
// Routes:
//   Manager (require Authorization: Bearer <MANAGER_PASSWORD>):
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
//     POST   /api/auth/check                    (any body) — 200 if the bearer token is valid
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

function isAuthed(request, env) {
  if (!env.MANAGER_PASSWORD) return false;
  const auth = request.headers.get("authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  return !!m && m[1] === env.MANAGER_PASSWORD;
}
function requireAuth(request, env) {
  if (!isAuthed(request, env)) return err(401, "unauthorized");
  return null;
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

function buildSystemPrompt(villa, items) {
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
    "- If the guest asks something that is not covered below, say clearly and politely that you don't have that information, and offer to relay the question to the villa manager. Never guess to fill a gap."
  );
  lines.push("- Always reply in the same language the guest is writing in. If it's ambiguous, reply in English.");
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

async function listVillas(env) {
  const { results } = await env.DB.prepare(
    "SELECT id, name, slug, created_at, updated_at FROM villas ORDER BY created_at DESC"
  ).all();
  return json(results.map(rowToVilla));
}
function rowToVilla(r) {
  return { id: r.id, name: r.name, slug: r.slug, createdAt: r.created_at, updatedAt: r.updated_at };
}

async function createVilla(env, body) {
  const name = (body.name || "").trim();
  if (!name) return err(400, "name is required");
  const id = newId("villa");
  const ts = nowIso();
  await env.DB.prepare(
    "INSERT INTO villas (id, name, slug, created_at, updated_at) VALUES (?, ?, ?, ?, ?)"
  )
    .bind(id, name, slugify(name), ts, ts)
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

async function chat(env, villaId, body) {
  const sessionId = String(body.sessionId || "").slice(0, 200);
  const message = String(body.message || "").trim().slice(0, 4000);
  if (!sessionId || !message) return err(400, "sessionId and message are required");

  const villa = await env.DB.prepare("SELECT id, name FROM villas WHERE id = ?").bind(villaId).first();
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

  const userMsg = { role: "user", content: message, ts: nowIso() };
  const historyForPrompt = messages.slice(-16);
  const turns = historyForPrompt
    .concat([userMsg])
    .map((m) => ({ role: m.role, content: m.content }));

  const systemPrompt = buildSystemPrompt(villa, items);

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
    const prevNeeds = !!convoRow.needs_human;
    await env.DB.prepare(
      "UPDATE conversations SET messages_json = ?, updated_at = ?, needs_human = ? WHERE id = ?"
    )
      .bind(JSON.stringify(newMessages), ts, prevNeeds || !answered ? 1 : 0, convoRow.id)
      .run();
  } else {
    await env.DB.prepare(
      "INSERT INTO conversations (id, villa_id, session_id, started_at, updated_at, messages_json, needs_human, handled) VALUES (?,?,?,?,?,?,?,0)"
    )
      .bind(newId("convo"), villaId, sessionId, ts, ts, JSON.stringify(newMessages), answered ? 0 : 1)
      .run();
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

    if (!path.startsWith("/api/")) {
      return env.ASSETS.fetch(request);
    }

    try {
      const parts = path.split("/").filter(Boolean); // ["api", "villas", ":id", ...]

      // /api/auth/check
      if (parts[1] === "auth" && parts[2] === "check") {
        const authErr = requireAuth(request, env);
        return authErr || json({ ok: true });
      }

      if (parts[1] === "villas") {
        const villaId = parts[2];

        // /api/villas
        if (!villaId) {
          if (request.method === "GET") {
            const authErr = requireAuth(request, env);
            return authErr || (await listVillas(env));
          }
          if (request.method === "POST") {
            const authErr = requireAuth(request, env);
            return authErr || (await createVilla(env, await readJson(request)));
          }
          return err(405, "method not allowed");
        }

        const sub = parts[3];

        // /api/villas/:id
        if (!sub) {
          if (request.method === "GET") return await getVillaPublic(env, villaId);
          if (request.method === "PATCH") {
            const authErr = requireAuth(request, env);
            return authErr || (await updateVilla(env, villaId, await readJson(request)));
          }
          if (request.method === "DELETE") {
            const authErr = requireAuth(request, env);
            return authErr || (await deleteVilla(env, villaId));
          }
          return err(405, "method not allowed");
        }

        // /api/villas/:id/chat  (public)
        if (sub === "chat" && request.method === "POST") {
          return await chat(env, villaId, await readJson(request));
        }

        // /api/villas/:id/session/:sessionId  (public, read-only — lets a
        // guest resume their own conversation after a page reload)
        if (sub === "session" && parts[4] && request.method === "GET") {
          return await getSession(env, villaId, parts[4]);
        }

        // /api/villas/:id/knowledge[...]  (manager only)
        if (sub === "knowledge") {
          const authErr = requireAuth(request, env);
          if (authErr) return authErr;
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

        // /api/villas/:id/conversations[...]  (manager only)
        if (sub === "conversations") {
          const authErr = requireAuth(request, env);
          if (authErr) return authErr;
          const convoId = parts[4];
          if (!convoId) {
            if (request.method === "GET") return await listConversations(env, villaId);
            return err(405, "method not allowed");
          }
          if (request.method === "PATCH") return await updateConversationHandled(env, villaId, convoId, await readJson(request));
          return err(405, "method not allowed");
        }
      }

      return err(404, "not found");
    } catch (e) {
      return err(500, (e && e.message) || "internal error");
    }
  },
};
