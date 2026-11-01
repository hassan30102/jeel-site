// Cloudflare Pages Function: /api/works
// GET: آخر 100 عمل معتمد (ومع ?all=1 وبمفتاح المشرف تظهر الأعمال المنتظرة أيضاً)، POST: إضافة عمل بحالة «قيد المراجعة»،
// PATCH: بمفتاح المشرف، ?action=approve (اعتماد، وهو الافتراضي) أو feature / unfeature (تمييز العمل المعتمد)، DELETE: حذف بمفتاح المشرف.
// المتطلبات: KV باسم WORKS_KV، وسر ADMIN_KEY، واختيارياً FORWARD_URL وFORWARD_SECRET.

const TYPE_MAP = {
  "إنفوجرافيك": "infographic",
  "فيديو": "video",
  "خريطة": "map",
  "تقرير تقييم": "report",
  "صور": "image"
};

const ALLOWED_GRADES = new Set(["الصف العاشر", "الصف الحادي عشر", "الصف الثاني عشر"]);
const HOSTS = [
  "drive.google.com",
  "docs.google.com",
  "1drv.ms",
  "onedrive.live.com",
  "sharepoint.com",
  "youtube.com",
  "youtu.be"
];

const MAX_BODY_BYTES = 4096;
const RATE_LIMIT_MAX = 10;
const RATE_LIMIT_WINDOW_SECONDS = 10 * 60;

const SECURITY_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer"
};

const json = (data, status = 200, extraHeaders = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { ...SECURITY_HEADERS, ...extraHeaders }
  });

const clip = (value, max) => String(value ?? "").trim().slice(0, max);

function isAllowedUrl(value) {
  let url;
  try {
    url = new URL(clip(value, 250));
  } catch {
    return null;
  }
  const host = url.hostname.toLowerCase();
  const allowedHost = HOSTS.some((item) => host === item || host.endsWith(`.${item}`));
  if (url.protocol !== "https:" || !allowedHost || url.username || url.password) return null;
  return url;
}

function sameOriginWhenProvided(request) {
  const origin = request.headers.get("Origin");
  if (!origin) return true;
  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

async function sha256Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function takeRateLimitSlot(request, env) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const fingerprint = await sha256Hex(ip);
  const window = Math.floor(Date.now() / (RATE_LIMIT_WINDOW_SECONDS * 1000));
  const key = `rl:${fingerprint}:${window}`;
  const count = Number(await env.WORKS_KV.get(key)) || 0;

  if (count >= RATE_LIMIT_MAX) {
    const retryAfter = RATE_LIMIT_WINDOW_SECONDS - Math.floor((Date.now() / 1000) % RATE_LIMIT_WINDOW_SECONDS);
    return { allowed: false, retryAfter };
  }

  await env.WORKS_KV.put(key, String(count + 1), {
    expirationTtl: RATE_LIMIT_WINDOW_SECONDS + 60
  });
  return { allowed: true };
}

function safeSecretEqual(left, right) {
  const a = String(left || "");
  const b = String(right || "");
  let diff = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i += 1) {
    diff |= (a.charCodeAt(i % Math.max(a.length, 1)) || 0) ^ (b.charCodeAt(i % Math.max(b.length, 1)) || 0);
  }
  return diff === 0;
}

function isAdmin(request, env) {
  return Boolean(env.ADMIN_KEY) && safeSecretEqual(request.headers.get("x-admin-key"), env.ADMIN_KEY);
}

export async function onRequestGet({ request, env }) {
  if (!env.WORKS_KV) return json({ error: "التخزين غير مهيأ" }, 503);

  const wantsAll = new URL(request.url).searchParams.get("all") === "1";
  if (wantsAll && !isAdmin(request, env)) return json({ error: "غير مصرح" }, 401);

  const list = await env.WORKS_KV.list({ prefix: "w:", limit: 1000 });
  const works = list.keys
    .filter((key) => key.metadata && /^w:\d{13}-[0-9a-f]{6}$/.test(key.name))
    .filter((key) => wantsAll || key.metadata.status !== "pending")
    .slice(0, 100)
    .map((key) => ({ id: key.name, ...key.metadata }));

  return json(works);
}

export async function onRequestPost({ request, env, waitUntil }) {
  if (!env.WORKS_KV) return json({ error: "التخزين غير مهيأ" }, 503);
  if (!sameOriginWhenProvided(request)) return json({ error: "مصدر الطلب غير مسموح" }, 403);

  const contentType = request.headers.get("Content-Type") || "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    return json({ error: "نوع المحتوى يجب أن يكون JSON" }, 415);
  }

  const declaredLength = Number(request.headers.get("Content-Length") || 0);
  if (declaredLength > MAX_BODY_BYTES) return json({ error: "حجم الطلب كبير جداً" }, 413);

  const rate = await takeRateLimitSlot(request, env);
  if (!rate.allowed) {
    return json(
      { error: "تم تجاوز حد الإرسال. حاول مرة أخرى بعد عدة دقائق." },
      429,
      { "Retry-After": String(rate.retryAfter) }
    );
  }

  const raw = await request.text();
  if (new TextEncoder().encode(raw).byteLength > MAX_BODY_BYTES) {
    return json({ error: "حجم الطلب كبير جداً" }, 413);
  }

  let body;
  try {
    body = JSON.parse(raw);
  } catch {
    return json({ error: "JSON غير صالح" }, 400);
  }

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return json({ error: "بيانات الطلب غير صالحة" }, 400);
  }

  const type = TYPE_MAP[body.workType];
  const title = clip(body.encyclopediaTopic, 100);
  const team = clip(body.studentName, 60);
  const grade = clip(body.grade, 30);
  const url = isAllowedUrl(body.cloudLink);

  if (!type || !title || !team || !ALLOWED_GRADES.has(grade) || !url) {
    return json({
      error: "بيانات غير مقبولة. أكمل الحقول واستخدم رابط HTTPS من جوجل درايف أو ون درايف أو SharePoint أو يوتيوب."
    }, 400);
  }

  const work = {
    title,
    team,
    grade,
    type,
    link: url.href,
    status: "pending",
    at: Date.now()
  };

  const id = `w:${String(9999999999999 - Date.now()).padStart(13, "0")}-${crypto.randomUUID().slice(0, 6)}`;
  await env.WORKS_KV.put(id, "1", { metadata: work });

  if (env.FORWARD_URL) {
    waitUntil((async () => {
      try {
        const forwardUrl = new URL(env.FORWARD_URL);
        if (forwardUrl.protocol !== "https:") return;
        const headers = { "Content-Type": "application/json" };
        if (env.FORWARD_SECRET) headers["x-forward-secret"] = env.FORWARD_SECRET;
        const response = await fetch(forwardUrl.href, {
          method: "POST",
          headers,
          body: JSON.stringify({ id, ...work })
        });
        if (!response.ok) console.error("FORWARD_URL failed", response.status);
      } catch (error) {
        console.error("FORWARD_URL error", error instanceof Error ? error.message : "unknown");
      }
    })());
  }

  return json({ ok: true, id, ...work }, 201);
}

export async function onRequestDelete({ request, env }) {
  if (!env.WORKS_KV) return json({ error: "التخزين غير مهيأ" }, 503);
  if (!isAdmin(request, env)) return json({ error: "غير مصرح" }, 401);

  const id = new URL(request.url).searchParams.get("id") || "";
  if (!/^w:\d{13}-[0-9a-f]{6}$/.test(id)) return json({ error: "معرّف غير صحيح" }, 400);

  await env.WORKS_KV.delete(id);
  return json({ ok: true });
}

export async function onRequestPatch({ request, env }) {
  if (!env.WORKS_KV) return json({ error: "التخزين غير مهيأ" }, 503);
  if (!isAdmin(request, env)) return json({ error: "غير مصرح" }, 401);

  const id = new URL(request.url).searchParams.get("id") || "";
  if (!/^w:\d{13}-[0-9a-f]{6}$/.test(id)) return json({ error: "معرّف غير صحيح" }, 400);

  const action = new URL(request.url).searchParams.get("action") || "approve";
  if (!["approve", "feature", "unfeature"].includes(action)) return json({ error: "إجراء غير صحيح" }, 400);

  const { metadata } = await env.WORKS_KV.getWithMetadata(id);
  if (!metadata) return json({ error: "العمل غير موجود" }, 404);

  const next = { ...metadata };
  if (action === "approve") next.status = "approved";
  if (action === "feature") {
    if (metadata.status === "pending") return json({ error: "اقبل العمل أولاً ثم ميّزه" }, 409);
    next.featured = true;
  }
  if (action === "unfeature") delete next.featured;

  await env.WORKS_KV.put(id, "1", { metadata: next });
  return json({ ok: true });
}
