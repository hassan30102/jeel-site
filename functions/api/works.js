// Cloudflare Pages Function: /api/works
// GET: آخر 100 عمل معتمد (ومع ?all=1 وبمفتاح المشرف تظهر الأعمال المنتظرة أيضاً)، POST: إضافة عمل بحالة «قيد المراجعة»،
// PATCH: بمفتاح المشرف، ?action=approve (اعتماد، وهو الافتراضي) أو feature / unfeature (تمييز العمل المعتمد)، DELETE: حذف بمفتاح المشرف.
// المتطلبات: KV باسم WORKS_KV، وسر ADMIN_KEY، واختيارياً FORWARD_URL وFORWARD_SECRET.

const TYPE_MAP = {
  "إنفوجرافيك": "infographic",
  "فيديو": "video",
  "خريطة": "map",
  "خريطة تفاعلية": "map",
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
  "youtu.be",
  "jeel-site.pages.dev"
];

const MAX_BODY_BYTES = 4096;
// الصور تُرفع مباشرة (multipart/form-data) وتُحفظ في KV بمفتاح img:<معرّف العمل>.
// المتصفح يحوّل أي امتداد (HEIC، TIFF، BMP، SVG...) إلى JPEG قبل الرفع، فالخادم لا يقبل إلا هذه الصيغ الأربع بعد فحص محتواها الفعلي.
const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
const MAX_UPLOAD_BYTES = MAX_IMAGE_BYTES + 64 * 1024;
const ID_RE = /^w:\d{13}-[0-9a-f]{6}$/;

function sniffImage(bytes) {
  const b = bytes;
  if (b.length > 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "image/jpeg";
  if (b.length > 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return "image/png";
  if (b.length > 6 && b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38) return "image/gif";
  if (b.length > 12 && b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 &&
      b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return "image/webp";
  return null;
}

const newWorkId = () =>
  `w:${String(9999999999999 - Date.now()).padStart(13, "0")}-${crypto.randomUUID().slice(0, 6)}`;
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

  const contentType = (request.headers.get("Content-Type") || "").toLowerCase();
  const isUpload = contentType.startsWith("multipart/form-data");
  if (!isUpload && !contentType.startsWith("application/json")) {
    return json({ error: "نوع المحتوى يجب أن يكون JSON أو ملف صورة" }, 415);
  }

  const declaredLength = Number(request.headers.get("Content-Length") || 0);
  if (isUpload && !declaredLength) return json({ error: "حجم الطلب غير معروف" }, 411);
  if (declaredLength > (isUpload ? MAX_UPLOAD_BYTES : MAX_BODY_BYTES)) {
    return json({ error: isUpload ? "حجم الصورة أكبر من 5 ميغابايت" : "حجم الطلب كبير جداً" }, 413);
  }

  const rate = await takeRateLimitSlot(request, env);
  if (!rate.allowed) {
    return json(
      { error: "تم تجاوز حد الإرسال. حاول مرة أخرى بعد عدة دقائق." },
      429,
      { "Retry-After": String(rate.retryAfter) }
    );
  }

  if (isUpload) return handleImageUpload(request, env, waitUntil);

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

  if (type === "image") {
    return json({ error: "الصور تُرفع مباشرة من الجهاز، اختر ملف الصورة بدل الرابط." }, 400);
  }

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

  const id = newWorkId();
  await env.WORKS_KV.put(id, "1", { metadata: work });
  forwardWork(env, waitUntil, id, work);
  return json({ ok: true, id, ...work }, 201);
}

async function handleImageUpload(request, env, waitUntil) {
  let form;
  try {
    form = await request.formData();
  } catch {
    return json({ error: "تعذّرت قراءة الملف المرفوع" }, 400);
  }

  const title = clip(form.get("encyclopediaTopic"), 100);
  const team = clip(form.get("studentName"), 60);
  const grade = clip(form.get("grade"), 30);
  const file = form.get("image");

  if (TYPE_MAP[form.get("workType")] !== "image" || !title || !team || !ALLOWED_GRADES.has(grade)) {
    return json({ error: "بيانات غير مقبولة. أكمل جميع الحقول." }, 400);
  }
  if (!file || typeof file === "string" || !file.size) {
    return json({ error: "اختر ملف الصورة أولاً" }, 400);
  }
  if (file.size > MAX_IMAGE_BYTES) return json({ error: "حجم الصورة أكبر من 5 ميغابايت" }, 413);

  const bytes = new Uint8Array(await file.arrayBuffer());
  const mime = sniffImage(bytes);
  if (!mime) return json({ error: "الملف المرفوع ليس صورة صالحة" }, 415);

  const id = newWorkId();
  const work = {
    title,
    team,
    grade,
    type: "image",
    link: `/api/image?id=${encodeURIComponent(id)}`,
    status: "pending",
    at: Date.now()
  };

  // الصورة أولاً، ثم سجل العمل؛ فلا يظهر عمل بلا صورة.
  await env.WORKS_KV.put(`img:${id}`, bytes, { metadata: { ct: mime, size: bytes.length } });
  await env.WORKS_KV.put(id, "1", { metadata: work });
  forwardWork(env, waitUntil, id, work);
  return json({ ok: true, id, ...work }, 201);
}

function forwardWork(env, waitUntil, id, work) {
  if (env.FORWARD_URL && waitUntil) {
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
}

export async function onRequestDelete({ request, env }) {
  if (!env.WORKS_KV) return json({ error: "التخزين غير مهيأ" }, 503);
  if (!isAdmin(request, env)) return json({ error: "غير مصرح" }, 401);

  const id = new URL(request.url).searchParams.get("id") || "";
  if (!/^w:\d{13}-[0-9a-f]{6}$/.test(id)) return json({ error: "معرّف غير صحيح" }, 400);

  await env.WORKS_KV.delete(id);
  await env.WORKS_KV.delete(`img:${id}`); // لا يضر إن لم تكن للعمل صورة
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
