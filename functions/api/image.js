// Cloudflare Pages Function: /api/image?id=<معرّف العمل>
// يعرض الصورة المرفوعة مباشرة. الصورة «قيد المراجعة» لا تظهر إلا للمشرف (بترويسة x-admin-key)، والمعتمدة للجميع.

const ID_RE = /^w:\d{13}-[0-9a-f]{6}$/;
const IMAGE_TYPES = new Set(["image/jpeg", "image/png", "image/gif", "image/webp"]);

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

const notFound = () =>
  new Response("غير موجود", {
    status: 404,
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" }
  });

export async function onRequestGet({ request, env }) {
  if (!env.WORKS_KV) return new Response("التخزين غير مهيأ", { status: 503 });

  const id = new URL(request.url).searchParams.get("id") || "";
  if (!ID_RE.test(id)) return notFound();

  const { metadata: work } = await env.WORKS_KV.getWithMetadata(id);
  if (!work || work.type !== "image") return notFound();

  const isAdmin = Boolean(env.ADMIN_KEY) && safeSecretEqual(request.headers.get("x-admin-key"), env.ADMIN_KEY);
  const pending = work.status === "pending";
  if (pending && !isAdmin) return notFound();

  const { value, metadata } = await env.WORKS_KV.getWithMetadata(`img:${id}`, { type: "arrayBuffer" });
  if (!value || !metadata || !IMAGE_TYPES.has(metadata.ct)) return notFound();

  return new Response(value, {
    headers: {
      "Content-Type": metadata.ct,
      "Content-Disposition": "inline",
      "Cache-Control": pending ? "private, no-store" : "public, max-age=86400",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": "default-src 'none'; sandbox",
      "Referrer-Policy": "no-referrer"
    }
  });
}
