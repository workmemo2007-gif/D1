export interface Env {
  DB: D1Database;
  IMAGES: R2Bucket;
  ADMIN_PIN: string;
}

const headers = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-Admin-Pin",
  "Access-Control-Max-Age": "86400",
  "X-Content-Type-Options": "nosniff",
};
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { ...headers, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
});

async function secretMatches(candidate: string, expected: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const [a, b] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(candidate)),
    crypto.subtle.digest("SHA-256", encoder.encode(expected)),
  ]);
  const x = new Uint8Array(a), y = new Uint8Array(b);
  let difference = 0;
  for (let i = 0; i < x.length; i++) difference |= x[i] ^ y[i];
  return difference === 0;
}

async function validAdmin(request: Request, env: Env): Promise<boolean> {
  const pin = request.headers.get("X-Admin-Pin") || "";
  return Boolean(pin && env.ADMIN_PIN && await secretMatches(pin, env.ADMIN_PIN));
}

function sanitizeMenu(value: unknown): unknown {
  if (typeof value === "string") return value.replace(/[<>]/g, "");
  if (Array.isArray(value)) return value.map(sanitizeMenu);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, sanitizeMenu(item)]));
  }
  return value;
}

async function readLimitedBody(request: Request, maxBytes: number): Promise<Uint8Array | null> {
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { headers });

    if (request.method === "GET" && url.pathname === "/api/menu") {
      try {
        const row = await env.DB.prepare("SELECT menu_json, updated_at FROM restaurant_menu WHERE id = 1").first<{menu_json: string; updated_at: string}>();
        if (!row) return json({ error: "لم تُهيأ قائمة الطعام بعد." }, 404);
        return json({ menu: JSON.parse(row.menu_json), updatedAt: row.updated_at });
      } catch (error) {
        console.error("Could not read menu", error);
        return json({ error: "تعذر تحميل القائمة." }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/api/admin/verify") {
      if (!env.ADMIN_PIN) return json({ error: "رمز المدير غير مضبوط في Cloudflare." }, 503);
      if (!(await validAdmin(request, env))) return json({ error: "الرمز السري غير صحيح." }, 401);
      return json({ ok: true });
    }

    if (request.method === "PUT" && url.pathname === "/api/admin/menu") {
      if (!(await validAdmin(request, env))) return json({ error: "الرمز السري غير صحيح." }, 401);
      try {
        const body = await request.json() as { menu?: unknown };
        if (!Array.isArray(body.menu) || body.menu.length === 0 || JSON.stringify(body.menu).length > 2_000_000) {
          return json({ error: "بيانات القائمة غير صالحة أو أكبر من الحد." }, 400);
        }
        const safeMenu = sanitizeMenu(body.menu);
        await env.DB.prepare("UPDATE restaurant_menu SET menu_json = ?, updated_at = ? WHERE id = 1")
          .bind(JSON.stringify(safeMenu), new Date().toISOString()).run();
        return json({ ok: true });
      } catch (error) {
        console.error("Could not save menu", error);
        return json({ error: "تعذر حفظ القائمة." }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/api/admin/upload") {
      if (!(await validAdmin(request, env))) return json({ error: "الرمز السري غير صحيح." }, 401);
      const type = request.headers.get("Content-Type")?.split(";")[0].toLowerCase() || "";
      const extension: Record<string, string> = { "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif" };
      if (!extension[type]) return json({ error: "الصيغ المدعومة: JPG وPNG وWebP وGIF." }, 415);
      const size = Number(request.headers.get("Content-Length") || 0);
      if (size > 5 * 1024 * 1024) return json({ error: "حجم الصورة يتجاوز 5 ميغابايت." }, 413);
      const imageBytes = await readLimitedBody(request, 5 * 1024 * 1024);
      if (!imageBytes) return json({ error: "حجم الصورة يتجاوز 5 ميغابايت." }, 413);
      const key = `menu/${crypto.randomUUID()}.${extension[type]}`;
      await env.IMAGES.put(key, imageBytes, { httpMetadata: { contentType: type, cacheControl: "public, max-age=31536000, immutable" } });
      return json({ url: `${url.origin}/images/${key}` });
    }

    if (request.method === "GET" && url.pathname.startsWith("/images/")) {
      const key = url.pathname.slice("/images/".length);
      if (!key.startsWith("menu/") || key.includes("..")) return new Response("Not found", { status: 404, headers });
      const object = await env.IMAGES.get(key);
      if (!object) return new Response("Not found", { status: 404, headers });
      const responseHeaders = new Headers(headers);
      object.writeHttpMetadata(responseHeaders);
      responseHeaders.set("etag", object.httpEtag);
      responseHeaders.set("Cache-Control", "public, max-age=31536000, immutable");
      return new Response(object.body, { headers: responseHeaders });
    }

    return json({ error: "المسار غير موجود." }, 404);
  },
};
