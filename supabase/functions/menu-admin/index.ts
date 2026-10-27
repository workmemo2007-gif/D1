import { serve } from "https://deno.land/std@0.224.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
});

async function equalSecret(a: string, b: string): Promise<boolean> {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  const x = new Uint8Array(ha), y = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  try {
    const expected = Deno.env.get("MENU_ADMIN_PIN");
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!expected || !supabaseUrl || !serviceKey) return json({ error: "الخدمة غير مهيأة بعد." }, 503);
    const body = await req.json();
    if (typeof body.pin !== "string" || !(await equalSecret(body.pin, expected))) {
      return json({ error: "الرمز السري غير صحيح." }, 401);
    }
    if (body.action === "verify") return json({ ok: true });
    if (!Array.isArray(body.menu) || body.menu.length === 0 || JSON.stringify(body.menu).length > 2_000_000) {
      return json({ error: "بيانات القائمة غير صالحة أو أكبر من الحد المسموح." }, 400);
    }
    const response = await fetch(`${supabaseUrl}/rest/v1/restaurant_menu?id=eq.1`, {
      method: "PATCH",
      headers: {
        apikey: serviceKey,
        Authorization: `Bearer ${serviceKey}`,
        "Content-Type": "application/json",
        Prefer: "return=minimal",
      },
      body: JSON.stringify({ menu: body.menu, updated_at: new Date().toISOString() }),
    });
    if (!response.ok) {
      console.error("Supabase update failed", response.status);
      return json({ error: "تعذر حفظ القائمة في قاعدة البيانات." }, 502);
    }
    return json({ ok: true });
  } catch (error) {
    console.error("menu-admin request failed", error);
    return json({ error: "تعذر معالجة الطلب." }, 400);
  }
});
