import type { VercelRequest, VercelResponse } from "@vercel/node";
import { createHmac, timingSafeEqual } from "node:crypto";
function send(res: VercelResponse, status: number, body: object) { res.setHeader("Cache-Control", "no-store"); return res.status(status).json(body); }
export default function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== "GET") { res.setHeader("Allow", "GET"); return send(res, 405, { authenticated: false }); }
  const secret = process.env.KMCT_ADMIN_SESSION_SECRET;
  if (!secret || secret.length < 32) return send(res, 503, { authenticated: false, error: "Admin login is not configured yet." });
  const cookie = req.headers.cookie || "";
  const match = cookie.match(/(?:^|;\s*)kmct_admin_session=([^;]+)/);
  if (!match) return send(res, 401, { authenticated: false });
  const [payload, signature, extra] = match[1].split(".");
  if (!payload || !signature || extra) return send(res, 401, { authenticated: false });
  const expected = createHmac("sha256", secret).update(payload).digest();
  let provided: Buffer;
  try { provided = Buffer.from(signature, "base64url"); } catch { return send(res, 401, { authenticated: false }); }
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) return send(res, 401, { authenticated: false });
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!Number.isInteger(data.exp) || data.exp < Math.floor(Date.now()/1000)) return send(res, 401, { authenticated: false });
  } catch { return send(res, 401, { authenticated: false }); }
  return send(res, 200, { authenticated: true, role: "super_admin" });
}
