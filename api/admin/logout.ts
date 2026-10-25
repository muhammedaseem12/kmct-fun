import type { VercelRequest, VercelResponse } from "@vercel/node";
export default function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") { res.setHeader("Allow", "POST"); return res.status(405).json({ error: "Method not allowed" }); }
  res.setHeader("Set-Cookie", "kmct_admin_session=; HttpOnly; Secure; SameSite=Strict; Path=/api/admin; Max-Age=0");
  return res.status(200).json({ ok: true });
}
