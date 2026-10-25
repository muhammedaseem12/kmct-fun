export default function handler(req: any, res: any) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }
  const username = String(req.body?.username || "");
  const password = String(req.body?.password || "");
  const expectedUser = process.env.ADMIN_USERNAME || "";
  const expectedPassword = process.env.ADMIN_PASSWORD || "";
  if (!expectedUser || !expectedPassword) {
    return res.status(503).json({ error: "Admin login is not configured. Set ADMIN_USERNAME and ADMIN_PASSWORD in Vercel Environment Variables." });
  }
  if (username !== expectedUser || password !== expectedPassword) {
    return res.status(401).json({ error: "Invalid admin username or password." });
  }
  return res.status(200).json({ ok: true, username });
}
