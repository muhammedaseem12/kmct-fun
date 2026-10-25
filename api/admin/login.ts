import type { VercelRequest, VercelResponse } from "@vercel/node";
import { createHmac, randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
const scrypt = promisify(scryptCallback);
const COOKIE = "kmct_admin_session";
const ttl = 60 * 60 * 8;
function send(res: VercelResponse, status: number, body: object) { res.setHeader("Cache-Control", "no-store"); return res.status(status).json(body); }
function sign(value: string, secret: string) { return createHmac("sha256", secret).update(value).digest("base64url"); }
async function verifyPassword(password: string, stored: string) {
  const [salt, expectedHex] = stored.split(":");
  if (!salt || !expectedHex || !/^[a-f0-9]{128}$/i.test(expectedHex)) return false;
  const actual = (await scrypt(password, salt, 64)) as Buffer;
  const expected = Buffer.from(expectedHex, "hex");
  return expected.length === actual.length && timingSafeEqual(actual, expected);
}
export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== "POST") { res.setHeader("Allow", "POST"); return send(res, 405, { error: "Method not allowed" }); }
  const username = process.env.KMCT_ADMIN_USERNAME;
  const passwordHash = process.env.KMCT_ADMIN_PASSWORD_HASH;
  const secret = process.env.KMCT_ADMIN_SESSION_SECRET;
  if (!username || !passwordHash || !secret || secret.length < 32) return send(res, 503, { error: "Admin login is not configured yet." });
  const body = req.body && typeof req.body === "object" ? req.body : {};
  const suppliedUser = typeof body.username === "string" ? body.username : "";
  const password = typeof body.password === "string" ? body.password : "";
  if (suppliedUser.length > 100 || password.length > 1024 || suppliedUser !== username || !(await verifyPassword(password, passwordHash))) {
    await new Promise(resolve => setTimeout(resolve, 350));
    return send(res, 401, { error: "Invalid username or password." });
  }
  const payload = Buffer.from(JSON.stringify({ exp: Math.floor(Date.now()/1000)+ttl, nonce: randomBytes(16).toString("hex") })).toString("base64url");
  const token = payload + "." + sign(payload, secret);
  res.setHeader("Set-Cookie", `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/api/admin; Max-Age=${ttl}`);
  return send(res, 200, { ok: true, expiresIn: ttl });
}
