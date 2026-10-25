# KMCT Super Admin setup (Vercel)

This adds a separate `/admin` login page and server-side login/session endpoints. It does **not** yet grant broad database or website-editing powers; each admin operation must be implemented and authorized separately.

## Required Vercel project environment variables

Set these for **Production** first. Do not put secrets in `VITE_*` variables or client-side code.

- `KMCT_ADMIN_USERNAME`: the username you choose.
- `KMCT_ADMIN_PASSWORD_HASH`: `salt:hexhash`, where hexhash is 64-byte scrypt output (128 hex characters).
- `KMCT_ADMIN_SESSION_SECRET`: at least 32 random characters, unique and private.

Generate the password hash locally without sending the password to anyone. With Node.js installed, run this in a trusted terminal and follow the prompt. Do not commit the output or paste it into chat:

```js
// save as make-admin-hash.mjs, run: node make-admin-hash.mjs
import { scrypt as scryptCallback, randomBytes } from 'node:crypto';
import { promisify } from 'node:util';
import { createInterface } from 'node:readline/promises';
const scrypt = promisify(scryptCallback);
const rl = createInterface({ input: process.stdin, output: process.stdout });
const password = await rl.question('Choose a strong admin password (input may be visible): ');
rl.close();
if (password.length < 14) throw new Error('Use at least 14 characters.');
const salt = randomBytes(16).toString('hex');
const hash = await scrypt(password, salt, 64);
console.log('KMCT_ADMIN_PASSWORD_HASH=' + salt + ':' + hash.toString('hex'));
```

For better privacy, use a terminal that does not echo typed input. Keep the resulting hash local until pasting it directly into Vercel's Secret value field. Generate the session secret using a trusted local password manager or a local cryptographically secure generator; do not reuse your password.

After setting the values, redeploy so Vercel Functions receive them. Start with Production only; configure Preview later only if you need admin sign-in on preview deployments. Vercel environment variable changes apply to new deployments.

## Routes

- `/admin`: login page
- `/api/admin/login`: POST username/password; issues an HttpOnly, Secure, SameSite=Strict cookie
- `/api/admin/session`: GET current session status
- `/api/admin/logout`: POST to clear the cookie

Use Vercel's project deployment protection and rate limiting as additional layers. The login handler includes a small delay on invalid credentials but does not replace edge rate limiting. Do not expose the Supabase service-role key in the browser.
