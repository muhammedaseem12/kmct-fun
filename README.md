# KMCT Community

A responsive student-community web app built with React, TypeScript, Vite, Supabase, and Vercel.

**Production:** https://kmct-fun.vercel.app  
**Repository:** https://github.com/muhammedaseem12/kmct-fun

## Stack

- React + TypeScript + Vite
- Supabase Auth and PostgreSQL via `@supabase/supabase-js`
- Vercel hosting and deployment previews
- Row-level security (RLS) for database access

## Local development

Requirements: Node.js 20+ and npm.

```bash
npm install
npm run dev
```

Production build:

```bash
npm run build
npm run preview
```

## Environment variables

Set these in Vercel (Development, Preview, and Production as appropriate):

- `VITE_SUPABASE_URL` — the Supabase project URL
- `VITE_SUPABASE_PUBLISHABLE_KEY` — the public publishable/anon key

These `VITE_*` values are delivered to the browser and **must never contain secrets**. Never put a Supabase service-role key, database password, admin password, or session-signing secret in a `VITE_*` variable or commit one to Git.

The app has fallback values in `src/App.tsx`; prefer configuring the Vercel environment variables so the target project is explicit.

## Supabase setup and production safety

1. Confirm the target project in the Supabase dashboard before running SQL.
2. Review `supabase/schema.sql` and each migration before applying it.
3. Enable and review RLS on every table exposed through the Data API. Test policies with separate user accounts, including attempts to read or modify another user's private data.
4. Configure Auth Site URL and redirect allow-list for `https://kmct-fun.vercel.app` and any required preview URLs. Enable email confirmation if signup must require email verification.
5. Configure production email delivery (custom SMTP may be needed for reliable delivery and volume). Test signup, confirmation link, sign-in, sign-out, and password reset end-to-end.
6. Enable Realtime only for tables/channels that the app actually needs.
7. Back up important data before schema changes; test restore procedures. Free-plan backup and retention capabilities may be limited.
8. Check Supabase Logs and Security Advisors after schema or policy changes.

### Important database changes

The SQL migration in `supabase/migrations/` for friend-request and conversation-membership security is **not automatically applied by deploying the frontend**. Review it against the live schema and apply it deliberately in the correct Supabase project. Do not assume a GitHub migration has already run in production.

## Admin portal

The Admin portal work is currently tracked in [PR #3](https://github.com/muhammedaseem12/kmct-fun/pull/3). It is a preview-stage authentication foundation, not yet a verified production administration system. Before enabling it:

- Review the code and verify the deployment.
- Configure server-only `KMCT_ADMIN_USERNAME`, `KMCT_ADMIN_PASSWORD_HASH`, and `KMCT_ADMIN_SESSION_SECRET` environment variables in Vercel.
- Use a strong password hash and a random session secret of at least 32 characters.
- Implement and test server-side authorization separately for every destructive admin action.
- Do not merge until authentication, session expiry, logout, and authorization tests pass.

## Deployment workflow

- `main` is the production branch.
- Feature branches should use Preview deployments.
- Check build logs and test the Preview before merging.
- Historical failed Vercel deployments remain in deployment history; an old `ERROR` record does not mean the latest `READY` deployment is failing.
- Keep the production domain attached to the production deployment and do not delete project resources to tidy up history.

## Current verification limits

A successful Vercel build confirms compilation and bundling only. It does not prove that Supabase Auth email delivery, RLS policies, Realtime, private messaging, or the Admin portal work end-to-end. Test these in the deployed app using separate accounts before inviting users.
