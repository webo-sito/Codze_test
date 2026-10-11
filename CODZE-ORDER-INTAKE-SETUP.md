# CODZE Order Intake — staged foundation

This branch intentionally leaves the public `index.html` unchanged. It adds backend groundwork for GitHub Pages + Supabase.

## Current scope
- `supabase/migrations/202610110001_codze_orders.sql`: private orders/admin/rate-limit tables, constraints, indexes, RLS enabled, no public policies.
- `supabase/functions/submit-order/index.ts`: validates submissions, checks origin, honeypot, optional Turnstile verification, rate limiting, saves first, then attempts Telegram.
- No Supabase project is created by these files. No secrets are included.
- No admin dashboard yet: the single admin's Supabase Auth UUID must be established before writing and reviewing admin-only policies and dashboard behavior.
- No public form endpoint is configured yet. The website remains unchanged until the backend is configured and tested.

## Before deploying
1. Create a Supabase project manually in the intended owner account.
2. Review the SQL migration; run it only after approval.
3. Deploy the Edge Function and set secrets via Supabase's secret manager (never in HTML or Git):
   - `SUPABASE_URL`
   - `SUPABASE_SERVICE_ROLE_KEY`
   - `TELEGRAM_BOT_TOKEN`
   - `TELEGRAM_CHAT_ID`
   - `ALLOWED_ORIGIN=https://webo-sito.github.io`
   - `RATE_LIMIT_SALT` (long random secret)
   - Optional `TURNSTILE_SECRET` only after the public site includes a Turnstile widget.
4. Configure the function to require no Supabase end-user JWT because it is a public intake endpoint; the function itself validates all input and uses the server-only service-role secret. Do not expose the service-role key.
5. Test using dummy submissions, including invalid fields, honeypot, rate limits, wrong origin, Supabase save failure, and Telegram failure.
6. Only after tests pass, make the smallest approved change to `window.CODZE_CONFIG.formEndpoint` in `index.html`. The form currently expects a JSON POST and treats HTTP 2xx as success, so adapt the response carefully before enabling.
7. Create one Supabase Auth user for the owner, record and verify its UUID, then add a narrowly scoped admin allowlist and RLS policies. Do not make customer orders readable by anon or all authenticated users.
8. Add the separate admin dashboard after the exact RLS policy design has been reviewed. Use Supabase Auth, admin allowlist, sign-out, and preferably MFA.

## Important engineering notes
- Telegram uses plain text, not HTML parse mode, to avoid markup injection.
- The function stores a salted hash of the available client IP fingerprint, not the raw IP.
- The rate-limit table uses a read/upsert sequence and is a useful baseline, but is not fully atomic under concurrent requests. Before public launch, replace it with a PostgreSQL RPC/atomic counter or an edge rate-limit service.
- Telegram delivery is best-effort. A saved order is never rolled back because Telegram fails.
- Automatic retries are not implemented in this foundation. Add a reviewed retry worker/cron and bounded retry policy before relying on automatic recovery.
- The origin check is useful but not authentication; non-browser clients can spoof headers. Rate limiting and server-side validation remain necessary.
- GitHub Pages only hosts static files; it does not run the Edge Function.
