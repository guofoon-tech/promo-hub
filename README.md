# PROMO HUB 3.1 — Vercel Production-ready
.
This version replaces the SQLite/local-disk architecture with Vercel-compatible services:

- Vercel Serverless Functions + Express adapter
- PostgreSQL via `@vercel/postgres`
- Vercel Blob for image/video uploads
- HttpOnly JWT cookie authentication
- Stripe Checkout + signed webhook support
- Affiliate click attribution
- Orders / commission / wallet / withdrawals

## Deploy

1. Create a Vercel project and connect this folder/repository.
2. Add a Vercel Postgres database and expose `POSTGRES_URL` to Production.
3. Add Vercel Blob and expose `BLOB_READ_WRITE_TOKEN`.
4. Set `JWT_SECRET` to a long random value.
5. Set `APP_URL` to the production URL.
6. If using Stripe, set `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET`.
7. Deploy with `vercel --prod`.

## First boot

The API creates the required PostgreSQL tables automatically on first request and seeds demo products. Set `DEFAULT_ADMIN_PASSWORD` before first boot if you want a known admin password.

Admin email: `admin@promohub.local`

## Important production notes

- Do not use the old SQLite database in production.
- Do not keep the demo admin password.
- Configure Stripe webhook URL as `/api/webhooks/stripe`.
- Use a custom domain and HTTPS.
- Review tax, refund, affiliate terms, privacy policy, and payout/KYC requirements before accepting real money.
- Commission release should be moved to a scheduled job/queue for high volume rather than relying on request-time work.
