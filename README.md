# Teaching Reflection 2025–2026

Annual self-assessment app for the Department of Computer Science & Cybersecurity. Faculty fill out a five-section reflection; the chair (admin) reviews and exports submissions.

## Stack

- **Frontend**: Vanilla HTML/CSS/JS, single file in `public/index.html`. No build step.
- **Backend**: Node.js + Express
- **Database**: SQLite via `better-sqlite3` (single file on disk)
- **Auth**: Session cookies (HTTP-only, SameSite=lax), bcrypt-hashed passwords
- **Hosting**: Render web service with a 1 GB persistent disk

## Local development

```bash
npm install
SESSION_SECRET="$(openssl rand -hex 32)" \
ADMIN_BOOTSTRAP_EMAIL="you@example.edu" \
ADMIN_BOOTSTRAP_PASSWORD="ChangeMe123!" \
ADMIN_BOOTSTRAP_NAME="Your Name" \
npm start
```

Then open http://localhost:3000.

## Environment variables

| Variable | Required | Notes |
|---|---|---|
| `SESSION_SECRET` | Yes | Random string, ≥32 chars. Render's blueprint generates this automatically. |
| `DATA_DIR` | No | Where SQLite files live. Defaults to `./data`. On Render, set to `/data` (matches the mounted disk). |
| `PORT` | No | Defaults to 3000. Render sets this automatically. |
| `ADMIN_BOOTSTRAP_EMAIL` | First boot only | Creates the first admin if no admin exists in the DB. |
| `ADMIN_BOOTSTRAP_PASSWORD` | First boot only | Initial admin password. The admin is forced to change it on first sign-in. |
| `ADMIN_BOOTSTRAP_NAME` | First boot only | Display name for the bootstrap admin. |

After the first admin is created, the bootstrap env vars are ignored on subsequent boots. You can leave them set or rotate/remove them.

## Data model

- `users(id, name, email, password_hash, is_admin, must_change_password, created_at)`
- `responses(user_id, status, updated_at, submitted_at, data_json)` — one row per faculty member; the form responses live in `data_json` as opaque JSON.

## Admin features

- Submissions dashboard: filter by status (submitted / draft / not started), search, expand to see responses, export all to CSV.
- User management: add, edit, delete faculty; toggle admin role; reset passwords (forces change on next login).

## Backups

The DB is just two files in `DATA_DIR`: `app.db` and `sessions.db`. To back up faculty data, copy `app.db` somewhere safe — that's everything. On Render, you can SSH in (paid plans) or use the dashboard's disk snapshot feature, or just hit "Export CSV" from the admin dashboard periodically.

## Security notes

- Passwords hashed with bcrypt (cost 12).
- Sessions in HTTP-only, SameSite=lax cookies; secure flag in production.
- Login rate-limited: 10 attempts per 15 min per IP.
- CSP set via Helmet; allows the Google Fonts the form uses.
- Same-origin check on state-changing requests as a CSRF backstop.
- All response payloads capped at 250 KB.

## Deploy to Render

This repo contains a `render.yaml`. From the Render dashboard, "New → Blueprint" → point at this repo. Render will:

1. Provision a web service running `node server.js`.
2. Mount a 1 GB persistent disk at `/data`.
3. Generate `SESSION_SECRET` for you.
4. Prompt you for `ADMIN_BOOTSTRAP_EMAIL`, `ADMIN_BOOTSTRAP_PASSWORD`, and `ADMIN_BOOTSTRAP_NAME`.

After first deploy, sign in with your bootstrap credentials, change the password when prompted, and start adding faculty users.
