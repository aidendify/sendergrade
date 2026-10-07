# SenderGrade

Free, self-hosted email authentication monitor for agencies. Add every client's sending domain, and SenderGrade checks SPF, DKIM, DMARC and MX daily, emails you the moment something breaks, gives each client a read-only report link, and puts a branded "check your domain" page on your site that turns prospects into leads.

No signup. No license. One Docker Compose service and a SQLite file. About 15 minutes on a 1GB VPS.

## What it does

- **Clients:** add/edit/import client domains (`client_name,domain,dkim_selectors,notes`), active flag.
- **Checks (DNS only):**
  - **SPF:** fail if missing, multiple, unparseable, more than 10 DNS lookups (include/a/mx/ptr/exists/redirect counted recursively) or `+all`; warn at 8–10 lookups, `?all` or `ptr`. Lookup count is shown.
  - **DKIM:** your selectors plus auto-guessed ones from `selectors.txt`; fail if no valid key or key revoked (`p=` empty); warn below 2048-bit RSA; pass at 2048+ or ed25519. One click saves found selectors.
  - **DMARC:** fail if missing, invalid or multiple; warn on `p=none`, no `rua=`, `pct` < 100; pass on quarantine/reject with `rua`.
  - **MX:** fail on NXDOMAIN or no MX and no A fallback; warn on null MX (`0 .`); pass when an MX host resolves.
  - **Grade = worst check.** Every finding has a plain-English fix hint. DNS timeouts are recorded as `error`, shown as warn, and never trigger alerts.
- **Daily run** at `CHECK_HOUR_UTC`, plus **Run checks now** (all domains or one).
- **Change alerts:** grade change, any check status change, or a change in the raw SPF / DMARC / found-DKIM text. One email per run (when SMTP + `ALERT_EMAIL` are set); otherwise alerts are stored on the **Alerts** page as `not_sent_smtp_unconfigured`. **Send test alert** button.
- **Client report links:** `/r/{token}` read-only page per client (agency branding, current grade, fix hints, last 10 changes). Regenerate to revoke.
- **Public lead page:** `/check` — branded audit (agency name, logo, accent color, headline, CTA). Domain + email required, optional name/company, consent checkbox, honeypot, per-IP and global hourly limits. Leads page + `leads.csv`.
- **Exports:** `/export/leads.csv`, `/export/domains.csv`.
- `GET /health` → `{"status":"ok","smtp_configured":false,"domains":N,"last_run_at":...}`.

## What this is not

- Not a DMARC aggregate/forensic (RUA/RUF) report parser
- Not a blacklist / DNSBL checker
- Not an inbox placement, seed-list or warmup tool
- No ESP or registrar integrations (no Klaviyo/Mailchimp/SendGrid APIs, no DNS writes), no MTA-STS/BIMI/DNSSEC
- No Slack/webhook alerts, no PDF reports, no LLM

## 15-minute Ubuntu VPS install

Documented on **Ubuntu 22.04 / 24.04**.

**Debian 13:** do **not** run the Ubuntu `docker-ce` recipe below on Debian. Use the distro packages instead:

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose
sudo usermod -aG docker "$USER"
```

Log out and back in (or `newgrp docker`). On Debian, use `docker-compose` (hyphen) if `docker compose` is not available.

**Outbound DNS:** the VPS must be allowed to make outbound DNS queries (**UDP and TCP port 53**) to its resolver, or to the resolver you set in `DNS_RESOLVER` (for example `1.1.1.1`). If your provider firewall blocks it, every check shows `error`.

### 1. Install Docker Engine and the Compose plugin (Ubuntu only)

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo ${UBUNTU_CODENAME:-$VERSION_CODENAME}) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo usermod -aG docker "$USER"
```

Log out and back in (or run `newgrp docker`) so `docker` works without `sudo`.

### 2. Unpack, configure, start

Download the release zip, unzip it, and enter the folder:

```bash
unzip sendergrade.zip
cd sendergrade   # or the folder name inside the zip
cp .env.example .env
nano .env        # set SECRET_KEY, OWNER_PASSWORD, AGENCY_NAME, PUBLIC_BASE_URL
docker compose up -d --build
```

Open `http://YOUR_SERVER_IP:8080` and log in with `OWNER_PASSWORD`.

**Optional — install from git instead of the zip:**

```bash
git clone https://github.com/aidendify/sendergrade.git
cd sendergrade
cp .env.example .env
nano .env        # set SECRET_KEY, OWNER_PASSWORD, AGENCY_NAME, PUBLIC_BASE_URL
docker compose up -d --build
```

### 3. Smoke test

```bash
curl -s http://127.0.0.1:8080/health
# {"domains":0,"last_run_at":null,"smtp_configured":false,"status":"ok"}
```

1. Log in → **Clients** → **Load bundled sample-clients.csv** (or upload `sample-clients.csv`).
2. Click **Run checks now** (5 domains finish in a few seconds; worst case ~40s if DNS is timing out).
3. Every domain shows a grade plus SPF/DKIM/DMARC/MX status; open a client to see raw records, fix hints, SPF lookup count and DKIM selectors found. `nonexistent-sendergrade-test.invalid` grades **fail**.
4. Copy a client's `/r/{token}` link and open it in a private window.
5. Open `/check`, submit a domain + email, then see the lead on **Leads** and in `leads.csv`.
6. Change-alert test: edit the `nonexistent-sendergrade-test.invalid` client, change its domain to `github.com`, save, **Run checks now** → a new row on **Alerts** shows `fail → …` with `not_sent_smtp_unconfigured`. Run again with no edits → no new alert.

## Configuration (.env)

| Variable | Purpose |
| --- | --- |
| `PORT` | 8080 |
| `DATABASE_PATH` | `/data/sendergrade.db` (Compose volume `sendergrade-data`) |
| `SECRET_KEY` | Sessions + salt for hashed lead IPs |
| `OWNER_PASSWORD` | Dashboard password (required; login is refused when unset) |
| `PUBLIC_BASE_URL` | Absolute base for `/r/{token}` links and emails |
| `AGENCY_NAME` | Branding on `/check`, `/r/`, emails |
| `AGENCY_LOGO_URL` | Optional https logo URL |
| `AGENCY_ACCENT_COLOR` | Optional hex, e.g. `#1d4e89` |
| `AGENCY_CTA_TEXT` / `AGENCY_CTA_URL` | CTA on `/check` results (e.g. booking link) |
| `PUBLIC_CHECK_ENABLED` | Default `true`. `false` makes `/check` return 404 (master switch; the Settings toggle can only turn it off) |
| `PUBLIC_CHECK_RATE_PER_HOUR` | Per-IP accepted checks per hour, default 10 |
| `PUBLIC_CHECK_GLOBAL_PER_HOUR` | Optional global cap per hour, default 200 |
| `TRUST_PROXY_HEADERS` | `true` only behind a reverse proxy, so limits see the real visitor IP (`X-Forwarded-For`) |
| `CHECK_HOUR_UTC` | Daily run hour, default 3 |
| `DNS_RESOLVER` | Optional resolver IP(s), comma-separated. Blank = system resolver |
| `DNS_TIMEOUT_SECONDS` | Per query, default 3 (each domain is also capped at ~20s total) |
| `ALERT_EMAIL`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_STARTTLS` | Optional alerts + new-lead notifications. Port 465 uses implicit TLS |
| `MARKETING_URL` | Optional "Powered by" footer; empty = no footer |

Branding, headline, CTA, consent text and the public-page toggle can also be edited on **Settings** (stored in SQLite, overrides `.env`).

## How the schedule works

Single Compose service. Each Gunicorn worker starts a small scheduler thread, but only the worker that holds an exclusive `fcntl` file lock on `/data/scheduler.lock` actually runs checks; the others wait and take over if that worker restarts. Every minute the lock holder checks:

- **Daily:** at or after `CHECK_HOUR_UTC`:00 UTC, if no scheduled/startup run has happened since that hour today, run all active domains.
- **Startup catch-up:** when the lock is first acquired, if the last run was more than 24h ago (and there are active clients), run immediately.

All runs (scheduled and **Run checks now**) are serialised with a second lock (`/data/run.lock`), so double-clicks never create duplicate alerts.

**Baseline rule:** the first check of a new client is its baseline and creates no alert. From then on, each run is compared with that client's previous run; identical repeated results never re-alert. A domain that keeps failing is listed once in the daily run's digest line ("Still failing (unchanged)") instead of a new alert. If a check hits a DNS timeout, its previous value is carried forward for comparison, so resolver hiccups don't flap alerts.

## Finding your real DKIM selector

Auto-guess is **best effort**: it probes the common selectors in `selectors.txt` (google, selector1, selector2, s1, s2, k1, k2, k3, mandrill, kl, kl2, default, dkim, mail). Always add the client's real selector from their ESP:

- **Google Workspace:** Admin console → Apps → Google Workspace → Gmail → Authenticate email; selector is usually `google`.
- **Microsoft 365:** Defender portal → Email authentication settings → DKIM; selectors are `selector1` and `selector2`.
- **SendGrid:** Settings → Sender Authentication → your domain; CNAMEs `s1._domainkey` and `s2._domainkey` (selectors `s1`, `s2`).
- **Mailchimp / Mandrill:** Mailchimp Domains page shows `k2`/`k3` CNAMEs; Mandrill uses `mandrill` (Settings → Sending Domains).
- **Klaviyo:** Settings → Domains → your branded sending domain; DKIM CNAMEs are `kl._domainkey` and `kl2._domainkey`.

You can edit `selectors.txt` (rebuild the image) to add selectors your clients commonly use.

## Put /check on your own domain (reverse proxy)

Example with Caddy (automatic HTTPS) — `/etc/caddy/Caddyfile`:

```
audit.youragency.com {
    reverse_proxy 127.0.0.1:8080
}
```

Then set `PUBLIC_BASE_URL=https://audit.youragency.com` and `TRUST_PROXY_HEADERS=true` in `.env`, and `docker compose up -d`. Link prospects to `https://audit.youragency.com/check`. To keep the owner dashboard private, firewall port 8080 so only Caddy can reach it. Any other reverse proxy (nginx, Traefik) works the same way.

## Privacy

Self-hosted: domains, results and leads stay in your SQLite file on the Compose volume. Lead IPs are stored only as a salted SHA-256 hash (salted with `SECRET_KEY`). No analytics, no third-party APIs — only DNS queries and your own optional SMTP.

## Updating / backups

```bash
git pull && docker compose up --build -d
docker compose cp web:/data/sendergrade.db ./sendergrade-backup.db
```

## Development

```bash
pip install -r requirements.txt
SENDERGRADE_SCHEDULER=off python -m unittest test_app.py -v
```

Tests mock DNS; they don't need network access.
