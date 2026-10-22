# Installing PVM

Sets PVM up on a new server: an empty installation, or a copy of an
existing one with its data (see "Moving to another server").

## Requirements

- A Linux server with Docker Engine and the Docker Compose plugin
  (`docker compose`). 2 CPUs and 4 GB of RAM are plenty.
- Outbound HTTPS from the containers. Only CVE IDs are sent, never hosts
  or addresses; each source can be turned off in `.env`:

  | Host | Used for | Turn off with |
  |---|---|---|
  | `services.nvd.nist.gov` | CVSS scores | `NVD_ENABLED=false` |
  | `ubuntu.com` | Ubuntu security tracker | `UBUNTU_TRACKER_ENABLED=false` |
  | `errata.rockylinux.org` | Rocky Linux errata | `ROCKY_TRACKER_ENABLED=false` |
  | `www.cisa.gov` | CISA KEV catalog | `KEV_ENABLED=false` |
  | `api.first.org` | EPSS | `EPSS_ENABLED=false` |

- Optional: access to your Qualys platform's API and gateway. If it is
  reachable only through a VPN, the containers' traffic must go through it
  too (for example with the VPN client running on the host).

## 1. Get the code and configure

```bash
git clone git@github.com:<you>/<repo>.git pvm && cd pvm
cp .env.example .env && chmod 600 .env
```

Every variable is explained in `.env.example`. Set at least:

| Variable | What to put |
|---|---|
| `DJANGO_SECRET_KEY` | 32 characters or more (PVM refuses to start with the example). `python3 -c 'import secrets; print(secrets.token_urlsafe(64))'` |
| `DJANGO_ALLOWED_HOSTS` | The names and IPs users will open PVM with, comma-separated |
| `POSTGRES_PASSWORD` | A long random value, letters and digits only |
| `PVM_LISTEN` | `23847` (every interface) or `127.0.0.1:23847` |
| `PVM_TIME_ZONE` | Time zone of every date shown and of the nightly jobs (default `Europe/Rome`) |
| `QUALYS_API_URL`, `QUALYS_GATEWAY_URL`, `QUALYS_USERNAME`, `QUALYS_PASSWORD` | Only for the Qualys API |
| `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ZONES` | Only for reading Cloudflare DNS records through the API (a read-only token with Zone Read and DNS Read; zones empty = all). Without a token the records can still be loaded from a file in Imports > Cloudflare |
| `WIZ_API_URL`, `WIZ_AUTH_URL`, `WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET` | Only for Imports > Wiz: a read-only Wiz service account (the API takes service accounts only; a Global Reader user cannot be used). `WIZ_API_URL` is the GraphQL endpoint of the tenant, e.g. `https://api.eu23.app.wiz.io/graphql` |
| `WIZ_ISSUE_SEVERITIES`, `WIZ_VULN_SEVERITIES`, `WIZ_ISSUE_STATUSES`, `WIZ_VULN_STATUSES`, `WIZ_PORTAL_URL` | What Imports > Wiz reads: the issues listed (Critical and High by default; empty = all, which is tens of thousands), the vulnerabilities read for the hosts imported (Critical and High by default), their statuses, and the portal address used for the links to Wiz |
| `PVM_SSH_KEY_SECRET` | Only for "Ask Server"; changing it makes the stored SSH key unreadable |

A `$` inside a `.env` value must be in single quotes
(`QUALYS_PASSWORD='pa$$word'`), or Compose truncates it. After changing
`.env`: `docker compose up -d --force-recreate`. **Never commit `.env`**
and keep a copy of it apart from the repository and the backups.

## 2. Start

Run it as root (set `PVM_USER=0:0` in `.env`) or as a user in the `docker`
group (`PVM_USER=<id -u>:<id -g>`, default `1000:1000`). `start.sh` creates
the data folders, checks `data/postgres` when not root, and runs
`docker compose up -d` (arguments are passed on).

```bash
./start.sh --build
docker compose ps          # every service running / healthy
docker compose exec web python manage.py createsuperuser
```

Seven containers: `db` (PostgreSQL 16), `redis`, `web` (runs the
migrations before it starts), `worker`, `worker-background`, `beat`,
`nginx`. Data lives next to the compose file, in `data/postgres`,
`data/redis`, `data/scan_imports` and `data/backups`. Postgres and Redis
run as `PVM_USER` (`uid:gid`), so those folders must belong to that user
(`data/postgres` mode 700). With `PVM_USER=0:0` (server run as root) the
images start as root and give those folders to their own user. If another service already
uses port 23847 on the server, set `PVM_LISTEN` (e.g. `23848`) in `.env`.

Inside the Docker network the services use these ports
(PostgreSQL 5432, Redis 6379 are standard; gunicorn 37653, nginx 38814 are not); they are not
published on the server. If you change them, change `docker-compose.yml`,
`nginx/nginx.conf`, `POSTGRES_PORT` and `REDIS_URL` together.

Open `http://<server>:23847/` and sign in. Super Admins, Admins and
Analysts enroll an authenticator app (TOTP) at the first sign-in and get
10 backup codes, shown once. Further users are created in the Django admin
(`/admin/`) and every user needs a role.

nginx serves plain HTTP. Before exposing PVM beyond a trusted network, add
a TLS server block to `nginx/nginx.conf` (certificate mounted in the
container), publish port 443 and set `DJANGO_HTTPS=true`.

## Moving to another server

1. Old server: **Backups > FULL BACKUP** (the database plus the raw Qualys
   reports), then download it. No backup contains `.env`.
2. New server: install as above, with a copy of the old `.env` (a new
   `DJANGO_SECRET_KEY` is fine: it only signs everyone out), and create a
   Super Admin.
3. **Imports > Upload** (Super Admins): upload the file; PVM validates it
   and registers it as a backup, replacing nothing.
4. Confirm the restore (type `RESTORE`). The users, their MFA devices and
   all the data come back; the account of step 2 is replaced.

## Upgrading

```bash
git pull
docker compose up --build -d
```

The code is baked into the image, so a change reaches the app only after
`--build`; migrations run when `web` starts. Take a backup first, and do not
restart while an import or a Qualys search is running.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `web` exits at start | `DJANGO_SECRET_KEY` missing, the example, or under 32 characters |
| Qualys answers 401 | A `$` in `QUALYS_PASSWORD` not in single quotes, or wrong platform URLs |
| Qualys unreachable | The VPN is down, or no outbound HTTPS |
