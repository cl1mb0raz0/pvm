# Pvm (Patch - Vulnerability - Management)

An internal web application for managing the vulnerabilities Qualys
detects.

Persistent findings across scans, severity and risk priority
(NVD, EPSS, CISA KEV), and patch checks for Ubuntu, Rocky Linux and Windows
hosts.

Django, Postgresql, Celery / Redis and Htmx, shipped as one Docker
Compose stack.

> Host names, domains and addresses in the code and tests are placeholders
> (`.test` / `.corp` names, documentation IP ranges).

## Quick start

```bash
cp .env.example .env        # then set real secrets: see docs/INSTALL.md
./start.sh --build          # creates the data folders, then docker compose up -d
docker compose exec web python manage.py createsuperuser
```

Open `http://<server>:23847/` and sign in. Full setup, moving to another
server and upgrading: **[docs/INSTALL.md](docs/INSTALL.md)**.

### Running as a normal user or as root

The same code runs both ways; only `PVM_USER` in `.env` changes. It is the
`uid:gid` of the `db` and `redis` containers (`user: "${PVM_USER:-1000:1000}"`
in `docker-compose.yml`).

| | Normal user (docker group) | root (servers with no users) |
|---|---|---|
| `.env` | `PVM_USER=<id -u>:<id -g>` (default `1000:1000`) | `PVM_USER=0:0` |
| `data/` owner | the user: Postgres runs as that uid and needs `data/postgres` to be `0700` and owned by it | nothing to prepare: the Postgres and Redis images start as root, `chown` their own folder and drop privileges |
| Start | `./start.sh` or `docker compose up -d` | the same; with `PVM_USER=0:0` `./start.sh` only creates the folders and skips the ownership check |

Why `user:` exists: the project folder may sit on a filesystem that refuses
`chown` (a network or VMware share), so Postgres cannot switch to its own user
and has to run directly as the folder's owner. On a server's local disk, as
root, `0:0` is fine.

Switching mode on an existing `data/` folder: stop the stack and fix the owner
first (`chown -R <uid>:<gid> data/postgres data/redis`, with the ids of the
mode you are going to), otherwise Postgres refuses to start.

## License

Released under the [MIT License](LICENSE).
