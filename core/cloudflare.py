"""
Cloudflare: the real address of the sites that sit behind it.

The servers are published through Cloudflare (proxied DNS records), so a
scan of the site name reaches a Cloudflare edge address, not the server.
The DNS records know where Cloudflare sends the traffic: an A / AAAA record
holds the origin address, a CNAME leads to another record. PVM reads them
and gives each matching host its origin address as private IP, the same
field Imports > Mapping fills, so Qualys Csam can match the site to the
server that runs it.

Two ways to load the records, the same result (CloudflareRecord rows of a
CloudflareCollection; only the latest finished load is kept):

- the API (CLOUDFLARE_API_TOKEN in .env, a read-only token with Zone Read
  and DNS Read), on demand and every night;
- a file exported from the dashboard (DNS > Records > Export: a BIND zone
  file), or the API's own JSON answer, or a CSV with the columns
  name, type, content, proxied.

Loading changes nothing in PVM's hosts. "Apply" (Imports > Cloudflare)
shows which hosts would change, takes a backup and sets their private IPs.
Hosts of later imports get theirs when they are created (OriginIndex).
A host matches a record by its host name; a proxied record only: an
unproxied one already shows the server's own address to the scan.

Load balancers: if a Resolver for the stored balancer configurations
exists (core/balancer.py) the origin address is expanded to the real
servers behind it. That is the only link with it, kept in _resolver().
"""

import csv
import io
import ipaddress
import json
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import CloudflareCollection, CloudflareRecord, Host

logger = logging.getLogger(__name__)

API_URL = "https://api.cloudflare.com/client/v4"
TIMEOUT_SECONDS = 60
RETRIES = 3
RECORD_PAGE = 1000
ZONE_PAGE = 50
TYPES = ("A", "AAAA", "CNAME")
MAX_CNAME_HOPS = 8
MAX_ROWS = 200_000
# A collection still "running" after this long has lost its worker.
STALE_MINUTES = 60


class CloudflareError(Exception):
    """The API could not be reached or refused, or the file is not usable; the message is shown to the user."""


def configured():
    return bool(settings.CLOUDFLARE_API_TOKEN)


def fail_stale_collections(minutes=STALE_MINUTES):
    cutoff = timezone.now() - timedelta(minutes=minutes)
    return CloudflareCollection.objects.filter(state=CloudflareCollection.State.RUNNING, started_at__lt=cutoff).update(
        state=CloudflareCollection.State.FAILED,
        error="Interrupted: the Worker Stopped While It Was Running (a Restart or a Rebuild). Collect Again.",
        finished_at=timezone.now(),
    )


def latest():
    """The load whose records are in use: the newest finished one."""
    return CloudflareCollection.objects.filter(state=CloudflareCollection.State.DONE).first()


# --- The API -----------------------------------------------------------


class Client:
    def __init__(self):
        if not configured():
            raise CloudflareError("Cloudflare Is Not Configured: Set CLOUDFLARE_API_TOKEN in .env.")
        self.calls = 0

    def get(self, path, params=None):
        """One GET: retries a 429 / 5xx / network error, raises CloudflareError on a refusal. Returns the whole answer."""
        url = f"{API_URL}{path}?{urllib.parse.urlencode(params or {})}"
        for attempt in range(RETRIES):
            request = urllib.request.Request(url, headers={"Authorization": f"Bearer {settings.CLOUDFLARE_API_TOKEN}"})
            self.calls += 1
            try:
                with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as r:
                    data = json.load(r)
            except urllib.error.HTTPError as exc:
                if exc.code in (429, 500, 502, 503, 504) and attempt < RETRIES - 1:
                    time.sleep(min(int(exc.headers.get("Retry-After") or 10), 60))
                    continue
                if exc.code in (401, 403):
                    raise CloudflareError(
                        "Cloudflare Refused the Token in .env: It Needs Zone > Zone > Read and Zone > DNS > Read."
                    ) from exc
                raise CloudflareError(f"Cloudflare API Answered {exc.code}: {exc.read()[:300].decode(errors='replace')}") from exc
            except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
                if attempt < RETRIES - 1:
                    time.sleep(5)
                    continue
                raise CloudflareError(f"Cloudflare API Unreachable (Is the Network Open to It?): {exc}") from exc
            if not data.get("success", True):
                messages = "; ".join(str(e.get("message", e))[:200] for e in (data.get("errors") or [])[:3])
                raise CloudflareError(f"Cloudflare API Refused the Request: {messages}")
            return data

    def pages(self, path, per_page, params=None):
        """Every item of a paginated listing, page after page."""
        page = 1
        while True:
            data = self.get(path, {**(params or {}), "page": page, "per_page": per_page})
            yield from data.get("result") or []
            if page >= (data.get("result_info") or {}).get("total_pages", 1):
                return
            page += 1

    def zones(self):
        wanted = set(settings.CLOUDFLARE_ZONES)
        zones = [z for z in self.pages("/zones", ZONE_PAGE) if not wanted or z["name"].lower() in wanted]
        if wanted and not zones:
            raise CloudflareError("None of the Zones in CLOUDFLARE_ZONES Is Visible to the Token.")
        return zones

    def records(self, zone):
        for kind in TYPES:
            for item in self.pages(f"/zones/{zone['id']}/dns_records", RECORD_PAGE, {"type": kind}):
                yield {**item, "zone_name": zone["name"]}


# --- Reading records ---------------------------------------------------


def _name(value):
    return (value or "").strip().lower().rstrip(".")


def _ip_or_none(value):
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        return None


def clean_record(item):
    """(zone, name, type, content, proxied) of one record, or None when it is not an A / AAAA / CNAME to keep."""
    kind = str(item.get("type") or "").strip().upper()
    name = _name(item.get("name"))
    content = str(item.get("content") or "").strip()
    if kind not in TYPES or not name or not content:
        return None
    if kind == "CNAME":
        content = _name(content)
    else:
        content = _ip_or_none(content)
        if not content or (kind == "A") != (":" not in content):
            return None
    proxied = item.get("proxied")
    if isinstance(proxied, str):
        proxied = {"true": True, "yes": True, "1": True, "false": False, "no": False, "0": False}.get(proxied.strip().lower())
    return (_name(item.get("zone_name")), name[:255], kind, content[:255], proxied if isinstance(proxied, bool) else None)


BIND_LINE = re.compile(r"^(?P<name>\S+)\s+(?:\d+\s+)?(?:IN\s+)?(?P<type>A|AAAA|CNAME)\s+(?P<content>\S+)\s*(?:;(?P<comment>.*))?$", re.I)


def _parse_bind(text):
    """A zone file as the dashboard exports it; the proxy flag is in the trailing comment (cf_tags=cf-proxied:true)."""
    origin, zone, items = "", "", []
    for line in text.splitlines():
        line = line.strip()
        if line.upper().startswith("$ORIGIN"):
            origin = _name(line.split(None, 1)[1]) if len(line.split(None, 1)) > 1 else ""
            zone = zone or origin
            continue
        match = BIND_LINE.match(line)
        if not match:
            continue
        raw = match["name"]
        name = origin if raw == "@" else (_name(raw) if raw.endswith(".") or not origin else f"{_name(raw)}.{origin}")
        content = match["content"]
        if match["type"].upper() == "CNAME" and not content.endswith(".") and origin and "." not in content:
            content = f"{content}.{origin}"
        comment = (match["comment"] or "").lower()
        proxied = True if "cf-proxied:true" in comment else False if "cf-proxied:false" in comment else None
        items.append({"name": name, "type": match["type"], "content": content, "proxied": proxied, "zone_name": zone})
    return items


def parse_file(raw):
    """
    The records of an uploaded file, as clean_record() tuples: a BIND zone
    file, the API's JSON answer (or a list of records), or a CSV with the
    columns name, type, content and proxied. Raises CloudflareError.
    """
    text = None
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    text = (text if text is not None else raw.decode("latin-1")).strip()
    if not text:
        raise CloudflareError("The File Is Empty.")
    items = None
    if text[0] in "[{":
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise CloudflareError(f"The File Looks Like JSON but Cannot Be Read: {exc}") from exc
        items = data.get("result", []) if isinstance(data, dict) else data
        if not isinstance(items, list):
            raise CloudflareError("The JSON Has No List of Records (Expected the API's “result”).")
        items = [i for i in items if isinstance(i, dict)]
    else:
        first = text.splitlines()[0].lower()
        if "," in first or ";" in first or "\t" in first:
            if {"name", "type", "content"} <= {c.strip() for c in re.split(r"[,;\t]", first)}:
                try:
                    dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t")
                except csv.Error:
                    dialect = csv.excel
                reader = csv.DictReader(io.StringIO(text, newline=""), dialect=dialect)
                items = [{(k or "").strip().lower(): v for k, v in row.items()} for row in reader]
        if items is None:
            items = _parse_bind(text)
    if len(items) > MAX_ROWS:
        raise CloudflareError(f"More than {MAX_ROWS} Records: Load the Zones Separately.")
    records = [r for r in map(clean_record, items) if r]
    if not records:
        raise CloudflareError(
            "No A, AAAA or CNAME Record Found. Use the Zone File from the Dashboard (DNS > Records > Export), "
            "the API's JSON, or a CSV with the Columns name, type, content, proxied."
        )
    return records


# --- Storing -----------------------------------------------------------


def store(collection, records, zones=0, api_calls=0):
    """
    Save `records` as the collection's and make it the only one kept. The
    previous load is replaced only now, so a failed run leaves the last good
    data in place.
    """
    unique = list(dict.fromkeys(records))
    with transaction.atomic():
        CloudflareRecord.objects.bulk_create(
            (CloudflareRecord(collection=collection, zone_name=z, name=n, type=t, content=c, proxied=p) for z, n, t, c, p in unique),
            batch_size=1000,
        )
        CloudflareCollection.objects.exclude(pk=collection.pk).exclude(state=CloudflareCollection.State.RUNNING).delete()
        collection.items, collection.zones, collection.api_calls = len(unique), zones or len({r[0] for r in unique}), api_calls
        collection.state, collection.finished_at = CloudflareCollection.State.DONE, timezone.now()
        collection.save()


def run_collection(collection):
    """Read every zone's records from the API and store them."""
    client = Client()
    zones = client.zones()
    records = []
    for zone in zones:
        records.extend(r for r in map(clean_record, client.records(zone)) if r)
    store(collection, records, zones=len(zones), api_calls=client.calls)


def import_file(raw, filename, user):
    """Store the records of an uploaded file as the current load; returns the collection."""
    records = parse_file(raw)
    collection = CloudflareCollection.objects.create(
        source=CloudflareCollection.Source.FILE, filename=filename[:200], started_by=user
    )
    try:
        store(collection, records)
    except Exception:
        collection.delete()
        raise
    return collection


# --- From records to origin addresses -----------------------------------


class OriginIndex:
    """The latest load's records, indexed by name, answering "where does Cloudflare send this host name?"."""

    def __init__(self, records):
        self.by_name = {}
        for r in records:
            self.by_name.setdefault(r.name, []).append(r)

    @classmethod
    def stored(cls):
        collection = latest()
        return cls(collection.records.all() if collection else [])

    def __bool__(self):
        return bool(self.by_name)

    def _records_for(self, name):
        found = self.by_name.get(name)
        if found:
            return found
        # A wildcard record answers every name under it that has no record of its own.
        parts = name.split(".", 1)
        return self.by_name.get(f"*.{parts[1]}", []) if len(parts) == 2 else []

    def _addresses(self, name, hops=0):
        out = []
        for r in self._records_for(name):
            if r.type == "CNAME":
                if hops < MAX_CNAME_HOPS:
                    out.extend(self._addresses(r.content, hops + 1))
            else:
                out.append(r.content)
        return out

    def match(self, hostname):
        """
        (proxied records of the name, origin addresses) for a host name, or
        None when no proxied record carries it. The addresses are empty when
        the chain ends outside the load (e.g. a tunnel target).
        """
        name = _name(hostname)
        records = [r for r in self._records_for(name) if r.proxied is not False]
        if not records:
            return None
        return records, list(dict.fromkeys(self._addresses(name)))

    def origin_ips(self, host, resolver=None):
        """The addresses to give `host` as private IPs, or [] (not behind Cloudflare, unresolved, or scanned directly)."""
        found = self.match(host.hostname)
        if not found or not found[1] or host.ip_address in found[1]:
            return []
        ips = []
        for ip in found[1]:
            resolved = resolver.resolve(host.hostname, host.ip_address, ip) if resolver else None
            ips.extend(resolved.backends if resolved else [ip])
        return list(dict.fromkeys(ips))


def _resolver():
    """The stored balancer configurations' resolver, or None (also once core/balancer.py is gone)."""
    try:
        from . import balancer
    except ImportError:
        return None
    return balancer.Resolver.stored() or None


def plan():
    """
    Each PVM host behind a proxied record, with its current private IPs and
    the ones applying would set: status "new", "changed", "same", "direct"
    (scanned on the origin address itself) or "unresolved" (the record leads
    outside the load, e.g. to a tunnel). Nothing is written.
    """
    index = OriginIndex.stored()
    if not index:
        return []
    resolver = _resolver()
    rows = []
    for host in Host.objects.prefetch_related("other_private_ips").order_by("hostname", "pk"):
        found = index.match(host.hostname)
        if not found:
            continue
        records, origins = found
        current, target = host.all_private_ips, index.origin_ips(host, resolver)
        if not origins:
            status = "unresolved"
        elif host.ip_address in origins:
            status = "direct"
        else:
            status = "same" if current == target else "changed" if current else "new"
        rows.append({"host": host, "records": records, "origins": origins, "current": current, "target": target, "status": status})
    return rows


def apply(planned):
    """Set the private IPs of the hosts that are new or changed in `planned`; returns how many."""
    changed = 0
    with transaction.atomic():
        for row in planned:
            if row["status"] in ("new", "changed"):
                row["host"].set_private_ips(row["target"])
                changed += 1
    return changed
