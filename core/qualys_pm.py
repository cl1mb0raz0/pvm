"""
Qualys Patch Management (PM): checks PVM's Windows findings against what
Qualys' own PM module already knows about each host's missing and
installed patches, since Windows has no free security tracker like
Ubuntu's.

Nothing is imported into a host's data (unlike Qualys Csam): "Search
Qualys Pm" (Imports > Qualys Pm) reads PVM's Windows hosts, matches them
to Qualys PM assets by IP/name (core.csam-style matching), and writes a
PatchCheck (source=qualys_pm) directly on every relevant finding it can
match by QID, no approval step, exactly like the Ubuntu tracker check
(core.patchcheck): the verdict is advisory, only closing a finding needs
a manual Confirm.

How the correlation works: a PM "patch" (a Windows Update, a vendor
update such as a SQL Server GDR, a third-party app update) carries the
Qualys QID(s) it resolves. A PM "asset" lists, per host, which patch ids
are missing and which are installed. So for a finding's QID: look up the
patches that resolve it, then check whether Qualys PM has them installed
or still missing on that host. No CVE-to-KB mapping is built by PVM: it
is Qualys PM's own reconciliation, already keyed by the same QID PVM
already imports from every scan.

The patch catalog is read once per search and used only for the run
(nothing is kept locally between searches, only the resulting PatchCheck
rows), the same "mirror once, match locally" idea as core.kev but
without the local table: querying Qualys per finding would cost one call
per finding, the catalog fits under a dozen calls at 1,000 rows a page
instead. Checked live: the gateway refuses to page the listing past
roughly its first 10,000 rows ("Only the first 10000 results can be
displayed..."), well short of the full catalog (~43,000 on 2026-09-29);
since it sorts newest published first, a search still sees the newest,
most-likely-to-still-be-missing patches, and a QID whose only patch is
older than that reads as "cannot verify" rather than a guess
(Client.pm_patches stops on that specific error, keeping what it read).
"""

import json
from datetime import datetime, timezone as dt_timezone

import redis
from django.conf import settings
from django.db.models import Q
from django.utils import timezone

from . import csam, patchcheck
from .csam import CsamError as PmError  # noqa: F401 - re-exported: same gateway, same failure modes
from .models import Host, HostPrivateIp, PatchCheck

Verdict = PatchCheck.Verdict

ASSET_PAGE_SIZE = 100
ASSET_PASSES = 3  # reads of the asset listing when it shifts while being paged (Client.pm_assets)
PATCH_PAGE_SIZE = 1000
# Qualys' own wording when a listing is paged past its cap ("Only the
# first 10000 results can be displayed. Refine your search query...").
_PAGING_CAPPED = "Only the first"


class Client(csam.Client):
    """Qualys Patch Management calls, on the same gateway/token as Csam."""

    def pm_assets(self):
        """
        Every asset PM has scanned, with its missing/installed patch ids.

        The listing does not hold still while it is paged (checked live
        2026-10-14: two full reads of 315 rows gave 309 and 313 distinct
        assets, some twice and some not at all, and the gateway answers 500
        to a sort parameter and an empty page to a page size above 100). A
        read that saw a repeated asset is therefore read again, up to
        `ASSET_PASSES` times, and the passes are merged by id; it stops as
        soon as a pass has no repeats or finds nothing new. Still no
        guarantee of completeness: the page says how many it read.
        """
        found = {}
        for attempt in range(ASSET_PASSES):
            seen, rows, new, page = set(), 0, 0, 1
            while True:
                data = self._call("GET", "/pm/v1/assets", params={"pageSize": ASSET_PAGE_SIZE, "pageNumber": page})
                if not data:
                    break
                for asset in data:
                    key = asset.get("id") or asset.get("name")
                    rows += 1
                    seen.add(key)
                    if key not in found:
                        new += 1
                    found[key] = asset
                if len(data) < ASSET_PAGE_SIZE:
                    break
                page += 1
            if rows == len(seen) or (attempt > 0 and new == 0):
                break  # this read held still, or reading again added nothing
        return list(found.values())

    def pm_patches(self):
        """
        The patch catalog: id, the QID(s) it resolves, CVEs, KB, title -
        newest published first (Qualys' own sort). The gateway refuses to
        page a listing past a cap somewhere around its first 10,000 rows
        ("Only the first 10000 results can be displayed..."), well short
        of the ~43,000 total, so a search only ever sees the newest
        patches: the ones most likely to still be missing on a host
        scanned today. A QID whose only patch is older than that reads as
        "cannot verify" rather than a guess.
        """
        patches, page = [], 1
        while True:
            try:
                data = self._call("GET", "/pm/v1/patches", params={"pageSize": PATCH_PAGE_SIZE, "pageNumber": page})
            except PmError as exc:
                if page > 1 and _PAGING_CAPPED in str(exc):
                    break
                raise
            if not data:
                break
            patches.extend(data)
            if len(data) < PATCH_PAGE_SIZE:
                break
            page += 1
        return patches


def windows_hosts():
    """PVM hosts whose recorded OS is some Windows (see Host.is_windows)."""
    return Host.objects.filter(Q(os_version__icontains="windows") | Q(os_name__icontains="windows"))


def build_index(patches):
    """
    (catalog, by_qid): catalog is {patch id: {qids, cve, kb, title}}; by_qid
    is {QID: {patch ids}}, for a finding's QID to look up in O(1).
    """
    catalog, by_qid = {}, {}
    for p in patches:
        pid = p.get("id")
        if not pid:
            continue
        qids = {str(q) for q in (p.get("qid") or [])}
        catalog[pid] = {
            "qids": qids,
            "cve": [c for c in (p.get("cve") or []) if c],
            "kb": str(p.get("kb") or ""),
            "title": p.get("title") or pid,
        }
        for qid in qids:
            by_qid.setdefault(qid, set()).add(pid)
    return catalog, by_qid


def _addresses(asset):
    return {i.get("address") for i in (asset.get("interfaces") or []) if i.get("address")}


def _names(asset):
    # PM asset names sometimes carry a " - <tenant>" suffix.
    name = (asset.get("name") or "").split(" - ")[0].strip().lower().rstrip(".")
    return {name, name.split(".")[0]} if name else set()


def match(hosts, assets):
    """[(host, asset, how)] for the Windows hosts that have a Patch Management asset."""
    by_ip = {}
    for asset in assets:
        for ip in _addresses(asset):
            by_ip.setdefault(ip, []).append(asset)
    hosts_per_ip = {}
    for host in hosts:
        hosts_per_ip.setdefault(host.ip_address, []).append(host)

    matches = []
    for host in hosts:
        name = (host.hostname or "").lower().rstrip(".")
        found = None
        for ip, how in [(p, "Private IP") for p in host.all_private_ips] + [(host.ip_address, "IP")]:
            if not ip:
                continue
            candidates = by_ip.get(ip, [])
            named = [a for a in candidates if name and (name in _names(a) or name.split(".")[0] in _names(a))]
            if len(named) == 1:
                found = (named[0], f"{how} and Name")
            elif how == "IP" and len(candidates) == 1 and len(hosts_per_ip.get(ip, [])) == 1:
                found = (candidates[0], "IP Only")
            elif how == "Private IP" and len(candidates) == 1:
                found = (candidates[0], "Private IP")
            if found:
                break
        if found:
            matches.append((host, found[0], found[1]))
    return matches


def _kb_note(kb):
    if not kb:
        return ""
    return f" (KB{kb})" if kb[0].isdigit() else f" ({kb})"


def check_finding(finding, missing_ids, installed_ids, catalog, by_qid):
    """Create or update the finding's PatchCheck from Qualys Patch Management."""
    qid = finding.vulnerability_definition.qid
    primary_cve = next((c.cve_id for c in finding.vulnerability_definition.cves.all()), "")
    relevant = sorted(by_qid.get(qid, set()) & (missing_ids | installed_ids))
    if not relevant:
        details = [
            {
                "cve": primary_cve,
                "verdict": Verdict.UNKNOWN,
                "packages": [],
                "missing": [],
                "kb": "",
                "reason": "No Matching Patch Found in Qualys Patch Management",
            }
        ]
    else:
        details = []
        for pid in relevant:
            patch = catalog[pid]
            is_missing = pid in missing_ids
            verdict = Verdict.VULNERABLE_UPDATE if is_missing else Verdict.FIXED
            details.append(
                {
                    "cve": patch["cve"][0] if patch["cve"] else primary_cve,
                    "verdict": verdict,
                    "packages": [],
                    "missing": [],
                    "kb": patch["kb"],
                    "reason": f"{'Missing' if is_missing else 'Installed'} in Qualys Patch Management: "
                    f"{patch['title']}{_kb_note(patch['kb'])}",
                }
            )
    check, _ = PatchCheck.objects.update_or_create(
        vulnerability_finding=finding,
        defaults={
            "verdict": patchcheck.worst(d["verdict"] for d in details),
            "source": PatchCheck.Source.QUALYS_PM,
            "ubuntu_release": "",
            "details": details,
            "package_versions": {},
            "checked_at": timezone.now(),
        },
    )
    return check


def check_host(host, missing_ids, installed_ids, catalog, by_qid):
    """Re-check every relevant finding of `host`. Returns {verdict: count}."""
    counts = {}
    for finding in patchcheck.findings_to_check(host):
        check = check_finding(finding, missing_ids, installed_ids, catalog, by_qid)
        counts[check.verdict] = counts.get(check.verdict, 0) + 1
    return counts


def run_search(search, only=None):
    """
    Fill `search` (a PmSearch) by checking every matched Windows host, or only those of `only` (Pvm
    hosts) that are Windows; returns the matches [(host, asset, how)]; raises PmError.
    """
    client = Client()
    hosts = list(windows_hosts().prefetch_related("other_private_ips"))
    if only is not None:
        wanted = {h.pk for h in only}
        hosts = [h for h in hosts if h.pk in wanted]
    assets = client.pm_assets()
    matches = match(hosts, assets)
    patches = client.pm_patches()
    catalog, by_qid = build_index(patches)

    totals = {}
    findings_checked = 0
    for host, asset, _how in matches:
        missing_ids = {p.get("id") for p in (asset.get("missingPatches") or []) if p.get("id")}
        installed_ids = {i for i in (asset.get("installedPatches") or []) if i}
        for verdict, count in check_host(host, missing_ids, installed_ids, catalog, by_qid).items():
            totals[verdict] = totals.get(verdict, 0) + count
            findings_checked += count

    search.windows_hosts = len(hosts)
    search.matched = len(matches)
    search.patches_seen = len(patches)
    search.findings_checked = findings_checked
    search.missing_count = totals.get(Verdict.VULNERABLE_UPDATE, 0)
    search.fixed_count = totals.get(Verdict.FIXED, 0)
    search.unknown_count = totals.get(Verdict.UNKNOWN, 0)
    search.api_calls = client.calls
    search.save()
    return matches


# --- Live search (Imports > Qualys Pm, "Search Live") --------------------------
#
# Asked by the user: ask Qualys itself for any host or software, not only the
# Windows hosts Pvm already checked. The gateway ignores every filter on both
# listings (checked live 2026-10-14: `name`, `q`, `search`, `filter`, `title`,
# `kb`... all return the first page unchanged), so a live search reads the
# listing and matches it here. That costs calls (about 3 for the 291 assets,
# about 14 for the patch catalog), so both are kept in Redis, which the web
# and the worker processes share (Django's own cache is per process): assets
# for 5 minutes, the catalog for an hour. A second search inside that time asks
# Qualys nothing.

ASSETS_CACHE_SECONDS = 5 * 60
CATALOG_CACHE_SECONDS = 60 * 60
LIVE_HOSTS_LIMIT = 50
LIVE_PATCHES_LIMIT = 25
LIVE_HOSTS_PER_PATCH = 8


def _store():
    return redis.Redis.from_url(settings.CELERY_BROKER_URL)


def _cached(key, seconds, loader, fresh=False):
    """(data, read_at, from_cache): `loader()` result kept in Redis; works without Redis."""
    r = _store()
    if not fresh:
        try:
            raw = r.get(key)
            if raw:
                stored = json.loads(raw)
                return stored["data"], datetime.fromisoformat(stored["at"]), True
        except (redis.RedisError, ValueError, KeyError):
            pass
    data, now = loader(), timezone.now()
    try:
        r.setex(key, seconds, json.dumps({"at": now.isoformat(), "data": data}))
    except redis.RedisError:
        pass  # unreachable Redis: the search still works, it just is not remembered
    return data, now, False


def _terms(query):
    return [t for t in (query or "").lower().split() if t]


def _has_all(text, terms):
    text = text.lower()
    return all(t in text for t in terms)


def _kb_label(kb):
    kb = str(kb or "")
    return f"KB{kb}" if kb[:1].isdigit() else kb


def _scan_time(millis):
    try:
        return datetime.fromtimestamp(int(millis) / 1000, tz=dt_timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def live_search(query, client=None, fresh=False):
    """
    Ask Qualys Patch Management (through the shared listings) for `query`.
    Every word must be in the same item. Returns:
      hosts:   assets whose name, address or operating system matches, with
               their missing / installed patch counts and the Pvm host they are
      patches: catalog patches whose title, KB, CVE or QID matches, with how many
               assets miss / have each and the first of the ones missing it
    plus when each listing was read, whether from the stored copy, and the
    number of API calls this search made (0 when both were stored).
    """
    terms = _terms(query)
    # The client signs in when it is created, which is already a call: make it
    # only if a listing has to be read, so a search served from the stored
    # copies asks Qualys nothing at all.
    made = {"client": client}

    def qualys():
        if made["client"] is None:
            made["client"] = Client()
        return made["client"]

    assets, assets_at, assets_cached = _cached("pvm:pm-assets", ASSETS_CACHE_SECONDS, lambda: qualys().pm_assets(), fresh)
    patches, patches_at, patches_cached = _cached(
        "pvm:pm-patches", CATALOG_CACHE_SECONDS, lambda: _compact_patches(qualys().pm_patches()), fresh
    )

    def asset_text(a):
        return " ".join([a.get("name") or "", a.get("operatingSystem") or "", *sorted(_addresses(a))])

    host_assets = [a for a in assets if _has_all(asset_text(a), terms)]

    def patch_text(p):
        kb = str(p.get("kb") or "")
        return " ".join([p.get("title") or "", kb, _kb_label(kb), *(p.get("cve") or []), *(str(q) for q in p.get("qid") or [])])

    patch_hits = [p for p in patches if _has_all(patch_text(p), terms)]
    hit_ids = {p["id"] for p in patch_hits if p.get("id")}

    missing_on, installed_on = {}, {}
    if hit_ids:
        for a in assets:
            for item in a.get("missingPatches") or []:
                if item.get("id") in hit_ids:
                    missing_on.setdefault(item["id"], []).append(a)
            for pid in a.get("installedPatches") or []:
                if pid in hit_ids:
                    installed_on[pid] = installed_on.get(pid, 0) + 1
    patch_hits.sort(key=lambda p: -len(missing_on.get(p.get("id"), [])))
    shown_patches = patch_hits[:LIVE_PATCHES_LIMIT]

    shown_hosts = host_assets[:LIVE_HOSTS_LIMIT]
    listed = list(shown_hosts)
    for p in shown_patches:
        listed.extend(missing_on.get(p.get("id"), [])[:LIVE_HOSTS_PER_PATCH])
    pvm = _pvm_hosts(listed)

    def known(a):
        return pvm.get(a.get("id"))

    return {
        "query": query,
        "hosts": [
            {
                "name": a.get("name") or "",
                "addresses": sorted(_addresses(a)),
                "os": a.get("operatingSystem") or "",
                "status": a.get("assetStatus") or "",
                "scanned": _scan_time(a.get("scanDateTime")),
                "missing": a.get("missingCount", len(a.get("missingPatches") or [])),
                "installed": a.get("installedCount", len(a.get("installedPatches") or [])),
                "pvm_host": known(a),
            }
            for a in shown_hosts
        ],
        "hosts_total": len(host_assets),
        "patches": [
            {
                "title": p.get("title") or p.get("id"),
                "kb": _kb_label(p.get("kb")),
                "cves": (p.get("cve") or [])[:3],
                "qids": len(p.get("qid") or []),
                "missing": len(missing_on.get(p.get("id"), [])),
                "installed": installed_on.get(p.get("id"), 0),
                "more": max(0, len(missing_on.get(p.get("id"), [])) - LIVE_HOSTS_PER_PATCH),
                "hosts": [
                    {"name": a.get("name") or "", "pvm_host": known(a)}
                    for a in missing_on.get(p.get("id"), [])[:LIVE_HOSTS_PER_PATCH]
                ],
            }
            for p in shown_patches
        ],
        "patches_total": len(patch_hits),
        "assets_read": len(assets),
        "patches_read": len(patches),
        "assets_at": assets_at,
        "patches_at": patches_at,
        "from_cache": assets_cached and patches_cached,
        "api_calls": made["client"].calls if made["client"] else 0,
    }


def _compact_patches(patches):
    """The catalog reduced to what a search shows (the full records are large)."""
    return [
        {"id": p.get("id"), "qid": p.get("qid") or [], "cve": p.get("cve") or [], "kb": str(p.get("kb") or ""), "title": p.get("title") or ""}
        for p in patches
        if p.get("id")
    ]


def _pvm_hosts(assets):
    """{PM asset id: Pvm Host} for the assets Pvm has, by address (private IPs included) or by name."""
    addresses = {ip for a in assets for ip in _addresses(a)}
    names = {n for a in assets for n in _names(a)}
    if not addresses and not names:
        return {}
    hosts = list(
        Host.objects.filter(
            Q(ip_address__in=addresses)
            | Q(private_ip__in=addresses)
            | Q(hostname__in=names)
            | Q(pk__in=HostPrivateIp.objects.filter(ip_address__in=addresses).values("host"))
        ).prefetch_related("other_private_ips")
    )
    found = {}
    for host, asset, _how in match(hosts, assets):
        found.setdefault(asset.get("id"), host)
    return found
