"""
Imports > Wiz: two runs, each with the steps the page shows as it goes.

"Import Wiz Issues" reads the issues from Wiz and lists the hosts (Wiz
resources) they are about. It changes nothing in Pvm's own hosts; the
hosts already imported get their findings brought up to date.

"Full Import" does everything for the hosts chosen:
1. host information, from Wiz;
2. addresses, internet exposure and vulnerabilities, from Wiz (the resource
   has no address of its own: it comes with its vulnerabilities);
3. the Pvm host: a host Pvm already has (same Wiz id, or same name on one of
   its addresses) is linked and stays in the main Hosts list; any other is
   created as `wiz_only`, shown under Hosts > Wiz only. A resource without an
   address (a bucket, a service account…) is a host at 0.0.0.0 to carry its issues;
4. the issues as Pvm findings (Vulnerabilities > Wiz): one finding per Wiz
   rule, with SLA and priority. An issue Wiz no longer lists closes its finding;
5. Qualys Csam for the hosts with an address that Csam knows: release, packages,
   OS and tags are applied, and the patch check runs again;
6. Qualys Pm for those that are Windows.
A host with no match in Qualys is skipped, and the page says so. A step that
fails does not stop the next ones.
"""

import hashlib
import ipaddress
import logging
import time
from datetime import timedelta

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from . import audit, priority, sla, wiz
from .models import (
    CsamSearch, Host, Perimeter, PmSearch, VulnerabilityDefinition, VulnerabilityFinding, WizAsset, WizIssue,
    WizRun, WizVulnerability,
)

logger = logging.getLogger(__name__)

Status = VulnerabilityFinding.Status
STALE_MINUTES = 15
# The address of a Wiz resource that has none (a bucket): Host needs one.
NO_ADDRESS = "0.0.0.0"
WIZ_SOURCE = "Wiz"
CLOSED = {"RESOLVED", "REJECTED"}
# Wiz severities on Qualys' 1-5 scale, from which Pvm's four levels follow as for every other finding.
LEVEL = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFORMATIONAL": 1}
SEVERITY = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "low"}

# Internet exposure, the most exposed first: a host seen exposed in any finding is exposed.
EXPOSURE = ["wide", "limited", "none"]

STEPS = {
    WizRun.Kind.ISSUES: [("issues", "Read the Issues from Wiz")],
    WizRun.Kind.FULL: [
        ("info", "Host Information from Wiz"),
        ("vulns", "Addresses and Vulnerabilities from Wiz"),
        ("hosts", "Pvm Hosts"),
        ("findings", "Issues as Findings"),
        ("csam", "Qualys Csam"),
        ("pm", "Qualys Pm"),
    ],
}


def start(kind, user, asset_ids=(), severities=()):
    """A new run, with its steps waiting. The caller queues the task once the transaction commits."""
    steps = [{"key": k, "label": label, "state": "pending", "done": 0, "total": 0, "detail": ""} for k, label in STEPS[kind]]
    return WizRun.objects.create(kind=kind, started_by=user, asset_ids=list(asset_ids), severities=list(severities), steps=steps, heartbeat=timezone.now())


def fail_stale_runs(minutes=STALE_MINUTES):
    """A run with no sign of life for `minutes` has lost its worker (every step reports as it goes)."""
    cutoff = timezone.now() - timedelta(minutes=minutes)
    stale = Q(heartbeat__lt=cutoff) | Q(heartbeat__isnull=True, started_at__lt=cutoff)
    runs = list(WizRun.objects.filter(state=WizRun.State.RUNNING).filter(stale))
    for run in runs:
        _fail(run, f"Interrupted: No Sign of Life for {minutes} Minutes (the Worker Stopped: a Restart or a Rebuild). Run It Again.")
    return len(runs)


def _fail(run, error):
    """Mark `run` failed, and the step it was in failed too, so the page does not keep spinning on it."""
    for step in run.steps:
        if step["state"] == "running":
            step["state"], step["detail"] = "failed", step["detail"] or error[:200]
    WizRun.objects.filter(pk=run.pk).update(state=WizRun.State.FAILED, error=error[:2000], finished_at=timezone.now(), steps=run.steps)


class Progress:
    """Writes a step's state to the run as it changes: it is what the page polls."""

    def __init__(self, run):
        self.run = run

    def update(self, key, **values):
        step = next(s for s in self.run.steps if s["key"] == key)
        step.update(values)
        self.run.heartbeat = timezone.now()
        WizRun.objects.filter(pk=self.run.pk).update(steps=self.run.steps, heartbeat=self.run.heartbeat, api_calls=self.run.api_calls)

    def step(self, key, total, fn):
        """Run `fn(report)` as step `key`; `report(done, detail)` moves the bar. A failure is shown, not raised."""
        self.update(key, state="running", total=total, done=0, detail="")

        def report(done, detail=None, **extra):
            values = {"done": done, **extra}
            if detail is not None:
                values["detail"] = detail
            self.update(key, **values)

        try:
            outcome = fn(report)
        except Exception as exc:  # the next steps still run
            logger.exception("Wiz step %s failed", key)
            self.update(key, state="failed", detail=str(exc)[:500])
            return
        if isinstance(outcome, tuple):  # ("skipped", why)
            self.update(key, state=outcome[0], detail=outcome[1])
        else:
            self.update(key, state="done", done=total, detail=outcome or "")


def run(run_id):
    """The task body: run the steps of WizRun `run_id` and mark it done or failed."""
    run = WizRun.objects.get(pk=run_id)
    try:
        client = wiz.Client()
        if run.kind == WizRun.Kind.ISSUES:
            run_issues(run, client)
        else:
            run_full(run, client)
    except Exception as exc:  # the page must show why, whatever it was
        logger.warning("Wiz run %s failed: %s", run_id, exc)
        _fail(WizRun.objects.get(pk=run_id), str(exc))
        return
    WizRun.objects.filter(pk=run_id).update(state=WizRun.State.DONE, finished_at=timezone.now())


# --- Import Wiz Issues -----------------------------------------------------------


def run_issues(run, client):
    progress = Progress(run)

    def read(report):
        nodes = []

        def page(total):
            run.api_calls = client.calls
            report(len(nodes), f"{len(nodes)} of {total or '?'} Issues", total=total or 0)

        for node in client.issues(on_page=page, severities=run.severities):
            nodes.append(node)
        assets, issues = store_issues(nodes)
        findings = sum(sync_findings(a) for a in WizAsset.objects.filter(imported_at__isnull=False).select_related("host") if a.host)
        run.api_calls = client.calls
        return f"{issues} Issues on {assets} Hosts" + (f"; {findings} Findings Updated on the Hosts Already Imported" if findings else "")

    progress.step("issues", 0, read)


def store_issues(nodes):
    """Replace the stored issues by `nodes`; returns (hosts listed, issues). An imported host with no issue left stays."""
    with transaction.atomic():
        assets = {a.wiz_id: a for a in WizAsset.objects.all()}
        seen = {}
        for node in nodes:
            entity = node.get("entitySnapshot") or {}
            if not entity.get("id"):
                continue
            fields = wiz.asset_fields(entity)
            asset = assets.get(entity["id"])
            if asset is None:
                asset = assets[entity["id"]] = WizAsset.objects.create(wiz_id=entity["id"], **fields)
            elif not asset.imported_at:
                for name, value in fields.items():
                    setattr(asset, name, value)
                asset.save(update_fields=list(fields))
            seen.setdefault(entity["id"], []).append(node)
        WizIssue.objects.all().delete()
        WizIssue.objects.bulk_create(
            [WizIssue(asset=assets[wiz_id], **wiz.issue_fields(n)) for wiz_id, ns in seen.items() for n in ns], batch_size=500
        )
        WizAsset.objects.filter(imported_at__isnull=True).exclude(wiz_id__in=list(seen)).delete()
        refresh_counts()
    return len(seen), sum(len(v) for v in seen.values())


def refresh_counts():
    """issue_count and worst_severity of every asset, from its issues not closed."""
    rank = {s: i for i, s in enumerate(wiz.SEVERITIES)}
    found = {}
    for asset_id, severity in WizIssue.objects.exclude(status__in=CLOSED).values_list("asset_id", "severity"):
        count, worst = found.get(asset_id, (0, ""))
        found[asset_id] = (count + 1, severity if not worst or rank.get(severity, 9) < rank.get(worst, 9) else worst)
    changed = []
    for asset in WizAsset.objects.all():
        count, worst = found.get(asset.pk, (0, ""))
        if (asset.issue_count, asset.worst_severity) != (count, worst):
            asset.issue_count, asset.worst_severity = count, worst
            changed.append(asset)
    WizAsset.objects.bulk_update(changed, ["issue_count", "worst_severity"], batch_size=500)


# --- Full Import -----------------------------------------------------------------


def run_full(run, client):
    progress = Progress(run)
    assets = list(WizAsset.objects.filter(wiz_id__in=run.asset_ids))
    total = len(assets)
    progress.step("info", total, lambda report: step_info(client, assets, report))
    run.api_calls = client.calls
    progress.step("vulns", total, lambda report: step_vulnerabilities(client, assets, report, run))
    progress.step("hosts", total, lambda report: step_hosts(assets, report))
    progress.step("findings", total, lambda report: step_findings(assets, report))
    progress.step("csam", total, lambda report: step_csam(assets, run.started_by, report))
    progress.step("pm", total, lambda report: step_pm(assets, run.started_by, report))
    if run.started_by:
        audit.log(run.started_by, "wiz.full_import", run, hosts=total)


def step_info(client, assets, report):
    described = 0
    for start in range(0, len(assets), wiz.ENTITY_BATCH):
        batch = assets[start:start + wiz.ENTITY_BATCH]
        entities = client.entities([a.wiz_id for a in batch])
        for asset in batch:
            entity = entities.get(asset.wiz_id)
            if entity:
                fields = wiz.entity_fields(entity)
                for name, value in fields.items():
                    setattr(asset, name, value)
                asset.save(update_fields=list(fields))
                described += 1
        report(min(start + wiz.ENTITY_BATCH, len(assets)), f"{described} of {len(assets)} Hosts Described by Wiz")
        time.sleep(wiz.BATCH_PAUSE_SECONDS)
    return f"{described} of {len(assets)} Hosts Described by Wiz"


def _ips(values):
    found = []
    for value in values or []:
        try:
            ip = str(ipaddress.ip_address(str(value).strip()))
        except ValueError:
            continue
        if ip not in found:
            found.append(ip)
    return found


def step_vulnerabilities(client, assets, report, run):
    total = with_address = 0
    for done, asset in enumerate(assets, start=1):
        rows, ips, exposure = [], [], ""
        for node in client.vulnerabilities(asset.wiz_id, run.severities):
            rows.append(WizVulnerability(asset=asset, **wiz.vulnerability_fields(node)))
            machine = node.get("vulnerableAsset") or {}
            ips += [ip for ip in _ips(machine.get("ipAddresses")) if ip not in ips]
            if "hasWideInternetExposure" in machine:
                level = "wide" if machine.get("hasWideInternetExposure") else "limited" if machine.get("hasLimitedInternetExposure") else "none"
                if not exposure or EXPOSURE.index(level) < EXPOSURE.index(exposure):
                    exposure = level
        with transaction.atomic():
            asset.vulnerabilities.all().delete()
            WizVulnerability.objects.bulk_create(rows, batch_size=500, ignore_conflicts=True)
            if ips:
                asset.ip_addresses = ips
            if exposure:
                asset.exposure = exposure
            asset.save(update_fields=["ip_addresses", "exposure"])
        total += len(rows)
        with_address += bool(asset.ip_addresses)
        run.api_calls = client.calls
        report(done, f"{total} Vulnerabilities; {with_address} Hosts with an Address")
        time.sleep(0.3)
    return f"{total} Vulnerabilities; {with_address} of {len(assets)} Hosts with an Address"


# RFC 1918 and friends. Not ipaddress's is_private, which also counts the documentation ranges.
PRIVATE_NETWORKS = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10")
]


def is_private(ip):
    address = ipaddress.ip_address(ip)
    return any(address in n for n in PRIVATE_NETWORKS if n.version == address.version)


def addresses(asset):
    """(ip_address, private_ips) of an asset: the public address is the IP, the private ones go with it; None when it has none."""
    ips = _ips(asset.ip_addresses)
    private = [ip for ip in ips if is_private(ip)]
    public = [ip for ip in ips if ip not in private]
    ip = (public or private or [None])[0]
    return ip, [p for p in private if p != ip]


def link_host(asset):
    """The Pvm host of an asset: linked if Pvm has it, created otherwise. Returns (host, "linked" | "created")."""
    ip, private = addresses(asset)
    host = Host.objects.filter(wiz_id=asset.wiz_id).first()
    if host is None and ip:
        known = [ip, *private]
        named = Host.objects.filter(hostname__iexact=asset.name, wiz_id__isnull=True)
        host = named.filter(Q(ip_address__in=known) | Q(private_ip__in=known)).first()
        if host is None:
            sharing = Host.objects.filter(ip_address=ip, wiz_id__isnull=True)
            host = sharing.first() if sharing.count() == 1 else None
        if host is not None:
            host.wiz_id = asset.wiz_id
            host.save(update_fields=["wiz_id"])
            return host, "linked"
    if host is not None:
        if host.cloud_resource and ip:  # made without an address, which Wiz has given since
            host.ip_address, host.cloud_resource = ip, ""
            host.save(update_fields=["ip_address", "cloud_resource"])
        return host, "linked"
    host = Host.objects.create(
        hostname=(asset.name or asset.wiz_id)[:255], ip_address=ip or NO_ADDRESS, os_name=asset.os_name[:255],
        wiz_id=asset.wiz_id, wiz_only=True, cloud_resource="" if ip else (asset.resource_type or "resource")[:64], is_active=True,
    )
    if private:
        host.set_private_ips(private)
    return host, "created"


def step_hosts(assets, report):
    linked = created = 0
    for done, asset in enumerate(assets, start=1):
        host, how = link_host(asset)
        ip, private = addresses(asset)
        if private and not host.private_ip:
            host.set_private_ips(private)
        asset.host, asset.imported_at = host, timezone.now()
        asset.save(update_fields=["host", "imported_at"])
        linked += how == "linked"
        created += how == "created"
        report(done, f"{linked} Linked to Hosts Pvm Already Had, {created} Created")
    return f"{linked} Linked to Hosts Pvm Already Had, {created} Created (Shown under Hosts > Wiz)"


# --- Issues as findings -----------------------------------------------------------


def _qid(issue, level):
    digest = hashlib.sha1(f"{issue.title}|{issue.issue_type}|{level}".encode()).hexdigest()[:12].upper()
    return f"WIZ-{digest}"


def _definition(issue, level):
    definition, _ = VulnerabilityDefinition.objects.get_or_create(
        qid=_qid(issue, level), defaults={"title": issue.title or "Wiz Issue", "severity": SEVERITY[level]}
    )
    definition.title = (issue.title or "Wiz Issue")[:500]
    definition.severity = SEVERITY[level]
    definition.qualys_severity = level
    definition.source_name = WIZ_SOURCE
    if issue.description:
        definition.description = issue.description
    if issue.recommendation:
        definition.solution_text = issue.recommendation
    definition.save()
    return definition


def perimeter_for(asset):
    exposed = asset.exposure in ("wide", "limited")
    return Perimeter.objects.filter(internet_facing=exposed).first() or Perimeter.objects.first()


def sync_findings(asset):
    """
    Bring the Wiz findings of the asset's Pvm host in line with its issues: one per rule (two issues of the
    same rule on a host are one finding, listing both). A finding whose issues Wiz no longer lists is resolved,
    one that comes back goes to "needs review". Returns how many findings were touched.
    """
    host = asset.host
    if host is None:
        return 0
    perimeter, now, target_days = perimeter_for(asset), timezone.now(), sla.targets()
    touched = {}
    with transaction.atomic():
        for issue in asset.issues.exclude(status__in=CLOSED):
            level = LEVEL.get((issue.severity or "").upper(), 3)
            definition = _definition(issue, level)
            finding = touched.get(definition.pk)
            again = finding is not None
            if finding is None:
                finding = VulnerabilityFinding.objects.filter(
                    host=host, vulnerability_definition=definition, service_port="", perimeter=perimeter
                ).first()
            since = issue.created_at_wiz or now
            if finding is None:
                finding = VulnerabilityFinding(
                    host=host, vulnerability_definition=definition, service_port="", perimeter=perimeter,
                    status=Status.NEW, first_detected_at=since, last_detected_at=now,
                )
                sla.start_clock(finding, since)
            elif not again:
                if finding.status == Status.RESOLVED:
                    finding.status, finding.resolved_at = Status.NEEDS_REVIEW, None
                    sla.start_clock(finding, now)
                elif finding.status == Status.NEW and finding.pk:
                    finding.status = Status.STILL_OPEN
            ids = (finding.extra_data.get("Wiz Issues", []) if again else []) + [issue.wiz_id]
            finding.extra_data = {
                "Reported By": WIZ_SOURCE, "Wiz Issues": ids, "Wiz Link": issue.portal_url, "Issue Type": issue.issue_type,
                "Wiz Status": issue.status, "Resource": asset.name, "Cloud": asset.cloud_platform,
                "Due in Wiz": issue.due_at.strftime("%Y-%m-%d") if issue.due_at else "",
            }
            finding.detection_result = "\n".join(filter(None, [
                issue.title, f"Resource: {asset.name} ({asset.resource_type})" if asset.name else "",
                f"Wiz: {issue.portal_url}" if issue.portal_url else "",
            ]))
            finding.last_detected_at = now
            if finding.status != Status.RESOLVED:
                sla.apply(finding, target_days)
            finding.save()
            touched[definition.pk] = finding
        gone = VulnerabilityFinding.objects.filter(
            host=host, vulnerability_definition__source_name=WIZ_SOURCE
        ).exclude(status=Status.RESOLVED).exclude(pk__in=[f.pk for f in touched.values()])
        resolved = gone.update(status=Status.RESOLVED, resolved_at=now)
        priority.recompute(host.findings.filter(vulnerability_definition__source_name=WIZ_SOURCE))
    return len(touched) + resolved


def step_findings(assets, report):
    touched = 0
    for done, asset in enumerate(assets, start=1):
        touched += sync_findings(asset)
        report(done, f"{touched} Findings")
    issues = sum(a.issues.exclude(status__in=CLOSED).count() for a in assets)
    return f"{issues} Issues Became {touched} Findings (Vulnerabilities > Wiz)"


# --- Qualys ------------------------------------------------------------------------


def _real_hosts(assets):
    return [a for a in assets if a.host and a.host.ip_address != NO_ADDRESS]


def step_csam(assets, user, report):
    from . import csam
    from .patch_views import start_check

    if not csam.configured():
        return ("skipped", "Qualys Csam Is Not Configured in .env")
    targets = _real_hosts(assets)
    for asset in assets:
        if asset not in targets:
            asset.csam_note = "Skipped: the Host Has No Address"
    if not targets:
        WizAsset.objects.bulk_update(assets, ["csam_note"])
        return ("skipped", "No Host Has an Address to Look For in Csam")
    csam.fail_stale_searches(CsamSearch)
    if CsamSearch.objects.filter(state=CsamSearch.State.RUNNING).exists():
        return ("skipped", "A Csam Search Is Already Running: Try Again When It Ends")
    search = CsamSearch.objects.create(started_by=user)
    try:
        csam.run_search(search, [a.host for a in targets])
        search.state = CsamSearch.State.DONE
    except Exception as exc:
        search.state, search.error = CsamSearch.State.FAILED, str(exc)[:2000]
        raise
    finally:
        search.finished_at = timezone.now()
        search.save()
    by_host = {p.host_id: p for p in search.proposals.select_related("host")}
    applied = 0
    for done, asset in enumerate(targets, start=1):
        proposal = by_host.get(asset.host_id)
        if proposal is None:
            asset.csam_note = "No Match in Qualys Csam"
        else:
            changed = csam.apply(proposal, csam.KINDS, user, remove_manual=False)
            proposal.imported_at, proposal.imported_by = timezone.now(), user
            proposal.save(update_fields=["imported_at", "imported_by"])
            asset.csam_note = f"Matched by {proposal.matched_by}: " + (", ".join(changed) if changed else "Nothing New")
            if {"Ubuntu Release", "Rocky Release"} & set(changed) or any(c.endswith("Packages") for c in changed):
                start_check(Host.objects.get(pk=asset.host_id))
            applied += bool(changed)
        report(done, f"{len(by_host)} Matched in Csam, {applied} Updated")
    WizAsset.objects.bulk_update(assets, ["csam_note"])
    return f"{len(by_host)} of {len(targets)} Hosts Matched in Csam, {applied} Updated; {len(assets) - len(targets)} Skipped (No Address)"


def step_pm(assets, user, report):
    from . import csam, qualys_pm

    if not csam.configured():
        return ("skipped", "Qualys Pm Is Not Configured in .env")
    hosts = [a.host for a in _real_hosts(assets) if a.host.is_windows]
    for asset in assets:
        asset.pm_note = "" if asset.host in hosts else "Skipped: Not a Windows Host with an Address"
    if not hosts:
        WizAsset.objects.bulk_update(assets, ["pm_note"])
        return ("skipped", "None of the Hosts Is a Windows Host (Pm Only Checks Those)")
    search = PmSearch.objects.create(started_by=user)
    try:
        matches = qualys_pm.run_search(search, only=hosts)
        search.state = PmSearch.State.DONE
    except Exception as exc:
        search.state, search.error = PmSearch.State.FAILED, str(exc)[:2000]
        raise
    finally:
        search.finished_at = timezone.now()
        search.save()
    matched = {h.pk: how for h, _, how in matches}
    for asset in assets:
        if asset.host in hosts:
            asset.pm_note = f"Matched by {matched[asset.host.pk]}" if asset.host.pk in matched else "No Match in Qualys Pm"
    WizAsset.objects.bulk_update(assets, ["pm_note"])
    return f"{len(matched)} of {len(hosts)} Windows Hosts Matched in Pm; {search.findings_checked} Findings Checked"
