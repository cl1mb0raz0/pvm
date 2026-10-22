"""
Imports > Qualys Pm: Windows findings checked against Qualys Patch
Management (core.qualys_pm). There is no approval step, unlike Qualys
Csam: "Search Qualys Pm" writes the verdicts directly (a PatchCheck per
finding, source=qualys_pm), the same as the Ubuntu tracker's "Check Now".
This page shows the last run and, per Windows host, what it found; a
finding's own verdict and evidence are on the host page, alongside
"Confirm" (shared with the Ubuntu check, see core.patch_views).
"""

from django.contrib import messages
from django.db import transaction
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST

from accounts.permissions import editor_required

from . import audit, csam, qualys_pm
from .models import InstalledPackage, PatchCheck, PmSearch
from .sorting import sort_rows, sorting
from .tasks import search_pm

PM_COLUMNS = [
    ("host", "Windows Host", lambda r: (r["host"].hostname or "").lower(), "asc", False),
    ("checked", "Findings Checked", lambda r: r["total"], "desc", True),
    ("missing", "Vulnerable, Patch Missing", lambda r: r["missing"], "desc", True),
    ("fixed", "Fixed", lambda r: r["fixed"], "desc", True),
    ("unknown", "Cannot Verify", lambda r: r["unknown"], "desc", True),
]


HITS_SHOWN = 3  # matching items listed under a host before "+N more"


def _terms(q):
    return [t for t in (q or "").lower().split() if t]


def _matches(text, terms):
    text = text.lower()
    return all(t in text for t in terms)


def _rows(q=""):
    """
    Per Windows host with at least one checked finding, the tally of its
    verdicts. With a search `q`, only the hosts it matches, each with the
    items that matched (`hits`): the host itself (name, address, private
    IPs), software installed on it, a patch Qualys Pm named for one of its
    findings (title or KB) or a finding's QID / title. Every word of the
    search must be in the same item, so "sql 2017" finds "... SQL Server
    2017" but not a host that merely has both words in unrelated places.
    Read from what Pvm already holds: no call to Qualys.
    """
    checks = PatchCheck.objects.filter(source=PatchCheck.Source.QUALYS_PM).select_related(
        "vulnerability_finding__host", "vulnerability_finding__vulnerability_definition"
    )
    terms = _terms(q)
    by_host = {}
    for check in checks:
        finding = check.vulnerability_finding
        host = finding.host
        row = by_host.setdefault(
            host.pk, {"host": host, "missing": 0, "fixed": 0, "unknown": 0, "total": 0, "items": {}}
        )
        row["total"] += 1
        if check.verdict == PatchCheck.Verdict.VULNERABLE_UPDATE:
            row["missing"] += 1
        elif check.verdict == PatchCheck.Verdict.FIXED:
            row["fixed"] += 1
        else:
            row["unknown"] += 1
        if terms:
            definition = finding.vulnerability_definition
            row["items"].setdefault("Finding", {})[f"{definition.qid} {definition.title}"] = None
            if check.verdict != PatchCheck.Verdict.UNKNOWN:
                for detail in check.details or []:
                    if detail.get("reason"):
                        row["items"].setdefault("Patch", {})[detail["reason"]] = None

    rows = list(by_host.values())
    if not terms:
        return rows

    packages = {}
    for host_id, name, version in InstalledPackage.objects.filter(host_id__in=by_host).values_list(
        "host_id", "package_name", "installed_version"
    ):
        packages.setdefault(host_id, {})[f"{name} {version}".strip()] = None

    matched = []
    for row in rows:
        host = row["host"]
        host_text = " ".join([host.hostname or "", host.ip_address or "", *host.all_private_ips])
        items = {**row["items"], "Software": packages.get(host.pk, {})}
        hits = []
        for label, texts in items.items():
            found = [t for t in texts if _matches(t, terms)]
            if found:
                hits.append({"label": label, "texts": found[:HITS_SHOWN], "more": max(0, len(found) - HITS_SHOWN)})
        # The host itself matching needs no explanation: it is the row.
        if hits or _matches(host_text, terms):
            row["hits"] = hits
            matched.append(row)
    return matched


@editor_required
def page(request):
    csam.fail_stale_searches(PmSearch)
    search = PmSearch.objects.select_related("started_by").first()
    value, direction, sort, headers = sorting(request, PM_COLUMNS, "missing")
    q = request.GET.get("q", "").strip()
    context = {
        "q": q,
        "headers": headers,
        "sort": sort,
        "dir": direction,
        "rows": sort_rows(_rows(q), value, direction),
        "search": search,
        "configured": csam.configured(),
        "running": bool(search and search.state == PmSearch.State.RUNNING),
    }
    if request.GET.get("live") and q and context["configured"] and request.headers.get("HX-Request") != "true":
        # "Search Live": ask Qualys itself (see qualys_pm.live_search for the cost).
        try:
            context["live"] = qualys_pm.live_search(q, fresh=bool(request.GET.get("fresh")))
            audit.log(
                request.user, "pm.live_search", request.user,
                query=q, api_calls=context["live"]["api_calls"], from_cache=context["live"]["from_cache"],
            )
        except qualys_pm.PmError as exc:
            context["live_error"] = str(exc)
    if search and search.state == PmSearch.State.DONE:
        context["unmatched"] = search.windows_hosts - search.matched
    if request.headers.get("HX-Request") == "true":
        if not context["running"]:
            # Finished while the page was polling: reload it with the results.
            response = HttpResponse(status=204)
            response["HX-Refresh"] = "true"
            return response
        return render(request, "core/imports/partials/pm_status.html", context)
    return render(request, "core/imports/qualys_pm.html", context)


@editor_required
@require_POST
def start(request):
    if not csam.configured():
        messages.error(request, "Qualys Pm Is Not Configured in .env (Same Credentials as Qualys Csam).")
        return redirect("core:qualys_pm")
    with transaction.atomic():
        PmSearch.objects.all().delete()  # only the latest search is kept
        search = PmSearch.objects.create(started_by=request.user)
        audit.log(request.user, "pm.search_started", search)

        def enqueue():
            try:
                search_pm.delay(search.pk)
            except Exception as exc:  # broker unreachable
                PmSearch.objects.filter(pk=search.pk).update(
                    state=PmSearch.State.FAILED, error=f"Could Not Start the Search: {exc}"
                )

        transaction.on_commit(enqueue)
    return redirect("core:qualys_pm")
