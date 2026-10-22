"""Imports > Wiz, Hosts > Wiz, Vulnerabilities > Wiz (the vulnerabilities tab) and the page of one Wiz host."""

import json

from django.conf import settings
from django.contrib import messages
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count, F, Q, TextField
from django.db.models.functions import Cast
from django.http import HttpResponse, QueryDict
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST

from accounts.permissions import editor_required

from . import audit, wiz, wiz_import
from .models import Host, WizAsset, WizRun, WizVulnerability
from .sorting import sorting
from .tasks import run_wiz

ROWS_SHOWN = 500

ASSET_COLUMNS = [
    ("name", "Host", "name", "asc", False),
    ("type", "Type", "resource_type", "asc", False),
    ("cloud", "Cloud", "cloud_platform", "asc", False),
    ("region", "Region", "region", "asc", False),
    ("addresses", "Addresses", "ip_text", "asc", False),
    ("exposure", "Exposure", "exposure", "asc", False),
    ("issues", "Issues", "issue_count", "desc", True),
    ("vulns", "Vulnerabilities", "vuln_count", "desc", True),
    ("imported", "Imported", "imported_at", "desc", False),
]
LISTED_COLUMNS = [c for c in ASSET_COLUMNS if c[0] != "vulns"]

VULN_COLUMNS = [
    ("cve", "CVE", "name", "asc", False),
    ("severity", "Severity", "severity_rank", "asc", False),
    ("score", "Score", "score", "desc", True),
    ("host", "Host", "asset__name", "asc", False),
    ("package", "Package", "package", "asc", False),
    ("installed", "Installed", "version", "asc", False),
    ("fixed", "Fixed In", "fixed_version", "asc", False),
    ("exploit", "Exploit", "exploit_rank", "desc", False),
    ("detected", "First Detected", "first_detected_at", "desc", False),
]

EXPOSURE_LABELS = {"wide": "Internet, Wide", "limited": "Internet, Limited", "none": "Not Exposed"}


def _assets(get, imported=None):
    """(the assets of the list, those matching the search and the filters). `imported`: True, False or None for both. Every field is searched."""
    base = WizAsset.objects.annotate(
        ip_text=Cast("ip_addresses", TextField()), props_text=Cast("properties", TextField()),
        vuln_count=Count("vulnerabilities", distinct=True),
    )
    if imported is not None:
        base = base.filter(imported_at__isnull=not imported)
    qs = base
    for param, field in (("type", "resource_type"), ("cloud", "cloud_platform"), ("region", "region"), ("exposure", "exposure"), ("severity", "worst_severity")):
        if get.get(param):
            qs = qs.filter(**{field: get[param]})
    q = get.get("q", "").strip()
    for word in q.split():
        match = Q()
        for field in ("name", "wiz_id", "resource_type", "native_type", "cloud_platform", "region", "subscription", "os_name",
                      "ip_text", "props_text", "csam_note", "pm_note", "worst_severity", "exposure", "host__hostname"):
            match |= Q(**{f"{field}__icontains": word})
        match |= Q(issues__title__icontains=word)
        qs = qs.filter(match)
    return base, qs.distinct()


def _choices(base):
    def values(field):
        return sorted(v for v in base.values_list(field, flat=True).distinct() if v)

    return {
        "types": values("resource_type"), "clouds": values("cloud_platform"), "regions": values("region"),
        "exposures": [(k, v) for k, v in EXPOSURE_LABELS.items()], "severities": [(s, s.title()) for s in wiz.SEVERITIES[:4]],
    }


def _run_context():
    wiz_import.fail_stale_runs()
    issues_run = WizRun.objects.filter(kind=WizRun.Kind.ISSUES).first()
    full_run = WizRun.objects.filter(kind=WizRun.Kind.FULL).first()
    running = WizRun.objects.filter(state=WizRun.State.RUNNING).first()
    runs = sorted([r for r in (issues_run, full_run) if r], key=lambda r: r.started_at, reverse=True)
    return {"runs": runs, "running": running}


@editor_required
def page(request):
    context = {"configured": wiz.configured(), **_run_context()}
    if request.headers.get("HX-Request") == "true":
        if context["running"] is None:
            response = HttpResponse(status=204)  # finished while the page was polling: reload it with the result
            response["HX-Refresh"] = "true"
            return response
        return render(request, "core/imports/partials/wiz_runs.html", context)
    field, direction, sort, headers = sorting(request, LISTED_COLUMNS, "issues")
    base, qs = _assets(request.GET)
    rows = list(qs.order_by(f"-{field}" if direction == "desc" else field, "name")[:ROWS_SHOWN])
    context.update(
        headers=headers, sort=sort, dir=direction, rows=rows, total=qs.count(), shown=len(rows),
        listed=base.count(), choices=_choices(base), q=request.GET.get("q", ""), get=request.GET,
        filtered=any(request.GET.get(k) for k in ("q", "type", "cloud", "region", "exposure", "severity")),
        query=request.GET.urlencode(), severity_choices=[(s, s.title()) for s in wiz.SEVERITIES],
        default_severities=settings.WIZ_VULN_SEVERITIES, default_issue_severities=settings.WIZ_ISSUE_SEVERITIES,
        summary={
            "hosts": base.count(), "critical": base.filter(worst_severity="CRITICAL").count(),
            "high": base.filter(worst_severity="HIGH").count(), "imported": base.filter(imported_at__isnull=False).count(),
        },
    )
    return render(request, "core/imports/wiz.html", context)


def _start(request, kind, asset_ids=(), severities=()):
    if not wiz.configured():
        messages.error(request, "Wiz Is Not Configured in .env (WIZ_API_URL, WIZ_CLIENT_ID, WIZ_CLIENT_SECRET).")
        return redirect("core:wiz")
    wiz_import.fail_stale_runs()
    if WizRun.objects.filter(state=WizRun.State.RUNNING).exists():
        messages.error(request, "A Wiz Import Is Already Running.")
        return redirect("core:wiz")
    with transaction.atomic():
        run = wiz_import.start(kind, request.user, asset_ids, severities)
        audit.log(request.user, "wiz.run_started", run, kind=kind, hosts=len(asset_ids), severities=list(severities))

        def enqueue():
            try:
                run_wiz.delay(run.pk)
            except Exception as exc:  # broker unreachable
                WizRun.objects.filter(pk=run.pk).update(state=WizRun.State.FAILED, error=f"Could Not Start the Import: {exc}")

        transaction.on_commit(enqueue)
    return redirect("core:wiz")


@editor_required
@require_POST
def start_issues(request):
    severities = [s for s in request.POST.getlist("severity") if s in wiz.SEVERITIES]
    return _start(request, WizRun.Kind.ISSUES, severities=severities)


@editor_required
@require_POST
def start_full(request):
    if request.POST.get("scope") == "all":
        ids = list(_assets(QueryDict(request.POST.get("query", "")))[1].values_list("wiz_id", flat=True))
    else:
        ids = list(WizAsset.objects.filter(pk__in=[i for i in request.POST.getlist("asset") if i.isdigit()]).values_list("wiz_id", flat=True))
    if not ids:
        messages.error(request, "Tick at Least One Host.")
        return redirect(f"{reverse('core:wiz')}?{request.POST.get('query', '')}")
    severities = [s for s in request.POST.getlist("severity") if s in wiz.SEVERITIES]
    return _start(request, WizRun.Kind.FULL, ids, severities)


# --- Hosts > Wiz ---------------------------------------------------------------------


def hosts_page(request):
    field, direction, sort, headers = sorting(request, ASSET_COLUMNS, "issues")
    base, qs = _assets(request.GET, imported=True)
    rows = list(qs.select_related("host").order_by(f"-{field}" if direction == "desc" else field, "name")[:ROWS_SHOWN])
    return render(request, "core/wiz_hosts.html", {
        "headers": headers, "sort": sort, "dir": direction, "rows": rows, "total": qs.count(), "shown": len(rows),
        "imported": base.count(), "choices": _choices(base), "q": request.GET.get("q", ""), "get": request.GET,
        "filtered": any(request.GET.get(k) for k in ("q", "type", "cloud", "region", "exposure", "severity")),
        "exposure_labels": EXPOSURE_LABELS, "query": request.GET.urlencode(),
    })


@editor_required
@require_POST
def hosts_add(request):
    """Add the ticked hosts to the main Hosts list (those with a real address only)."""
    assets = WizAsset.objects.filter(pk__in=[i for i in request.POST.getlist("asset") if i.isdigit()], host__isnull=False).select_related("host")
    added = skipped = 0
    for asset in assets:
        if asset.host.ip_address == wiz_import.NO_ADDRESS:
            skipped += 1
        elif asset.host.wiz_only:
            asset.host.wiz_only = False
            asset.host.save(update_fields=["wiz_only"])
            added += 1
    audit.log(request.user, "wiz.hosts_added", request.user, added=added, skipped=skipped)
    messages.success(request, f"{added} Host{'s' if added != 1 else ''} Added to the Hosts List."
                              + (f" {skipped} Without an Address Stay Here." if skipped else ""))
    return redirect(f"{reverse('core:wiz_hosts')}?{request.POST.get('query', '')}")


def asset_page(request, wiz_id):
    asset = get_object_or_404(WizAsset.objects.select_related("host"), wiz_id=wiz_id)
    properties = [(k, v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, sort_keys=True))
                  for k, v in sorted((asset.properties or {}).items()) if v not in (None, "", [], {})]
    vulnerabilities = asset.vulnerabilities.order_by(F("score").desc(nulls_last=True), "name")
    return render(request, "core/wiz_asset.html", {
        "asset": asset, "properties": properties, "issues": asset.issues.all(),
        "vulnerabilities": vulnerabilities[:200], "vulnerability_total": vulnerabilities.count(),
        "exposure_label": EXPOSURE_LABELS.get(asset.exposure, "Unknown"),
    })


# --- Vulnerabilities > Wiz (vulnerabilities tab) -------------------------------------------


def vulnerabilities_page(request):
    from django.db.models import Case, IntegerField, Value, When

    get = request.GET
    base = WizVulnerability.objects.filter(asset__imported_at__isnull=False).select_related("asset")
    base = base.annotate(
        severity_rank=Case(*[When(severity=s, then=Value(i)) for i, s in enumerate(wiz.SEVERITIES)], default=Value(9), output_field=IntegerField()),
        exploit_rank=Case(When(has_cisa_kev=True, then=Value(2)), When(has_exploit=True, then=Value(1)), default=Value(0), output_field=IntegerField()),
    )
    qs = base
    if get.get("severity"):
        qs = qs.filter(severity=get["severity"])
    if get.get("exploit") == "kev":
        qs = qs.filter(has_cisa_kev=True)
    elif get.get("exploit") == "yes":
        qs = qs.filter(Q(has_exploit=True) | Q(has_cisa_kev=True))
    if get.get("fix") == "yes":
        qs = qs.exclude(fixed_version="")
    elif get.get("fix") == "no":
        qs = qs.filter(fixed_version="")
    if get.get("asset", "").isdigit():
        qs = qs.filter(asset_id=get["asset"])
    q = get.get("q", "").strip()
    for word in q.split():
        match = Q()
        for field in ("name", "package", "version", "fixed_version", "detection_method", "status", "severity", "asset__name"):
            match |= Q(**{f"{field}__icontains": word})
        qs = qs.filter(match)
    field, direction, sort, headers = sorting(request, VULN_COLUMNS, "severity")
    order = F(field).desc(nulls_last=True) if direction == "desc" else F(field).asc(nulls_last=True)
    page = Paginator(qs.order_by(order, "name"), 50).get_page(get.get("page"))
    params = get.copy()
    params.pop("page", None)
    return render(request, "core/wiz_vulnerabilities.html", {
        "page": page, "headers": headers, "sort": sort, "dir": direction, "q": q, "get": get,
        "query": params.urlencode(), "total": qs.count(),
        "severities": [(s, s.title()) for s in wiz.SEVERITIES],
        "assets": WizAsset.objects.filter(imported_at__isnull=False).order_by("name").values_list("pk", "name"),
        "filtered": any(get.get(k) for k in ("q", "severity", "exploit", "fix", "asset")),
        "all_count": base.count(),
    })
