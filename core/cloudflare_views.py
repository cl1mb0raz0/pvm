"""
Imports > Cloudflare: the DNS records of the zones the servers sit behind
(core.cloudflare), read from the API or loaded from a file. Loading only
stores the records; "Apply to Hosts" sets the origin address of each proxied
site as the host's private IP, after a backup.
"""

from django.contrib import messages
from django.db import transaction
from django.db.models import Count, Q
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST

from accounts.permissions import editor_required
from backups.models import Backup
from backups.service import create_backup

from . import audit, cloudflare
from .models import CloudflareCollection
from .tasks import collect_cloudflare

ROWS_SHOWN = 500
MAX_UPLOAD_BYTES = 20 * 1024 * 1024


@editor_required
def page(request):
    cloudflare.fail_stale_collections()
    run = CloudflareCollection.objects.select_related("started_by").first()
    running = bool(run and run.state == CloudflareCollection.State.RUNNING)
    context = {"configured": cloudflare.configured(), "run": run, "running": running}
    if request.headers.get("HX-Request") == "true":
        if not running:
            # Finished while the page was polling: reload it with the results.
            response = HttpResponse(status=204)
            response["HX-Refresh"] = "true"
            return response
        return render(request, "core/imports/partials/cloudflare_status.html", context)

    current = cloudflare.latest()
    context["current"] = current
    if current:
        planned = cloudflare.plan()
        context["planned"] = planned
        context["counts"] = {s: sum(1 for r in planned if r["status"] == s) for s in ("new", "changed", "same", "direct", "unresolved")}
        context["to_change"] = context["counts"]["new"] + context["counts"]["changed"]
        q = request.GET.get("q", "").strip()
        records = current.records.all()
        if q:
            records = records.filter(Q(name__icontains=q) | Q(content__icontains=q))
        context.update(
            q=q, total=records.count(), records=list(records[:ROWS_SHOWN]),
            kinds=dict(current.records.values_list("type").annotate(n=Count("pk"))),
            proxied=current.records.filter(proxied=True).count(),
        )
        context["shown"] = len(context["records"])
    return render(request, "core/imports/cloudflare.html", context)


@editor_required
@require_POST
def collect(request):
    if not cloudflare.configured():
        messages.error(request, "Cloudflare Is Not Configured in .env (CLOUDFLARE_API_TOKEN).")
        return redirect("core:cloudflare")
    if CloudflareCollection.objects.filter(state=CloudflareCollection.State.RUNNING).exists():
        messages.error(request, "A Cloudflare Collection Is Already Running.")
        return redirect("core:cloudflare")
    with transaction.atomic():
        collection = CloudflareCollection.objects.create(started_by=request.user)
        audit.log(request.user, "cloudflare.collect_started", collection)

        def enqueue():
            try:
                collect_cloudflare.delay(collection.pk)
            except Exception as exc:  # broker unreachable
                CloudflareCollection.objects.filter(pk=collection.pk).update(
                    state=CloudflareCollection.State.FAILED, error=f"Could Not Start the Collection: {exc}"
                )

        transaction.on_commit(enqueue)
    return redirect("core:cloudflare")


@editor_required
@require_POST
def upload(request):
    uploaded = request.FILES.get("file")
    if not uploaded:
        messages.error(request, "Choose a File.")
    elif uploaded.size > MAX_UPLOAD_BYTES:
        messages.error(request, "The File Is Larger than 20 MB.")
    else:
        try:
            collection = cloudflare.import_file(uploaded.read(), uploaded.name, request.user)
        except cloudflare.CloudflareError as exc:
            messages.error(request, str(exc))
        else:
            audit.log(request.user, "cloudflare.file_loaded", collection, filename=uploaded.name[:200], records=collection.items)
            messages.success(request, f"{collection.items} Records Loaded from {uploaded.name}. Check the Hosts Below, Then Apply.")
    return redirect("core:cloudflare")


@editor_required
@require_POST
def apply(request):
    planned = cloudflare.plan()
    if not any(r["status"] in ("new", "changed") for r in planned):
        messages.info(request, "Nothing to Apply: No Host Would Change.")
        return redirect("core:cloudflare")

    # Never change hosts without a way back: back up first, and stop if that fails.
    backup = create_backup(Backup.Kind.PRE_MAPPING, request.user, note="Automatic, Before Applying Cloudflare")
    if backup.status != Backup.Status.COMPLETED:
        messages.error(request, f"The Backup Before Applying Failed, Nothing Was Changed: {backup.error_message}")
        return redirect("core:cloudflare")
    changed = cloudflare.apply(planned)
    audit.log(request.user, "cloudflare.applied", request.user, hosts_changed=changed, backup=backup.pk)
    messages.success(
        request,
        f"Cloudflare Applied: Private IP Set on {changed} Host{'s' if changed != 1 else ''}. "
        "Search Qualys Csam Again to Match the Internal Servers.",
    )
    return redirect("core:cloudflare")
