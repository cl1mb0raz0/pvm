import os

from celery import Celery, signals

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "pvm.settings")

app = Celery("pvm")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()


@signals.worker_init.connect
@signals.beat_init.connect
def _check_settings(**kwargs):
    from pvm.startup import require_real_secret_key

    require_real_secret_key()


@signals.worker_ready.connect
def _resume_interrupted_checks(sender=None, **kwargs):
    """
    A host check running when the interactive worker stopped (e.g. a
    rebuild) is lost, and its host would show "Checking…" for ever without
    a "Check Now" button: queue it again. Duplicates of checks still waiting
    in the queue are harmless (the tracker records are then cached).
    """
    if sender is not None and str(getattr(sender, "hostname", "")).startswith("background@"):
        return
    import logging

    from django.db import DatabaseError

    from core.tasks import fail_interrupted_searches, resume_interrupted_checks

    # On a first start the worker can come up while `web` is still applying
    # the migrations, so a table may not exist yet; with no database there is
    # nothing to resume either, so this is not an error.
    for name, step in (("resume_interrupted_checks", resume_interrupted_checks), ("fail_interrupted_searches", fail_interrupted_searches)):
        try:
            step()
        except DatabaseError:
            logging.getLogger(__name__).warning("%s skipped: database not migrated yet", name)
