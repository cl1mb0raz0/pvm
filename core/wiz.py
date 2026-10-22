"""
Wiz (cloud security), read through its GraphQL API.

What is asked, and nothing else:
- the issues (Wiz's own list of what matters: several findings combined into
  one risk), with the resource each is about;
- for the hosts chosen: the resource's properties, its vulnerabilities and,
  from those, its addresses and internet exposure.

Access is a read-only Wiz service account (client ID and secret in .env); a
token is requested from the OAuth endpoint and sent as a Bearer token.
Introspection is on, so a field Wiz refuses can be checked there. Facts
verified on the customer's tenant:
- the resource has no IP address of its own: the addresses come only from its
  vulnerability findings (`vulnerableAsset { ... on VulnerableAssetVirtualMachine }`);
- `vulnerabilityFindings` is filtered by host with `assetIdV2: {equals: id}`,
  one id per filter;
- many aliased queries in one request trigger HTTP 429: ENTITY_BATCH of them
  with a pause works, and a 429 is waited out.
"""

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request

from django.conf import settings
from django.utils.dateparse import parse_datetime

logger = logging.getLogger(__name__)

TIMEOUT_SECONDS = 120
RETRIES = 3
PAGE_SIZE = 500
ENTITY_BATCH = 10
BATCH_PAUSE_SECONDS = 1.0
RATE_RETRIES = 8
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]

ISSUES_QUERY = """
query WizIssues($first: Int, $after: String, $filterBy: IssueFilters) {
  issues: issuesV2(first: $first, after: $after, filterBy: $filterBy) {
    totalCount
    pageInfo { hasNextPage endCursor }
    nodes {
      id
      type
      status
      severity
      createdAt
      dueAt
      resolvedAt
      sourceRule {
        __typename
        ... on Control { id name controlDescription: description resolutionRecommendation }
        ... on CloudEventRule { id name cloudEventRuleDescription: description }
        ... on CloudConfigurationRule { id name cloudConfigurationRuleDescription: description remediationInstructions }
      }
      entitySnapshot { id type nativeType name cloudPlatform region subscriptionExternalId subscriptionName }
      projects { id name }
    }
  }
}
"""

VULNERABILITIES_QUERY = """
query WizVulnerabilities($first: Int, $after: String, $filterBy: VulnerabilityFindingFilters) {
  vulnerabilityFindings(first: $first, after: $after, filterBy: $filterBy) {
    totalCount
    pageInfo { hasNextPage endCursor }
    nodes {
      id
      name
      detailedName
      vendorSeverity
      CVSSSeverity
      score
      hasExploit
      hasCisaKevExploit
      status
      vulnerabilityExternalId
      version
      fixedVersion
      detectionMethod
      firstDetectedAt
      lastDetectedAt
      link
      portalUrl
      vulnerableAsset {
        ... on VulnerableAssetBase { id type name }
        ... on VulnerableAssetVirtualMachine { operatingSystem ipAddresses hasWideInternetExposure hasLimitedInternetExposure }
      }
    }
  }
}
"""

ENTITY_FIELDS = "id name type firstSeen lastSeen properties"


class WizError(Exception):
    """The API could not be reached or refused; the message is shown to the user."""


def configured():
    return bool(settings.WIZ_API_URL and settings.WIZ_CLIENT_ID and settings.WIZ_CLIENT_SECRET)


class Client:
    def __init__(self):
        if not configured():
            raise WizError("Wiz Is Not Configured: Set WIZ_API_URL, WIZ_CLIENT_ID and WIZ_CLIENT_SECRET in .env.")
        self.calls = 0
        self.token = self._authenticate()

    def _authenticate(self):
        data = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "audience": "wiz-api",
                "client_id": settings.WIZ_CLIENT_ID,
                "client_secret": settings.WIZ_CLIENT_SECRET,
            }
        ).encode()
        request = urllib.request.Request(
            settings.WIZ_AUTH_URL, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as r:
                token = json.load(r).get("access_token")
        except urllib.error.HTTPError as exc:
            if exc.code in (400, 401, 403):
                raise WizError("Wiz Refused the Service Account in .env (Client ID, Secret or Auth URL).") from exc
            raise WizError(f"Wiz Authentication Answered {exc.code}.") from exc
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise WizError(f"Wiz Authentication Unreachable (Is the Network Open to It?): {exc}") from exc
        if not token:
            raise WizError("Wiz Authentication Gave No Access Token.")
        return token

    def graphql(self, query, variables=None):
        """One GraphQL call: retries a 5xx / network error, waits out a 429, raises WizError on GraphQL errors."""
        body = json.dumps({"query": query, "variables": variables or {}}).encode()
        attempt = limited = 0
        while True:
            request = urllib.request.Request(
                settings.WIZ_API_URL, data=body, method="POST",
                headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
            )
            self.calls += 1
            try:
                with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as r:
                    data = json.loads(r.read())
            except urllib.error.HTTPError as exc:
                if exc.code == 429 and limited < RATE_RETRIES:
                    limited += 1
                    time.sleep(min(int(exc.headers.get("Retry-After") or 0) or 5 * 2 ** limited, 60))
                    continue
                attempt += 1
                if exc.code in (500, 502, 503, 504) and attempt < RETRIES:
                    time.sleep(10)
                    continue
                raise WizError(f"Wiz API Answered {exc.code}: {_messages(exc.read())}") from exc
            except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
                attempt += 1
                if attempt < RETRIES:
                    time.sleep(10)
                    continue
                raise WizError(f"Wiz API Unreachable: {exc}") from exc
            if data.get("errors"):
                raise WizError(f"Wiz API Refused the Query: {_messages(data)}")
            return data.get("data") or {}

    def pages(self, query, field, filter_by=None, on_page=None):
        """Every node of the connection `field`, page after page; `on_page(total)` is called after each page."""
        after = None
        while True:
            data = self.graphql(query, {"first": PAGE_SIZE, "after": after, "filterBy": filter_by})
            connection = data.get(field) or {}
            yield from connection.get("nodes") or []
            if on_page:
                on_page(connection.get("totalCount"))
            info = connection.get("pageInfo") or {}
            if not info.get("hasNextPage") or not info.get("endCursor"):
                return
            after = info["endCursor"]

    def issues(self, on_page=None, severities=()):
        """Every issue of these severities (all when none)."""
        filter_by = {"status": settings.WIZ_ISSUE_STATUSES}
        if severities:
            filter_by["severity"] = list(severities)
        return self.pages(ISSUES_QUERY, "issues", filter_by, on_page)

    def vulnerabilities(self, wiz_id, severities=()):
        """Every vulnerability of one host, of these severities (all when none)."""
        filter_by = {"status": settings.WIZ_VULN_STATUSES, "assetIdV2": {"equals": wiz_id}}
        if severities:
            filter_by["vendorSeverity"] = list(severities)
        return self.pages(VULNERABILITIES_QUERY, "vulnerabilityFindings", filter_by)

    def entities(self, wiz_ids):
        """{wiz id: graph entity} for these resources (ENTITY_BATCH aliased lookups in one request)."""
        declarations = ", ".join(f"$i{n}: ID!" for n in range(len(wiz_ids)))
        body = "\n".join(f"e{n}: graphEntity(id: $i{n}) {{ {ENTITY_FIELDS} }}" for n in range(len(wiz_ids)))
        data = self.graphql(f"query({declarations}) {{ {body} }}", {f"i{n}": i for n, i in enumerate(wiz_ids)})
        return {i: data.get(f"e{n}") for n, i in enumerate(wiz_ids) if data.get(f"e{n}")}


def _messages(body):
    """Every GraphQL error message of an answer (bytes or parsed), so one refusal shows all the fields Wiz rejects."""
    try:
        data = json.loads(body) if isinstance(body, (bytes, str)) else body
        return "; ".join(str(e.get("message", e))[:200] for e in data["errors"][:15])
    except (ValueError, KeyError, TypeError, AttributeError):
        return (body if isinstance(body, str) else body.decode(errors="replace"))[:500]


def clip(value, model, field):
    return str(value or "")[: model._meta.get_field(field).max_length]


def when(value):
    return parse_datetime(value) if isinstance(value, str) and value else None


def issue_fields(node):
    """The WizIssue fields of an issue node."""
    from .models import WizIssue

    rule = node.get("sourceRule") or {}
    description = rule.get("controlDescription") or rule.get("cloudEventRuleDescription") or rule.get("cloudConfigurationRuleDescription") or ""
    recommendation = rule.get("resolutionRecommendation") or rule.get("remediationInstructions") or ""
    return {
        "wiz_id": node["id"],
        "title": clip(rule.get("name"), WizIssue, "title"),
        "description": str(description),
        "recommendation": str(recommendation),
        "issue_type": clip(node.get("type"), WizIssue, "issue_type"),
        "severity": clip((node.get("severity") or "").upper(), WizIssue, "severity"),
        "status": clip(node.get("status"), WizIssue, "status"),
        "projects": [str(p.get("name")) for p in node.get("projects") or [] if isinstance(p, dict) and p.get("name")],
        "created_at_wiz": when(node.get("createdAt")),
        "due_at": when(node.get("dueAt")),
        "resolved_at": when(node.get("resolvedAt")),
        "raw": node,
    }


def asset_fields(entity):
    """The WizAsset fields the issue's entitySnapshot tells."""
    from .models import WizAsset

    return {
        "name": clip(entity.get("name"), WizAsset, "name"),
        "resource_type": clip(entity.get("type"), WizAsset, "resource_type"),
        "native_type": clip(entity.get("nativeType"), WizAsset, "native_type"),
        "cloud_platform": clip(entity.get("cloudPlatform"), WizAsset, "cloud_platform"),
        "region": clip(entity.get("region"), WizAsset, "region"),
        "subscription": clip(entity.get("subscriptionName") or entity.get("subscriptionExternalId"), WizAsset, "subscription"),
    }


OS_KEYS = ("operatingSystem", "osName", "os", "image")


def entity_fields(entity):
    """The WizAsset fields the graph entity adds."""
    from .models import WizAsset

    properties = entity.get("properties") or {}
    fields = {"properties": properties, "first_seen": when(entity.get("firstSeen")), "last_seen": when(entity.get("lastSeen"))}
    os_name = next((str(properties[k]) for k in OS_KEYS if properties.get(k)), "")
    if os_name:
        fields["os_name"] = clip(os_name, WizAsset, "os_name")
    for field, key in (("cloud_platform", "cloudPlatform"), ("region", "region"), ("native_type", "nativeType")):
        if properties.get(key):
            fields[field] = clip(properties[key], WizAsset, field)
    return fields


def vulnerability_fields(node):
    from .models import WizVulnerability

    score = node.get("score")
    link = str(node.get("portalUrl") or node.get("link") or "")
    return {
        "wiz_id": node["id"],
        "name": clip(node.get("name") or node.get("vulnerabilityExternalId"), WizVulnerability, "name"),
        "severity": clip((node.get("vendorSeverity") or node.get("CVSSSeverity") or "").upper(), WizVulnerability, "severity"),
        "score": score if isinstance(score, (int, float)) else None,
        "has_exploit": bool(node.get("hasExploit")),
        "has_cisa_kev": bool(node.get("hasCisaKevExploit")),
        "status": clip(node.get("status"), WizVulnerability, "status"),
        "package": clip(node.get("detailedName"), WizVulnerability, "package"),
        "version": clip(node.get("version"), WizVulnerability, "version"),
        "fixed_version": clip(node.get("fixedVersion"), WizVulnerability, "fixed_version"),
        "detection_method": clip(node.get("detectionMethod"), WizVulnerability, "detection_method"),
        "first_detected_at": when(node.get("firstDetectedAt")),
        "last_detected_at": when(node.get("lastDetectedAt")),
        "link": clip(link, WizVulnerability, "link") if link.startswith("http") else "",
    }
