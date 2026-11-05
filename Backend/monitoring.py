import asyncio
import os
from contextlib import asynccontextmanager
from typing import Annotated, Literal
from urllib.parse import quote

import httpx
from fastapi import APIRouter, FastAPI, HTTPException, Path, Query, Request

PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://localhost:9090")
LOKI_URL = os.environ.get("LOKI_URL", "http://localhost:3100")
TEMPO_URL = os.environ.get("TEMPO_URL", "http://localhost:3200")
GRAFANA_URL = os.environ.get("GRAFANA_URL", "http://localhost:3000")
# Grafana service account token (Viewer role is enough for the read endpoints below).
GRAFANA_TOKEN = os.environ.get("GRAFANA_TOKEN", "")
UPSTREAM_TIMEOUT_SECONDS = float(os.environ.get("UPSTREAM_TIMEOUT_SECONDS", "10"))

router = APIRouter(prefix="/api")


# ---------- shared HTTP client ----------
@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.http = httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT_SECONDS)
    try:
        yield
    finally:
        await app.state.http.aclose()


# Upstream status -> status returned to the browser. Anything not listed becomes 502.
# 401 and 403 are deliberately NOT passed through: the Angular interceptor signs the
# user out on any 401, and an upstream credential problem is not the user's fault.
UPSTREAM_STATUS_MAP = {400: 400, 404: 404, 422: 400}


async def fetch_json(
    request: Request,
    tool: str,
    url: str,
    *,
    params: dict | None = None,
    headers: dict | None = None,
):
    try:
        resp = await request.app.state.http.get(url, params=params, headers=headers)
    except httpx.TimeoutException:
        raise HTTPException(504, f"{tool} timed out")
    except httpx.HTTPError:
        raise HTTPException(502, f"{tool} is unreachable")

    if resp.status_code >= 400:
        status_out = UPSTREAM_STATUS_MAP.get(resp.status_code, 502)
        raise HTTPException(status_out, f"{tool} returned {resp.status_code}: {resp.text[:300]}")

    try:
        return resp.json()
    except ValueError:
        raise HTTPException(502, f"{tool} returned a response that is not JSON")


def seg(value: str) -> str:
    """Encode one URL path segment (label, tag or trace names may contain . / etc.)."""
    return quote(value, safe="")


def grafana_headers() -> dict:
    if not GRAFANA_TOKEN:
        raise HTTPException(503, "Grafana is not configured: set GRAFANA_TOKEN")
    return {"Authorization": f"Bearer {GRAFANA_TOKEN}"}


def require_range(start: float, end: float) -> None:
    if end <= start:
        raise HTTPException(400, "end must be greater than start")


def to_ns(unix_seconds: float) -> int:
    return int(unix_seconds * 1_000_000_000)


# ---------- metrics (Prometheus) ----------
@router.get("/metrics/query")
async def metrics_query(
    request: Request,
    query: Annotated[str, Query(min_length=1)],
    time: float | None = None,
):
    params = {"query": query}
    if time is not None:
        params["time"] = time
    return await fetch_json(request, "Prometheus", f"{PROMETHEUS_URL}/api/v1/query", params=params)


@router.get("/metrics/query_range")
async def metrics_query_range(
    request: Request,
    query: Annotated[str, Query(min_length=1)],
    start: float,
    end: float,
    step: Annotated[int, Query(ge=1)] = 15,
):
    require_range(start, end)
    params = {"query": query, "start": start, "end": end, "step": step}
    return await fetch_json(request, "Prometheus", f"{PROMETHEUS_URL}/api/v1/query_range", params=params)


@router.get("/metrics/names")
async def metrics_names(request: Request):
    return await fetch_json(request, "Prometheus", f"{PROMETHEUS_URL}/api/v1/label/__name__/values")


@router.get("/metrics/labels/{name}/values")
async def metrics_label_values(request: Request, name: str):
    return await fetch_json(request, "Prometheus", f"{PROMETHEUS_URL}/api/v1/label/{seg(name)}/values")


@router.get("/metrics/targets")
async def metrics_targets(request: Request):
    return await fetch_json(request, "Prometheus", f"{PROMETHEUS_URL}/api/v1/targets")


# ---------- logs (Loki) ----------
@router.get("/logs/query_range")
async def logs_query_range(
    request: Request,
    query: Annotated[str, Query(min_length=1)],
    start: float,
    end: float,
    limit: Annotated[int, Query(ge=1, le=5000)] = 100,
    direction: Literal["forward", "backward"] = "backward",
):
    require_range(start, end)
    params = {
        "query": query,
        "start": to_ns(start),
        "end": to_ns(end),
        "limit": limit,
        "direction": direction,
    }
    return await fetch_json(request, "Loki", f"{LOKI_URL}/loki/api/v1/query_range", params=params)


@router.get("/logs/labels")
async def logs_labels(request: Request):
    return await fetch_json(request, "Loki", f"{LOKI_URL}/loki/api/v1/labels")


@router.get("/logs/labels/{name}/values")
async def logs_label_values(request: Request, name: str):
    return await fetch_json(request, "Loki", f"{LOKI_URL}/loki/api/v1/label/{seg(name)}/values")


# ---------- traces (Tempo) ----------
TRACE_ID_PATTERN = r"^[0-9a-fA-F]{16,32}$"


@router.get("/traces/search")
async def traces_search(
    request: Request,
    tags: str | None = None,  # logfmt, e.g. service.name=auth-service http.status_code=500
    q: str | None = None,  # TraceQL
    min_duration: str | None = None,  # e.g. 100ms, 2s
    max_duration: str | None = None,
    start: int | None = None,  # unix seconds
    end: int | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 20,
):
    if tags and q:
        raise HTTPException(400, "Use either tags or q, not both")
    if (start is None) != (end is None):
        raise HTTPException(400, "Provide both start and end, or neither")
    if start is not None and end is not None and end <= start:
        raise HTTPException(400, "end must be greater than start")

    params: dict = {"limit": limit}
    if tags:
        params["tags"] = tags
    if q:
        params["q"] = q
    if min_duration:
        params["minDuration"] = min_duration
    if max_duration:
        params["maxDuration"] = max_duration
    if start is not None:
        params["start"] = start
        params["end"] = end
    return await fetch_json(request, "Tempo", f"{TEMPO_URL}/api/search", params=params)


@router.get("/traces/tags")
async def traces_tags(request: Request):
    return await fetch_json(request, "Tempo", f"{TEMPO_URL}/api/search/tags")


@router.get("/traces/tags/{tag}/values")
async def traces_tag_values(request: Request, tag: str):
    return await fetch_json(request, "Tempo", f"{TEMPO_URL}/api/search/tag/{seg(tag)}/values")


@router.get("/traces/{trace_id}")
async def traces_get(request: Request, trace_id: Annotated[str, Path(pattern=TRACE_ID_PATTERN)]):
    return await fetch_json(
        request,
        "Tempo",
        f"{TEMPO_URL}/api/traces/{trace_id}",
        headers={"Accept": "application/json"},
    )


# ---------- alerts (Prometheus rules and Grafana alerting) ----------
@router.get("/alerts/prometheus")
async def alerts_prometheus(request: Request):
    return await fetch_json(request, "Prometheus", f"{PROMETHEUS_URL}/api/v1/alerts")


@router.get("/alerts/grafana")
async def alerts_grafana(
    request: Request,
    active: bool = True,
    silenced: bool = False,
    inhibited: bool = False,
):
    params = {"active": active, "silenced": silenced, "inhibited": inhibited}
    return await fetch_json(
        request,
        "Grafana",
        f"{GRAFANA_URL}/api/alertmanager/grafana/api/v2/alerts",
        params=params,
        headers=grafana_headers(),
    )


# ---------- dashboards (Grafana) ----------
@router.get("/grafana/dashboards")
async def grafana_dashboards(request: Request, query: str = ""):
    params = {"type": "dash-db", "query": query}
    return await fetch_json(
        request,
        "Grafana",
        f"{GRAFANA_URL}/api/search",
        params=params,
        headers=grafana_headers(),
    )


# ---------- stack status and overview ----------
HEALTH_URLS = {
    "prometheus": f"{PROMETHEUS_URL}/-/healthy",
    "loki": f"{LOKI_URL}/ready",
    "tempo": f"{TEMPO_URL}/ready",
    "grafana": f"{GRAFANA_URL}/api/health",
}


@router.get("/stack/status")
async def stack_status(request: Request):
    async def check(name: str, url: str):
        try:
            resp = await request.app.state.http.get(url)
        except httpx.TimeoutException:
            return name, {"up": False, "detail": "timed out"}
        except httpx.HTTPError:
            return name, {"up": False, "detail": "unreachable"}
        if resp.status_code == 200:
            return name, {"up": True, "detail": "ok"}
        return name, {"up": False, "detail": f"HTTP {resp.status_code}"}

    results = await asyncio.gather(*(check(n, u) for n, u in HEALTH_URLS.items()))
    return dict(results)


def section(result, build):
    """One failed data source must not break the whole overview."""
    if isinstance(result, HTTPException):
        return {"error": result.detail}
    return build(result)


@router.get("/overview")
async def overview(request: Request):
    async def grafana_alerts():
        return await alerts_grafana(request)

    up_result, prom_alerts, graf_alerts = await asyncio.gather(
        metrics_query(request, query="up"),
        alerts_prometheus(request),
        grafana_alerts(),
        return_exceptions=True,
    )
    for r in (up_result, prom_alerts, graf_alerts):
        if isinstance(r, Exception) and not isinstance(r, HTTPException):
            raise r

    def targets(data):
        series = data["data"]["result"]
        return {"total": len(series), "up": sum(1 for s in series if s["value"][1] == "1")}

    def prometheus_alerts(data):
        alerts = data["data"]["alerts"]
        return {
            "firing": sum(1 for a in alerts if a["state"] == "firing"),
            "pending": sum(1 for a in alerts if a["state"] == "pending"),
        }

    def grafana(data):
        return {"active": len(data)}

    return {
        "targets": section(up_result, targets),
        "prometheus_alerts": section(prom_alerts, prometheus_alerts),
        "grafana_alerts": section(graf_alerts, grafana),
    }
