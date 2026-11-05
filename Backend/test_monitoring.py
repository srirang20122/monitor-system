"""Tests for monitoring.py using mocked Prometheus, Loki, Tempo and Grafana.

Run:  pytest -q
"""
import httpx
import pytest
from fastapi.testclient import TestClient

import main
import monitoring

monitoring.GRAFANA_TOKEN = "test-token"


class Upstream:
    """Records requests and answers from a {path: response} table."""

    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.routes: dict[str, httpx.Response | Exception] = {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        result = self.routes.get(request.url.path)
        if result is None:
            return httpx.Response(404, text="no such route in test")
        if isinstance(result, Exception):
            raise result
        return result

    def last(self) -> httpx.Request:
        return self.requests[-1]


@pytest.fixture
def api(tmp_path):
    main.DB_PATH = str(tmp_path / "test.db")
    main.init_db()
    upstream = Upstream()
    with TestClient(main.app) as client:
        # Swap the real HTTP client for one that talks to the mock.
        client.app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
        client.post(
            "/auth/register",
            json={"full_name": "Test User", "email": "t@example.com", "password": "password123"},
        )
        token = client.post(
            "/auth/login", json={"email": "t@example.com", "password": "password123"}
        ).json()["access_token"]
        client.headers["Authorization"] = f"Bearer {token}"
        client.upstream = upstream
        yield client


def ok(body) -> httpx.Response:
    return httpx.Response(200, json=body)


# ---------- auth ----------
def test_requires_login(api):
    api.headers.pop("Authorization")
    assert api.get("/api/metrics/names").status_code == 401
    assert api.upstream.requests == []


# ---------- Prometheus ----------
def test_query_range_passes_params(api):
    api.upstream.routes["/api/v1/query_range"] = ok({"status": "success", "data": {"result": []}})
    r = api.get("/api/metrics/query_range", params={"query": "up", "start": 100, "end": 200, "step": 30})
    assert r.status_code == 200
    q = dict(api.upstream.last().url.params)
    assert q == {"query": "up", "start": "100.0", "end": "200.0", "step": "30"}


def test_query_range_rejects_bad_range(api):
    r = api.get("/api/metrics/query_range", params={"query": "up", "start": 200, "end": 100})
    assert r.status_code == 400
    assert api.upstream.requests == []


def test_path_segments_are_url_encoded(api):
    api.upstream.routes["/api/search/tag/my tag/values"] = ok({"tagValues": []})
    assert api.get("/api/traces/tags/my%20tag/values").status_code == 200
    assert api.upstream.last().url.raw_path == b"/api/search/tag/my%20tag/values"


# ---------- Loki ----------
def test_logs_query_converts_seconds_to_nanoseconds(api):
    api.upstream.routes["/loki/api/v1/query_range"] = ok({"status": "success"})
    api.get("/api/logs/query_range", params={"query": '{app="x"}', "start": 1700000000, "end": 1700000060})
    q = dict(api.upstream.last().url.params)
    assert q["start"] == "1700000000000000000"
    assert q["end"] == "1700000060000000000"
    assert q["limit"] == "100" and q["direction"] == "backward"


def test_logs_limit_is_bounded(api):
    r = api.get("/api/logs/query_range", params={"query": "{a=\"b\"}", "start": 1, "end": 2, "limit": 99999})
    assert r.status_code == 422


# ---------- Tempo ----------
def test_trace_by_id_asks_for_json(api):
    api.upstream.routes["/api/traces/0123456789abcdef"] = ok({"batches": []})
    r = api.get("/api/traces/0123456789abcdef")
    assert r.status_code == 200
    assert api.upstream.last().headers["accept"] == "application/json"


def test_trace_id_is_validated(api):
    assert api.get("/api/traces/not-a-trace-id").status_code == 422
    assert api.upstream.requests == []


def test_trace_not_found_maps_to_404(api):
    api.upstream.routes["/api/traces/0123456789abcdef"] = httpx.Response(404, text="trace not found")
    assert api.get("/api/traces/0123456789abcdef").status_code == 404


def test_trace_search_param_names_and_rules(api):
    api.upstream.routes["/api/search"] = ok({"traces": []})
    api.get(
        "/api/traces/search",
        params={"tags": "service.name=auth", "min_duration": "100ms", "start": 10, "end": 20, "limit": 5},
    )
    q = dict(api.upstream.last().url.params)
    assert q == {"limit": "5", "tags": "service.name=auth", "minDuration": "100ms", "start": "10", "end": "20"}

    assert api.get("/api/traces/search", params={"tags": "a=b", "q": "{}"}).status_code == 400
    assert api.get("/api/traces/search", params={"start": 10}).status_code == 400


# ---------- Grafana ----------
def test_grafana_sends_service_account_token(api):
    api.upstream.routes["/api/alertmanager/grafana/api/v2/alerts"] = ok([])
    assert api.get("/api/alerts/grafana").status_code == 200
    req = api.upstream.last()
    assert req.headers["authorization"] == "Bearer test-token"
    assert dict(req.url.params) == {"active": "true", "silenced": "false", "inhibited": "false"}


def test_grafana_without_token_is_503(api, monkeypatch):
    monkeypatch.setattr(monitoring, "GRAFANA_TOKEN", "")
    assert api.get("/api/alerts/grafana").status_code == 503
    assert api.upstream.requests == []


# ---------- error mapping ----------
@pytest.mark.parametrize(
    "upstream_status, expected",
    [(400, 400), (422, 400), (404, 404), (401, 502), (403, 502), (500, 502), (503, 502)],
)
def test_upstream_status_mapping(api, upstream_status, expected):
    api.upstream.routes["/api/v1/label/__name__/values"] = httpx.Response(upstream_status, text="boom")
    assert api.get("/api/metrics/names").status_code == expected


def test_upstream_401_never_reaches_browser_as_401(api):
    # A 401 would make the Angular interceptor sign the user out.
    api.upstream.routes["/api/v1/targets"] = httpx.Response(401, text="nope")
    assert api.get("/api/metrics/targets").status_code != 401


def test_timeout_and_unreachable(api):
    api.upstream.routes["/api/v1/targets"] = httpx.ReadTimeout("slow")
    assert api.get("/api/metrics/targets").status_code == 504
    api.upstream.routes["/api/v1/targets"] = httpx.ConnectError("down")
    assert api.get("/api/metrics/targets").status_code == 502


def test_non_json_upstream_is_502(api):
    api.upstream.routes["/api/v1/targets"] = httpx.Response(200, text="<html>")
    assert api.get("/api/metrics/targets").status_code == 502


# ---------- stack status and overview ----------
def test_stack_status_reports_each_tool(api):
    api.upstream.routes["/-/healthy"] = httpx.Response(200, text="ok")
    api.upstream.routes["/ready"] = httpx.Response(503, text="not ready")  # shared by loki and tempo
    api.upstream.routes["/api/health"] = httpx.ConnectError("down")
    body = api.get("/api/stack/status").json()
    assert body["prometheus"] == {"up": True, "detail": "ok"}
    assert body["loki"] == {"up": False, "detail": "HTTP 503"}
    assert body["tempo"] == {"up": False, "detail": "HTTP 503"}
    assert body["grafana"] == {"up": False, "detail": "unreachable"}


def test_overview_counts(api):
    api.upstream.routes["/api/v1/query"] = ok(
        {"data": {"result": [{"value": [0, "1"]}, {"value": [0, "1"]}, {"value": [0, "0"]}]}}
    )
    api.upstream.routes["/api/v1/alerts"] = ok(
        {"data": {"alerts": [{"state": "firing"}, {"state": "pending"}, {"state": "firing"}]}}
    )
    api.upstream.routes["/api/alertmanager/grafana/api/v2/alerts"] = ok([{}, {}])
    assert api.get("/api/overview").json() == {
        "targets": {"total": 3, "up": 2},
        "prometheus_alerts": {"firing": 2, "pending": 1},
        "grafana_alerts": {"active": 2},
    }


def test_overview_survives_one_source_down(api):
    api.upstream.routes["/api/v1/query"] = ok({"data": {"result": []}})
    api.upstream.routes["/api/v1/alerts"] = httpx.ConnectError("down")
    api.upstream.routes["/api/alertmanager/grafana/api/v2/alerts"] = ok([])
    body = api.get("/api/overview").json()
    assert body["targets"] == {"total": 0, "up": 0}
    assert body["prometheus_alerts"] == {"error": "Prometheus is unreachable"}
    assert body["grafana_alerts"] == {"active": 0}
