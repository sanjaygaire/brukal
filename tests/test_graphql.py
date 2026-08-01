"""
test_graphql.py — GraphQL introspection, and the soft-404 trap it has to survive.

An endpoint that answers introspection has handed over its whole schema: every type,
field and mutation, including the operations no client is meant to call.

The trap is that the commonest shape here is a single-page app returning index.html with
status 200 for every path — so a status-code or keyword check would announce a GraphQL
server on any SPA. The verdict is therefore structural: the response must genuinely
contain a __schema with types.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, FakeKali, Gate, load_scope, webmap
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.web import GovernedBrowser, WebResult
from brukal.webmap import AttackSurface

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
URL = f"http://{TARGET}:5013/graphql"

SCHEMA = json.dumps({"data": {"__schema": {"types": [
    {"name": "Query"}, {"name": "PasteObject"}, {"name": "UserObject"},
    {"name": "Mutations"}, {"name": "DeletePaste"}, {"name": "String"},
    {"name": "__Type"},
]}}})
SPA_INDEX = "<!doctype html><html><head><title>Shop</title></head><body>app</body></html>"


def test_graphql_schema_reads_only_a_real_introspection_response():
    count, notable = webmap.graphql_schema(SCHEMA)
    assert count == 6                                  # __Type excluded
    assert "UserObject" in notable and "DeletePaste" in notable
    # everything that is not a schema yields nothing, and never raises
    assert webmap.graphql_schema(SPA_INDEX) == (0, [])
    assert webmap.graphql_schema('{"errors":[{"message":"introspection disabled"}]}') == (0, [])
    assert webmap.graphql_schema('{"data":{"__schema":null}}') == (0, [])
    assert webmap.graphql_schema("") == (0, [])


class _Cage:
    def __init__(self, body: str, status: int = 200):
        self.body, self.status = body, status
        self.posted: list[str] = []

    def run(self, action):
        self.posted.append(action.url)
        return WebResult(status=self.status, url=action.url, body=self.body)


def _session(cage):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    return AssistSession(TARGET, Executor(Gate(scope), FakeKali(), audit),
                         StrategistAgent(type("L", (), {"propose": lambda *a, **k: ""})()),
                         browser=GovernedBrowser(scope, cage, audit))


def test_introspection_is_confirmed_and_names_the_mutation_surface():
    sess = _session(_Cage(SCHEMA))
    assert sess.confirm_graphql_introspection(URL) is True
    f = next(f for f in sess.findings.all() if f.title.startswith("GraphQL"))
    assert f.confirmed and f.severity == "medium" and f.category == "api"
    assert "6 types" in f.evidence and "DeletePaste" in f.evidence


def test_a_single_page_app_is_not_a_graphql_server():
    """The trap: 200 with index.html for every path. A status or keyword check would
    announce GraphQL on any SPA — this one must stay silent."""
    sess = _session(_Cage(SPA_INDEX))
    assert sess.confirm_graphql_introspection(URL) is False
    assert not sess.findings.all()


def test_introspection_disabled_confirms_nothing():
    sess = _session(_Cage('{"errors":[{"message":"GraphQL introspection is not allowed"}]}'))
    assert sess.confirm_graphql_introspection(URL) is False


def test_candidate_endpoints_prefer_what_the_crawl_actually_found():
    sess = _session(_Cage(SCHEMA))
    sess.surface = AttackSurface(seed=f"http://{TARGET}:5013/")
    sess.surface.add_routes(["/api/graphql"])
    urls = sess.graphql_endpoints()
    assert urls[0].endswith("/api/graphql")            # mined route leads
    assert any(u.endswith("/graphql") for u in urls)   # conventional paths still tried
    assert len(urls) <= 8


def test_out_of_scope_graphql_probe_is_denied():
    cage = _Cage(SCHEMA)
    sess = _session(cage)
    assert sess.confirm_graphql_introspection("http://8.8.8.8/graphql") is False
    assert cage.posted == []


# --- schema recovery without introspection, and batching -------------------------

SUGGESTION = json.dumps({"errors": [{"message":
    'Cannot query field "pastse" on type "Query". Did you mean "paste" or "pastes"?'}]})
BATCH_OK = json.dumps([{"data": {"__typename": "Query"}}] * 3)


def test_field_suggestions_are_confirmed_when_introspection_is_shut():
    sess = _session(_Cage(SUGGESTION))
    assert sess.confirm_graphql_suggestions(URL) is True
    f = next(f for f in sess.findings.all() if "suggestions" in f.title)
    assert f.confirmed and f.severity == "medium"
    assert "'paste'" in f.evidence


def test_suggestions_are_not_reported_when_introspection_is_already_open():
    """The schema is one query away there, so this would be noise in the report."""
    sess = _session(_Cage(SUGGESTION))
    assert sess.confirm_graphql_suggestions(URL, introspection_open=True) is False
    assert not sess.findings.all()


def test_an_error_without_a_suggestion_confirms_nothing():
    sess = _session(_Cage(json.dumps({"errors": [{"message":
        'Cannot query field "brukalNoSuchField" on type "Query".'}]})))
    assert sess.confirm_graphql_suggestions(URL) is False


def test_batching_is_confirmed_structurally():
    sess = _session(_Cage(BATCH_OK))
    assert sess.confirm_graphql_batching(URL) is True
    f = next(f for f in sess.findings.all() if "batching" in f.title)
    assert f.confirmed and "3 operations" in f.evidence


def test_a_server_that_refuses_batches_confirms_nothing():
    """A single object, an error, or a mismatched count all mean batching is off — only
    an array answering every operation sent proves it."""
    for body in (json.dumps({"data": {"__typename": "Query"}}),
                 json.dumps({"errors": [{"message": "Batching is not supported"}]}),
                 json.dumps([{"data": {"__typename": "Query"}}]),      # wrong count
                 "<html>not json</html>"):
        sess = _session(_Cage(body))
        assert sess.confirm_graphql_batching(URL) is False, body[:40]
        assert not sess.findings.all()
