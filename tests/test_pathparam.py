"""
test_pathparam.py — REST path parameters as an injection point, and exposure scanning
of everything the GOVERNED BROWSER fetches.

Two blind spots this pins, both found by running against a live authorised API:

  * `confirm_surface` only ever probed query parameters, form fields and AI endpoints.
    On a REST API the object identifier lives in the PATH (/users/v1/{username}), which
    is where injection and broken object-level authz concentrate — and nothing touched
    it, because such a route has no query string and no form.
  * Shell tool output was scanned for exposures; browser output was not. The crawl is
    how Brukal sees content on a web target, so a stack trace, a leaked key or a SQL
    error could be read across twenty pages and recorded nowhere.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, FakeKali, Gate, load_scope, webprobe
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.web import GovernedBrowser, WebAction, WebResult
from brukal.webmap import AttackSurface

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope.json"
TARGET = "10.10.10.5"
ROUTE = f"http://{TARGET}:5000/users/v1/{{username}}"

SQL_ERROR = ('<title>sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) '
             'unrecognized token: "\'name1\'\'" [SQL: SELECT * FROM users WHERE '
             "username = 'name1'']</title>")


class _NullLLM:
    def propose(self, *a, **k):
        return ""


class _PathSqlCage:
    """An API whose path parameter is concatenated into SQL: an unbalanced quote errors,
    a balanced one does not — exactly what a live Flask+SQLAlchemy target did."""
    def __init__(self):
        self.seen: list[str] = []

    def run(self, action: WebAction) -> WebResult:
        self.seen.append(action.url)
        value = action.url.rsplit("/", 1)[-1]
        quotes = value.count("%27")
        if quotes % 2 == 1:                      # unbalanced -> the database complains
            return WebResult(status=500, url=action.url, body=SQL_ERROR)
        return WebResult(status=200, url=action.url,
                         body='{"username": "name1", "email": "mail1@mail.com"}')


def _session(cage):
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl")
    ex = Executor(Gate(scope), FakeKali(), audit)
    browser = GovernedBrowser(scope, cage, audit)
    return AssistSession(TARGET, ex, StrategistAgent(_NullLLM()), browser=browser)


def test_sql_error_signature_covers_the_common_stacks():
    """The signature knew PHP/MySQL, Oracle and Postgres but not the Python data stack,
    so a live SQLAlchemy error from an injectable parameter fired nothing."""
    def fires(body):
        return "SQL error (possible injection)" in [
            l for _s, l, _e in webprobe.scan_exposures(body)]

    assert fires(SQL_ERROR)                                     # SQLAlchemy + sqlite3
    assert fires("psycopg2.errors.SyntaxError: syntax error at or near")
    assert fires("django.db.utils.OperationalError: no such column")
    assert fires("java.sql.SQLException: ORA-00933")
    assert fires("System.Data.SqlClient.SqlException: Incorrect syntax near")
    assert fires("You have an error in your SQL syntax; check the MySQL server")  # old
    # and ordinary prose still must not
    assert not fires("<html>Our database of products is large.</html>")
    assert not fires("If you get an error, contact support.")


def test_confirm_sqli_error_on_a_path_parameter():
    sess = _session(_PathSqlCage())
    assert sess.confirm_sqli_error(ROUTE, "{username}", base="name1",
                                   method="PATH") is True
    f = next(f for f in sess.findings.all() if f.title == "SQL injection (error-based)")
    assert f.confirmed and f.severity == "critical"


def test_path_payloads_cannot_escape_the_path_segment():
    """A path payload is percent-encoded, so it can never invent a new segment or a
    query string — the request stays the one the gate ruled on."""
    cage = _PathSqlCage()
    sess = _session(cage)
    sess.confirm_sqli_error(ROUTE, "{username}", base="a/../../etc", method="PATH")
    assert cage.seen
    for url in cage.seen:
        prefix = f"http://{TARGET}:5000/users/v1/"
        assert url.startswith(prefix)
        assert "/" not in url[len(prefix):]   # payload slashes encoded, no new segment
        assert "?" not in url                 # and no query string smuggled in


def test_a_page_that_always_errors_does_not_confirm():
    """The proof is the PAIRING: error on unbalanced, clean on balanced. A page that
    errors on everything proves nothing."""
    class _AlwaysErrors:
        def run(self, action):
            return WebResult(status=500, url=action.url, body=SQL_ERROR)

    sess = _session(_AlwaysErrors())
    assert sess.confirm_sqli_error(ROUTE, "{username}", base="x", method="PATH") is False
    assert not [f for f in sess.findings.all()
                if f.title == "SQL injection (error-based)"]


def test_confirm_surface_probes_mined_path_routes():
    """The reflex reaches a path parameter with no query string and no form in sight."""
    sess = _session(_PathSqlCage())
    sess.surface = AttackSurface(seed=f"http://{TARGET}:5000/")
    sess.surface.add_routes(["/users/v1/{username}"])
    assert not sess.surface.params and not sess.surface.forms
    assert sess.confirm_surface() >= 1
    assert any(f.title.startswith("SQL injection") and f.confirmed
               for f in sess.findings.all())


def test_out_of_scope_path_probe_is_denied():
    cage = _PathSqlCage()
    sess = _session(cage)
    assert sess.confirm_sqli_error("http://8.8.8.8/users/{id}", "{id}",
                                   method="PATH") is False
    assert cage.seen == []                      # nothing left the gate


def test_crawled_pages_are_scanned_for_exposures():
    """Browser-fetched content is evidence too: the crawl reads it, so it must be
    inspected the same way shell output is."""
    class _LeakyCage:
        def run(self, action):
            return WebResult(status=200, url=action.url, body=SQL_ERROR)

    sess = _session(_LeakyCage())
    tmp = tempfile.mkdtemp()
    try:
        sess.crawl(seeds=[f"http://{TARGET}:5000/"], max_pages=1)
        titles = [f.title for f in sess.findings.all()]
        assert "SQL error (possible injection)" in titles
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_reflex_gate_counts_path_routes_as_probeable():
    """Regression: an API mined from its own spec has 0 params, 0 forms and no AI
    endpoint, so the confirm reflex skipped it entirely and the path-parameter probing
    above was unreachable in a real run — the same shape of miss twice over."""
    import re as _re
    sess = _session(_PathSqlCage())
    sess.surface = AttackSurface(seed=f"http://{TARGET}:5000/")
    sess.surface.add_routes(["/users/v1/{username}", "/books/v1"])
    assert not sess.surface.params and not sess.surface.forms
    assert not sess._ai_endpoints()
    probeable = bool(
        sess.surface.params or sess.surface.forms or sess._ai_endpoints()
        or any(_re.search(r"\{[^{}/]{1,40}\}", r) for r in sess.surface.api_routes))
    assert probeable, "path-parameter routes must make a surface probeable"
