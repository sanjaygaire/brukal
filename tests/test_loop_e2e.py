"""
test_loop_e2e.py — the WHOLE reflex chain, driven through GroundedLoop.run().

Every other test exercises a helper directly. That left the loop's own hot path barely
run, and three separate NameErrors reached live engagements through it — each time a
helper test passed while the reflex that calls it crashed, because the test rebuilt the
logic instead of invoking it.

So this drives the real loop, once, against a scripted target that has every surface
Brukal knows how to find:

    port sweep -> crawl -> OpenAPI spec -> query params -> path params -> chat endpoint

The strategist immediately hands off, so nothing here is the model's doing: whatever the
run produces came from the deterministic reflexes. A crash anywhere in that chain fails
this test instead of a live engagement.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import AuditLog, Executor, Gate, load_scope
from brukal.agents import StrategistAgent
from brukal.assist import AssistSession
from brukal.kali import ExecResult
from brukal.loop import GroundedLoop
from brukal.web import GovernedBrowser, WebResult

SCOPE = Path(__file__).resolve().parent / "fixtures" / "scope_fast.json"
TARGET = "10.10.10.5"
BASE = f"http://{TARGET}:5000"

NMAP_OUT = f"""Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for {TARGET}
PORT     STATE SERVICE REASON
5000/tcp open  http    syn-ack ttl 64
"""

SPEC = json.dumps({
    "openapi": "3.0.0",
    "paths": {
        "/users/v1": {"get": {}},
        "/users/v1/{username}": {"get": {}},
        "/books/v1": {"get": {}},
        "/books/v1/{book_title}": {"get": {}},
        "/me": {"get": {"security": [{"bearerAuth": []}]}},
        "/rest/chat": {"post": {}},
    },
})

SQL_ERROR = ("sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) "
             "unrecognized token: \"'x''\"")

# A token the app leaks into an ordinary page, signed with a guessable key. The chain
# should notice it, analyse it, and then have something to test object-authorization with.
LEAKED_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsImlhdCI6MTc4NTU2NTk0NywiZXhwIjoxNzg1NTY5NTQ3fQ._QhbIPc6rektm1Ktesi48t9eElwrWhP_M6KlDD-ghhk"
BOOKS = json.dumps({"Books": [{"book_title": "bookA", "user": "alice"},
                              {"book_title": "bookB", "user": "bob"}]})
# A listing the app serves to anyone, carrying other people's data.
USERS = json.dumps({"users": [{"username": "name1", "email": "mail1@mail.com"},
                              {"username": "name2", "email": "mail2@mail.com"},
                              {"username": "admin", "email": "admin@mail.com"}]})


class _ScriptedKali:
    """Answers the port sweep with a real nmap transcript; anything else is inert."""
    def __init__(self):
        self.executed: list[str] = []

    def run(self, command: str) -> ExecResult:
        self.executed.append(command)
        out = NMAP_OUT if command.startswith("nmap") else f"$ {command}\n(nothing)"
        return ExecResult(command, 0, out, "")


class _ScriptedSite:
    """One target carrying every surface: an HTML root with a query parameter, an
    OpenAPI document, a path parameter concatenated into SQL, and a chat endpoint that
    obeys an injected instruction."""
    def __init__(self):
        self.seen: list[str] = []

    def run(self, action):
        url, body = action.url, (action.body or "")
        self.seen.append(url)
        path = url.split(BASE, 1)[-1] if url.startswith(BASE) else url

        if path.startswith("/openapi.json"):
            return WebResult(status=200, url=url, body=SPEC)
        if path.startswith("/swagger") or path.startswith("/api-docs"):
            return WebResult(status=404, url=url, body="not found")
        if path.startswith("/rest/chat"):
            text = body
            reply = ("BRUKALZ7Q4" if "BRUKAL" in text and "Z7Q4" in text else "hello")
            return WebResult(status=200, url=url, body=json.dumps({"reply": reply}))
        if path.startswith("/me"):
            return WebResult(status=401, url=url,
                             body='{"detail":"No authorization token provided"}')
        if path.startswith("/books/v1"):
            pass                                      # handled above
        if path.rstrip("/").endswith("/users/v1"):
            return WebResult(status=200, url=url, body=USERS)
        if path.startswith("/users/v1/"):
            value = path.rsplit("/", 1)[-1]
            if value.count("%27") % 2 == 1:          # unbalanced quote -> DB error
                return WebResult(status=500, url=url, body=SQL_ERROR)
            return WebResult(status=200, url=url, body='{"username":"name1"}')
        if path.startswith("/brukal_nonexistent"):
            return WebResult(status=404, url=url, body="not found")
        if path.rstrip("/").endswith("/books/v1"):
            return WebResult(status=200, url=url, body=BOOKS)
        if path.startswith("/books/v1/"):
            auth = (action.headers or {}).get("Authorization", "")
            if not auth:                              # protected, so a hit means authz
                return WebResult(status=401, url=url, body='{"detail":"Unauthorized"}')
            title = path.rsplit("/", 1)[-1]
            owner = {"bookA": "alice", "bookB": "bob"}.get(title)
            if owner is None:
                return WebResult(status=404, url=url, body='{"detail":"no such book"}')
            return WebResult(status=200, url=url, body=json.dumps(
                {"book_title": title, "owner": owner, "secret": f"S3CRET_{owner}"}))
        # the crawlable root: a link carrying a query parameter
        return WebResult(status=200, url=url, body=(
            '<html><body><a href="/search?q=1">search</a>'
            '<a href="/users/v1">users</a><a href="/books/v1/bookA">book</a>'
            f'<script>var t="{LEAKED_JWT}";</script></body></html>'))


HANDOFF = ("PHASE: recon\nGOAL: hand off\nREASONING: over to the operator.\n"
           "MANUAL: your move")


class _HandsOff:
    def propose(self, system, user, max_tokens=1024):
        return HANDOFF


def _run_loop(max_steps: int = 8):
    tmp = tempfile.mkdtemp()
    scope = load_scope(SCOPE)
    audit = AuditLog(Path(tmp) / "a.jsonl")
    kali = _ScriptedKali()
    site = _ScriptedSite()
    ex = Executor(Gate(scope), kali, audit, approver=lambda d: True)
    sess = AssistSession(TARGET, ex, StrategistAgent(_HandsOff()),
                         browser=GovernedBrowser(scope, site, audit))
    result = GroundedLoop(sess, max_steps=max_steps).run()
    return sess, result, kali, site, audit, tmp


def test_the_whole_reflex_chain_runs_without_crashing():
    """The regression that matters: a NameError anywhere in the chain surfaces HERE."""
    sess, result, kali, site, audit, tmp = _run_loop()
    try:
        # 1. the port sweep ran, deterministically, without the model asking
        assert any(c.startswith("nmap -Pn") for c in kali.executed), kali.executed
        # 2. the sweep's output became a real web seed on the right PORT
        assert any(":5000" in u for u in site.seen), site.seen
        # 3. the crawl mapped the site
        assert sess.surface is not None and sess.surface.pages
        # 4. the OpenAPI document was found and its endpoints folded in
        assert "/users/v1/{username}" in sess.surface.api_routes
        assert ("GET", "/me") in sess.surface.protected_routes
        # 5. the surface is judged probeable through the REAL predicate
        assert sess.probeable_surface() is True
        # 6. and the ledger is intact throughout
        assert audit.verify()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_the_chain_confirms_findings_on_every_surface_it_reaches():
    sess, result, kali, site, audit, tmp = _run_loop()
    try:
        titles = {f.title for f in sess.findings.all()}
        confirmed = {f.title for f in sess.findings.all() if f.confirmed}
        # a path parameter concatenated into SQL, reached only via the mined spec
        assert any("SQL injection" in t for t in confirmed), titles
        # the chat endpoint obeyed an injected instruction
        assert any(t.startswith("Prompt injection") for t in confirmed), titles
        # nothing is claimed about /me, which correctly refuses
        assert not any("Unauthenticated access" in t for t in titles), titles
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_the_chain_never_leaves_scope():
    """Every request the whole chain made must belong to the authorised host."""
    sess, result, kali, site, audit, tmp = _run_loop()
    try:
        for url in site.seen:
            assert url.startswith(f"http://{TARGET}"), url
        assert not sess._rate_limited      # the fast fixture must not hit the wall
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_the_chain_finds_a_leaked_token_and_uses_it():
    """A token leaked into a page should be noticed, analysed offline, and then become
    the credential that makes an object-authorization test possible — three capabilities
    that only connect when the real loop runs them in order."""
    sess, result, kali, site, audit, tmp = _run_loop()
    try:
        confirmed = {f.title for f in sess.findings.all() if f.confirmed}
        assert "JWT signed with a guessable secret" in confirmed, confirmed
        assert sess.last_jwt, "the leaked token was not retained"
        assert any(t.startswith("Broken object-level authorization")
                   for t in confirmed), confirmed
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_every_finding_carries_report_grade_enrichment():
    """Whatever the chain confirms has to survive into a report — a finding with no CVSS
    or references is not something an operator can file."""
    from brukal import knowledge

    sess, result, kali, site, audit, tmp = _run_loop()
    try:
        found = [f for f in sess.findings.all() if f.confirmed]
        assert found
        for f in found:
            e = knowledge.enrich(f.title, f.severity)
            assert e["cvss"] > 0, f.title
            assert e["refs"] and e["impact"] and e["remediation"], f.title
            assert e["impact"] != "Weakens the security posture of the target.", f.title
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_the_chain_notices_what_the_app_gives_a_stranger():
    """A listing served without credentials, carrying other people's data, is a finding
    the chain should reach on its own — and the severity must track what leaked."""
    sess, result, kali, site, audit, tmp = _run_loop()
    try:
        exposure = [f for f in sess.findings.all() if "Unauthenticated exposure" in f.title]
        assert exposure, {f.title for f in sess.findings.all()}
        f = exposure[0]
        assert f.confirmed and f.category == "api"
        assert "email" in f.evidence and "record(s)" in f.evidence
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
