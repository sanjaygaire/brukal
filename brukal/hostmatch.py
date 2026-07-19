"""
hostmatch.py — deterministic host extraction for the scope gate (safety core).

Standard library ONLY (no third-party imports — this file is part of the
untrickable core alongside gate/scope/risk/executor/web/audit).

Given a command string or a session line, find EVERY host it references and
normalise each to a canonical string the scope check can look up:

  * URL tokens (anything containing ``://``) -> the parsed ``hostname``.
  * IPv4 / IPv6 literals.
  * Integer / 0x-hex / 0o-octal encodings that denote a routable IP — the classic
    "decimal IP" smuggle (``curl http://134744072/`` == ``8.8.8.8``). Only values
    at or above 1.0.0.0 are treated as IPs, so ``--top-ports 100`` stays a number.
  * Bare dotted hostnames used as arguments (``nmap evil.com``, ``ssh u@evil.com``),
    conservatively — a token with a path separator or a known file extension is a
    filename/path, NOT a host.

The gate enforces the policy: every host this returns must be in scope, or the
action is denied (fail-closed). This module only *finds* hosts; it never decides.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

# Integers below 1.0.0.0 (2**24) canonicalise into the 0.0.0.0/8 "this-network"
# block, which is never a routable target — that is exactly where ports, thread
# counts, and timeouts live. Only integers at/above it are read as an encoded IP,
# so `--top-ports 100` is a number while `134744072` (8.8.8.8) is a host.
_INT_HOST_MIN = 1 << 24

# A whole token that is a decimal / hex / octal integer (no leading-zero decimal).
_INT_TOKEN_RE = re.compile(r"(?:0[xX][0-9a-fA-F]+|0[oO][0-7]+|[1-9][0-9]*)\Z")

# A bare dotted hostname shape: dot-separated labels ending in an ALPHABETIC TLD
# (2-63 letters). Requiring an alphabetic final label is both correct (a real
# hostname can't have an all-numeric TLD — that would be an IP, handled above) and
# the thing that keeps dotted COMMAND names out: `mkfs.ext4`, `python3.11`, and
# `nmap.nse` end in a digit/short token, so they are not mistaken for hosts, while
# `evil.com` / `nexus.htb` still match.
_DOTTED_HOST_RE = re.compile(r"(?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,63}\Z")

# Known file extensions, so a filename / wordlist / script token is never read as a
# host (e.g. common.txt, linpeas.sh, exploit.py, scan.gnmap, backup.tar.gz).
_FILE_EXT_RE = re.compile(
    r"\.(?:txt|lst|list|log|conf|cfg|ini|json|xml|ya?ml|toml|sh|bash|zsh|py|rb|pl|"
    r"php|js|ts|go|c|cpp|h|java|html?|css|md|rst|csv|tsv|pem|key|pub|crt|cer|der|"
    r"p12|pfx|db|sqlite3?|sql|bak|old|orig|tmp|swp|zip|gz|tgz|bz2|xz|7z|rar|tar|"
    r"png|jpe?g|gif|svg|ico|bmp|webp|pdf|docx?|xlsx?|pptx?|bin|exe|dll|so|o|a|"
    r"out|dump|pcap|cap|nmap|gnmap|xsl|dtd|env|lock)\Z", re.I)


def canonical_ip(token: str) -> str | None:
    """Canonical IP string for a token that denotes an IP — a dotted IPv4, an IPv6
    literal, or an integer/hex/octal encoding at or above 1.0.0.0. Returns None for
    anything that is not an IP (including small integers that are ports/counts)."""
    t = (token or "").strip()
    if not t:
        return None
    try:
        return str(ipaddress.ip_address(t))          # dotted IPv4 or IPv6 literal
    except ValueError:
        pass
    if not _INT_TOKEN_RE.match(t):
        return None
    try:
        val = int(t, 0)
    except ValueError:
        return None
    if val < _INT_HOST_MIN:
        return None                                  # a port / count, not a host
    try:
        return str(ipaddress.ip_address(val))
    except ValueError:
        return None


def _clean(tok: str) -> str:
    return tok.strip().strip("\"'`(),<>[]{}")


def extract_hosts(text: str) -> list[str]:
    """Every host referenced in `text`, canonicalised and de-duplicated (order kept).
    See the module docstring for the classes of reference recognised. Conservative on
    bare dotted tokens so filenames/paths are not mistaken for hosts."""
    hosts: list[str] = []
    seen: set[str] = set()

    def add(h: str) -> None:
        h = (h or "").strip().lower()
        if h and h not in seen:
            seen.add(h)
            hosts.append(h)

    for raw in re.split(r"\s+", text or ""):
        tok = _clean(raw)
        if not tok:
            continue

        # 1. URL token — the host is whatever the scheme points at (canonicalise it,
        #    so an IP-encoded URL host like http://0x08080808/ becomes 8.8.8.8).
        if "://" in tok:
            host = urlsplit(tok).hostname
            if host:
                add(canonical_ip(host) or host)
            continue

        # user@host argument (ssh user@evil.com, scp f user@evil.com:/p) — the host
        # is after the '@' (only when the user part isn't itself a path).
        if "@" in tok and "/" not in tok.split("@", 1)[0]:
            tok = tok.split("@", 1)[1]

        # 2. IP literal / integer / hex / octal encoding (checked before the :port
        #    trim so an IPv6 literal's own colons are not mangled).
        ip = canonical_ip(tok)
        if ip is not None:
            add(ip)
            continue

        # a single trailing :port on a dotted host (evil.com:8080) -> keep the host.
        base = tok.split(":", 1)[0] if tok.count(":") == 1 else tok

        # 3. bare dotted hostname — conservative: reject paths and known filenames.
        if "/" in base or "\\" in base:
            continue
        if _FILE_EXT_RE.search(base):
            continue
        if _DOTTED_HOST_RE.match(base):
            # Fail-closed: if it is host-shaped but urlsplit can't extract a name,
            # still hand the literal to the scope check (which will almost certainly
            # deny it) rather than silently dropping it.
            add(urlsplit("//" + base).hostname or base)

    return hosts
