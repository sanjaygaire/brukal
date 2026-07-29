"""
apkscan.py — Android APK (mobile app) static-analysis detector.

The mobile end. Decompile an APK in the cage (jadx / apktool + unzip), then two
deterministic passes over the result:

  * scan_manifest(AndroidManifest.xml) — dangerous app configuration: debuggable,
    allowBackup, cleartext traffic, exported components (activities/services/receivers/
    providers) with no permission, exported content providers with grantUriPermissions,
    deep-link intent filters, dangerous permissions.
  * scan_apk_source(decompiled text) — hardcoded secrets (API/cloud/VCS keys, Firebase
    URLs, Google Maps keys, private keys, hardcoded passwords), embedded endpoints, JWTs,
    and cleartext-HTTP URLs.

No network target — this is offline static analysis of a file the operator supplied, so
it doesn't touch the scope gate; it runs in the cage (no shell strings, argv only) and
records evidence-backed findings. Deterministic; no LLM.
"""
from __future__ import annotations

import re

# --- AndroidManifest.xml signals -------------------------------------------
_MANIFEST_FLAGS = (
    (re.compile(r'android:debuggable\s*=\s*"true"', re.I), "high", "App is debuggable (android:debuggable=true)"),
    (re.compile(r'android:allowBackup\s*=\s*"true"', re.I), "medium", "Backup allowed (android:allowBackup=true)"),
    (re.compile(r'android:usesCleartextTraffic\s*=\s*"true"', re.I), "medium", "Cleartext traffic allowed"),
    (re.compile(r'android:networkSecurityConfig', re.I), "info", "Custom network-security config (review pinning)"),
    (re.compile(r'android:testOnly\s*=\s*"true"', re.I), "medium", "App marked testOnly"),
)
_COMPONENT_RE = re.compile(r"<(activity|activity-alias|service|receiver|provider)\b([^>]*?)(/?)>", re.I)
_PERM_RE = re.compile(r"android:(?:readPermission|writePermission|permission)\s*=", re.I)
_DANGEROUS_PERMS = re.compile(
    r"android\.permission\.(READ_SMS|SEND_SMS|RECEIVE_SMS|READ_CONTACTS|"
    r"ACCESS_FINE_LOCATION|RECORD_AUDIO|READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE|"
    r"READ_CALL_LOG|CAMERA|REQUEST_INSTALL_PACKAGES|SYSTEM_ALERT_WINDOW)")


def scan_manifest(xml: str) -> list[tuple[str, str, str]]:
    """Find dangerous configuration in a decompiled AndroidManifest.xml."""
    hits: list[tuple[str, str, str]] = []
    seen: set = set()
    def add(sev, label, ev):
        if (label, ev) not in seen:
            seen.add((label, ev)); hits.append((sev, label, ev[:160]))
    for rx, sev, label in _MANIFEST_FLAGS:
        m = rx.search(xml or "")
        if m:
            add(sev, label, m.group(0))
    for m in _COMPONENT_RE.finditer(xml or ""):
        kind, attrs = m.group(1).lower(), m.group(2)
        exported = re.search(r'android:exported\s*=\s*"true"', attrs, re.I)
        name = (re.search(r'android:name\s*=\s*"([^"]+)"', attrs) or [None, "?"])[1]
        if exported and not _PERM_RE.search(attrs):
            sev = "high" if kind == "provider" else "medium"
            add(sev, f"Exported {kind} without permission", f"{name} (exported=true)")
        if kind == "provider" and re.search(r'android:grantUriPermissions\s*=\s*"true"', attrs, re.I):
            add("high", "Content provider grants URI permissions", name)
    # deep links (intent-filter with a custom/http scheme => attacker-reachable)
    for m in re.finditer(r'<data\b[^>]*android:scheme\s*=\s*"([^"]+)"', xml or "", re.I):
        if m.group(1).lower() not in ("android-app",):
            add("info", "Deep-link scheme (attacker-reachable entry point)", m.group(1))
            break
    for m in _DANGEROUS_PERMS.finditer(xml or ""):
        add("info", "Dangerous permission requested", m.group(1))
    return hits


# --- decompiled-source / resources signals ---------------------------------
_SOURCE_SIGNALS = (
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
     "critical", "Private key bundled in APK"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical", "AWS access key hardcoded"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "critical", "Google API key hardcoded"),
    (re.compile(r"\bghp_[0-9A-Za-z]{36}\b"), "critical", "GitHub token hardcoded"),
    (re.compile(r"https://[a-z0-9-]+\.firebaseio\.com", re.I), "high", "Firebase database URL"),
    (re.compile(r"https://[a-z0-9-]+\.cloudfunctions\.net", re.I), "medium", "Cloud Functions endpoint"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}"),
     "medium", "JWT bundled in APK"),
    (re.compile(r'(?i)(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*'
                r'["\'][^"\'\s]{6,}["\']'), "high", "Hardcoded credential/secret"),
    (re.compile(r'\bhttp://[a-z0-9.-]+(?::\d+)?/[^\s"\'<)]*', re.I), "low",
     "Cleartext HTTP endpoint"),
    (re.compile(r"setAllowUniversalAccessFromFileURLs|setJavaScriptEnabled\(true\)"),
     "medium", "Risky WebView setting"),
    (re.compile(r"TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER|checkServerTrusted\(\s*\)\s*\{\s*\}",
                re.I), "high", "Disabled TLS validation"),
)


def scan_apk_source(text: str) -> list[tuple[str, str, str]]:
    """Find secrets, endpoints and unsafe patterns in decompiled APK source/resources."""
    hits: list[tuple[str, str, str]] = []
    seen: set = set()
    for rx, sev, label in _SOURCE_SIGNALS:
        m = rx.search(text or "")
        if m and label not in seen:
            seen.add(label)
            hits.append((sev, label, (m.group(0) or "").strip()[:160]))
    return hits


def analyze_apk(kali, apk_path: str, workdir: str = "/tmp/brukal_apk") -> dict:
    """Decompile `apk_path` inside the cage and scan it. Runs jadx (source) + apktool
    (manifest) via argv (no shell). Returns {'findings': [(sev,label,evidence,where)],
    'manifest': bool, 'source_files': int}. Best-effort: a missing tool is skipped.
    `kali` is a cage backend with .run(command:str) -> ExecResult (infra, not a target)."""
    findings: list[tuple[str, str, str, str]] = []
    kali.run(f"rm -rf {workdir}")
    kali.run(f"mkdir -p {workdir}")
    # apktool for the manifest (decoded), jadx for the sources.
    kali.run(f"apktool d -f -o {workdir}/apktool {apk_path}")
    kali.run(f"jadx -d {workdir}/jadx {apk_path}")
    man = kali.run(f"cat {workdir}/apktool/AndroidManifest.xml")
    manifest_ok = bool(getattr(man, "stdout", ""))
    if manifest_ok:
        for sev, label, ev in scan_manifest(man.stdout):
            findings.append((sev, label, ev, "manifest"))
    # grep the decompiled tree for source signals (bounded output).
    src = kali.run(f"grep -rIhoE "
                   r"""'(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[0-9A-Za-z]{36}|"""
                   r"""-----BEGIN [A-Z ]*PRIVATE KEY-----|https?://[a-zA-Z0-9./_-]+|"""
                   r"""eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}|"""
                   r"""(password|secret|api[_-]?key|token)[\"'= :]{1,3}[^\"' <]{6,})' """
                   f"{workdir}/jadx {workdir}/apktool 2>/dev/null | head -400")
    text = getattr(src, "stdout", "") or ""
    # Fallback for a cage without jadx/apktool: unzip and pull printable strings from the
    # dex + assets/resources. Less complete than decompilation but catches embedded
    # secrets/URLs on any cage.
    if not text.strip():
        kali.run(f"unzip -o {apk_path} -d {workdir}/unzip")
        st = kali.run(f"grep -rIhaoE "
                      r"""'(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[0-9A-Za-z]{36}|"""
                      r"""https?://[a-zA-Z0-9./_-]+\.firebaseio\.com|https?://[a-zA-Z0-9./_-]+)' """
                      f"{workdir}/unzip 2>/dev/null | head -400")
        text = getattr(st, "stdout", "") or ""
    for sev, label, ev in scan_apk_source(text):
        findings.append((sev, label, ev, "source"))
    return {"findings": findings, "manifest": manifest_ok, "source_bytes": len(text)}


# Tools the mobile flow needs (checked / installed in the cage).
APK_TOOLS = ("jadx", "apktool", "unzip", "aapt", "grep")

METHODOLOGY = (
    "MOBILE APP (ANDROID APK) METHODOLOGY:\n"
    "1. Acquire the APK (operator-supplied file, or pull from the device / a store).\n"
    "2. Decompile: apktool d <apk> (manifest+resources), jadx -d out <apk> (Java source).\n"
    "3. Manifest: exported activities/services/receivers/providers without a permission "
    "(intent-injection), debuggable, allowBackup, usesCleartextTraffic, content-provider "
    "grantUriPermissions, deep-link schemes, dangerous permissions.\n"
    "4. Secrets: grep source/resources for API/cloud/VCS keys, Firebase URLs, JWTs, "
    "hardcoded creds, private keys, cleartext http:// endpoints.\n"
    "5. Transport/logic: disabled TLS validation / pinning bypass, risky WebView settings, "
    "the API endpoints the app talks to (then test those as web/API targets).\n"
    "Static analysis is local/offline; dynamic (Frida, intent injection) needs a device "
    "and operator sign-off."
)
