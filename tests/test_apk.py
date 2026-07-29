"""
test_apk.py — the Android APK static-analysis detector (mobile end).

Pins that scan_manifest flags dangerous app configuration (debuggable, backup,
cleartext, exported components without a permission, provider URI grants, deep links,
dangerous permissions) while leaving a permission-guarded component alone; that
scan_apk_source flags hardcoded secrets / endpoints / disabled TLS; and that
analyze_apk drives decompile-then-scan through a cage backend (argv, no shell). Real
manifest/source formats — no live APK needed.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from brukal import apkscan

MANIFEST = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.corp.app">
  <uses-permission android:name="android.permission.READ_SMS"/>
  <application android:debuggable="true" android:allowBackup="true"
               android:usesCleartextTraffic="true">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter><data android:scheme="corpapp" android:host="pay"/></intent-filter>
    </activity>
    <service android:name=".SyncService" android:exported="true"/>
    <receiver android:name=".BootRcv" android:exported="true"
              android:permission="com.corp.PRIVATE"/>
    <provider android:name=".FileProvider" android:exported="true"
              android:grantUriPermissions="true"/>
  </application>
</manifest>"""


def _labels(hits):
    return [l for _s, l, _e in hits]


def test_manifest_flags_dangerous_config():
    L = _labels(apkscan.scan_manifest(MANIFEST))
    assert "App is debuggable (android:debuggable=true)" in L
    assert "Backup allowed (android:allowBackup=true)" in L
    assert "Cleartext traffic allowed" in L
    assert "Exported activity without permission" in L
    assert "Exported service without permission" in L
    assert "Exported provider without permission" in L
    assert "Content provider grants URI permissions" in L
    assert "Deep-link scheme (attacker-reachable entry point)" in L
    assert "Dangerous permission requested" in L


def test_manifest_leaves_permission_guarded_component_alone():
    # the receiver is guarded by android:permission -> not an unprotected export
    evs = [e for _s, l, e in apkscan.scan_manifest(MANIFEST) if "receiver" in l.lower()]
    assert evs == []


def test_hardened_manifest_is_quieter():
    hard = ('<manifest><application android:debuggable="false" android:allowBackup="false">'
            '<activity android:name=".A"/></application></manifest>')
    assert _labels(apkscan.scan_manifest(hard)) == []


def test_source_flags_secrets_and_endpoints():
    blob = (
        'String key = "AKIAIOSFODNN7EXAMPLE";\n'
        'String g = "AIzaSy' + "b" * 33 + '";\n'
        'url = "https://corp-app-12.firebaseio.com/users.json";\n'
        'String password = "S3cr3tP@ss";\n'
        'auth = "eyJhbGciOiJIUzI1NiJ9.eyJ1IjoxfQ.abcdef123456";\n'
        'api = "http://api.internal.corp/v1/login";\n'
        'public void checkServerTrusted() {}\n'
    )
    L = _labels(apkscan.scan_apk_source(blob))
    assert "AWS access key hardcoded" in L
    assert "Google API key hardcoded" in L
    assert "Firebase database URL" in L
    assert "Hardcoded credential/secret" in L
    assert "JWT bundled in APK" in L
    assert "Cleartext HTTP endpoint" in L


def test_analyze_apk_drives_decompile_and_scan():
    class _FakeCage:
        """Returns the manifest for the cat, the source blob for the grep, '' otherwise."""
        def run(self, command):
            class R: pass
            r = R()
            if command.startswith("cat ") and "AndroidManifest" in command:
                r.stdout = MANIFEST
            elif command.startswith("grep "):
                r.stdout = 'k="AKIAIOSFODNN7EXAMPLE" url="http://api.corp/login"'
            else:
                r.stdout = ""
            return r
    out = apkscan.analyze_apk(_FakeCage(), "/tmp/app.apk")
    assert out["manifest"] is True
    labels = [l for _s, l, _e, _w in out["findings"]]
    assert "App is debuggable (android:debuggable=true)" in labels   # from manifest
    assert "AWS access key hardcoded" in labels                      # from source grep
    wheres = {w for _s, _l, _e, w in out["findings"]}
    assert wheres == {"manifest", "source"}
