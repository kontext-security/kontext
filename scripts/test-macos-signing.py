#!/usr/bin/env python3
"""Exercise the signing preflight with disposable certificates, never Apple keys."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

script = Path(__file__).with_name("check-macos-signing.sh")
results = []
with tempfile.TemporaryDirectory(prefix="kontext-signing-test-") as directory:
    root = Path(directory)
    password = "disposable-fixture-password"
    team = "ABCDE12345"
    env = {key: value for key, value in os.environ.items() if not key.startswith("MACOS_")}

    def certificate(name, ou=team):
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", f"/OU={ou}/CN={name}", "-keyout", str(root / "key.pem"),
            "-out", str(root / "cert.pem"),
        ], check=True, capture_output=True)
        subprocess.run([
            "openssl", "pkcs12", "-export", "-in", str(root / "cert.pem"),
            "-inkey", str(root / "key.pem"), "-out", str(root / "identity.p12"),
            "-passout", f"pass:{password}",
        ], check=True, capture_output=True)
        return base64.b64encode((root / "identity.p12").read_bytes()).decode()

    company = {
        "MACOS_SIGNING_PROFILE": "company", "MACOS_EXPECTED_TEAM_ID": team,
        "MACOS_SIGN_P12": certificate(f"Developer ID Application: CoBrowser Technology GmbH ({team})"),
        "MACOS_SIGN_PASSWORD": password, "MACOS_NOTARY_ISSUER_ID": "fixture-issuer",
        "MACOS_NOTARY_KEY_ID": "fixture-id", "MACOS_NOTARY_KEY": "fixture-notary-key",
    }

    def check(name, settings, expected):
        result = subprocess.run(["bash", str(script)], env={**env, **settings}, capture_output=True, text=True)
        output = result.stdout + result.stderr
        assert (result.returncode == 0) == expected, f"{name}: {output}"
        for secret in (password, company["MACOS_SIGN_P12"], "fixture-notary-key", "PRIVATE KEY"):
            assert secret not in output, f"{name}: credential in output"
        results.append({"case": name, "passed": True})

    check("legacy unsigned", {}, True)
    check("legacy signed configuration", {key: value for key, value in company.items() if key not in ("MACOS_SIGNING_PROFILE", "MACOS_EXPECTED_TEAM_ID")}, True)
    check("company identity", company, True)
    for key in company:
        if key != "MACOS_SIGNING_PROFILE":
            check(f"missing {key}", {**company, key: ""}, False)
    check("unknown selector", {**company, "MACOS_SIGNING_PROFILE": "typo"}, False)
    check("personal team", {**company, "MACOS_EXPECTED_TEAM_ID": "L2LV5YHMJ3"}, False)
    check("invalid team", {**company, "MACOS_EXPECTED_TEAM_ID": "../invalid"}, False)
    check("different team", {**company, "MACOS_EXPECTED_TEAM_ID": "ZZZZZ12345"}, False)
    check("wrong password", {**company, "MACOS_SIGN_PASSWORD": "wrong"}, False)
    check("corrupt certificate", {**company, "MACOS_SIGN_P12": "not-base64"}, False)
    for name in (f"Developer ID Application: Other Company ({team})", f"Developer ID Installer: CoBrowser Technology GmbH ({team})"):
        check(name, {**company, "MACOS_SIGN_P12": certificate(name)}, False)
    check("certificate OU differs", {**company, "MACOS_SIGN_P12": certificate(f"Developer ID Application: CoBrowser Technology GmbH ({team})", "ZZZZZ12345")}, False)

artifact = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/kontext-signing-checks.json")
artifact.write_text(json.dumps({"fixture_only": True, "checks": results}, indent=2) + "\n")
print(f"{len(results)} signing preflight checks passed; artifact: {artifact}")
