"""Run the public CLI and an independent stdlib HTTP oracle against two servers.

Usage: python validate.py /absolute/path/to/rangeprobe OUTPUT_DIRECTORY
Servers: parent on 18761, merged revision on 18762. See README.md for setup.
"""

import base64
import hashlib
import http.client
import json
import subprocess
import sys
from pathlib import Path

binary, output = sys.argv[1:]
output = Path(output)
output.mkdir(parents=True, exist_ok=True)
fixture = Path(__file__).with_name("fixture.bin").read_bytes()
rows = []
for revision, port in [("parent", 18761), ("fixed", 18762)]:
    for route in ["strong", "weak"]:
        stem = f"{revision}-{route}"
        cmd = [
            binary,
            "if-range",
            f"http://127.0.0.1:{port}/{route}",
            "--probe-size",
            "5",
            "--json",
            str(output / f"{stem}.json"),
            "--html",
            str(output / f"{stem}.html"),
        ]
        if route == "weak":
            cmd.append("--weak-if-range")
        run = subprocess.run(cmd, capture_output=True, text=True, check=False)
        (output / f"{stem}.txt").write_text(run.stdout + run.stderr)
        expected_exit = 0 if route == "strong" else (1 if revision == "parent" else 3)
        assert run.returncode == expected_exit, (cmd, run.returncode, run.stderr)
        report = json.loads((output / f"{stem}.json").read_text())
        for check in report["checks"]:
            if "skip" in check:
                continue
            e = check["if_range"]
            headers = {
                "Range": check["request"]["range"],
                "Accept-Encoding": "identity",
            }
            if e.get("validator_base64"):
                headers["If-Range"] = base64.b64decode(e["validator_base64"]).decode(
                    "latin-1"
                )
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", f"/{route}", headers=headers)
            response = conn.getresponse()
            body = response.read(1024)  # fixture is 12 bytes; oracle is bounded too
            status = response.status
            rh = dict(response.getheaders())
            conn.close()
            expected = (
                206
                if "If-Range" not in headers
                else (
                    206
                    if route == "strong" and e["role"] == "matching"
                    else (206 if route == "weak" and revision == "parent" else 200)
                )
            )
            assert status == expected == check["response"]["status"], (
                stem,
                check["id"],
                status,
            )
            assert body == (fixture[:5] if status == 206 else fixture)
            assert rh.get("content-range") == (
                "bytes 0-4/12" if status == 206 else None
            )
            assert int(rh["content-length"]) == len(body)
            assert rh["etag"] == (
                '"strong-control"' if route == "strong" else 'W/"a_weak_etag"'
            )
            assert "last-modified" in rh
            assert check["body"]["complete"] and check["body"]["bytes_read"] == len(
                body
            )
            rows.append(
                {
                    "revision": revision,
                    "route": route,
                    "probe": e["role"],
                    "range": headers["Range"],
                    "if_range": headers.get("If-Range"),
                    "status": status,
                    "headers": rh,
                    "bytes": len(body),
                    "body_hex": body.hex(),
                    "sha256": hashlib.sha256(body).hexdigest(),
                    "outcome": e["outcome"],
                    "exit": run.returncode,
                }
            )
            print(
                f"{stem:14} {e['role']:12} {status} {len(body):2}B {e['outcome']} exit={run.returncode}"
            )
(output / "oracle.json").write_text(json.dumps(rows, indent=2) + "\n")
