"""Compare the CLI with a raw HTTP/1.1 oracle on three Starlette revisions."""

import hashlib
import io
import json
import os
import re
import socket
import subprocess
import sys
import tarfile
import time
import urllib.request
from contextlib import contextmanager
from pathlib import Path

LAB = Path(__file__).resolve().parent
FIXTURE = LAB / "fixture.bin"
RANGES = [(0, 2), (8, 10)]
RANGE = "bytes=" + ",".join(f"{start}-{end}" for start, end in RANGES)
CASES = [
    ("before", "c011d1fcb27ab8b4759288479208315695ef3ca3", "content-range", "lf"),
    ("header-fixed", "90b805fda70db2316d79aa577f4c3eb670f9a8a1", "content-type", "lf"),
    ("crlf-fixed", "9c74ef4c7cb1b79909aebf38be0e155064c27601", "content-type", "crlf"),
]


def download(work, sha):
    url = f"https://codeload.github.com/Kludex/starlette/tar.gz/{sha}"
    with urllib.request.urlopen(url, timeout=30) as response:
        archive = response.read()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as source:
        source.extractall(work, filter="data")
    return work / f"starlette-{sha}", hashlib.sha256(archive).hexdigest()


@contextmanager
def serve(source, log):
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(source), str(LAB)]))
    cmd = [
        sys.executable, "-m", "uvicorn", "app:app", "--host", "127.0.0.1",
        "--port", "0", "--lifespan", "off", "--http", "h11", "--loop", "asyncio",
        "--no-access-log",
    ]
    with log.open("w") as output, subprocess.Popen(
        cmd, env=env, stdout=output, stderr=subprocess.STDOUT
    ) as server:
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and server.poll() is None:
                match = re.search(r"Uvicorn running on http://127\.0\.0\.1:(\d+)", log.read_text())
                if match:
                    yield int(match[1])
                    return
                time.sleep(0.05)
            raise RuntimeError(f"Uvicorn did not start. See {log}")
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()


def raw_http(port):
    request = (
        f"GET /strong HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
        f"Range: {RANGE}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    )
    with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
        conn.sendall(request.encode("ascii"))
        with conn.makefile("rb") as raw:
            wire = raw.read(8192)
    assert len(wire) < 8192, "Unexpected lab response size"
    head, body = wire.split(b"\r\n\r\n", 1)
    status_line, *fields = head.decode("latin-1").split("\r\n")
    headers = {}
    for field in fields:
        name, value = field.split(":", 1)
        headers.setdefault(name.lower(), []).append(value.strip())
    return int(status_line.split()[1]), headers, body


def oracle(port):
    status, headers, body = raw_http(port)
    assert status == 206 and "transfer-encoding" not in headers, (status, headers)
    declared, = headers["content-length"]
    declared = int(declared)
    fixture = FIXTURE.read_bytes()
    hits = [
        (name, match[1])
        for name in ["content-type", "content-range"]
        for value in headers.get(name, [])
        if (match := re.fullmatch(r"multipart/byteranges; boundary=(\w+)", value))
    ]
    assert len(hits) == 1, headers
    field, boundary = hits[0]
    if field == "content-type":
        assert "content-range" not in headers, headers
    else:
        assert headers["content-type"] == ["application/octet-stream"], headers

    marker = f"--{boundary}".encode("ascii")
    part_ranges = [f"bytes {start}-{end}/{len(fixture)}" for start, end in RANGES]
    bodies = [fixture[start : end + 1] for start, end in RANGES]

    def frame(nl):
        return b"".join(
            nl.join([
                marker, b"Content-Type: application/octet-stream",
                f"Content-Range: {content_range}".encode("ascii"), b"", data, b"",
            ])
            for content_range, data in zip(part_ranges, bodies)
        )

    if body == frame(b"\r\n") + marker + b"--":
        framing, closed = "crlf", True
        assert declared == len(body), headers
    elif body == frame(b"\n"):
        framing, closed = "lf", False
        # The historical ASGI final write had one byte more than h11's
        # remaining Content-Length budget. h11 withheld the whole write.
        final_write = b"\n" + marker + b"--\n"
        assert declared == len(body) + len(final_write) - 1, headers
    else:
        raise AssertionError(f"Unexpected multipart framing or part bytes ({len(body)} bytes)")
    return {
        "status": status,
        "content_type": headers["content-type"][0],
        "content_range": headers.get("content-range", [None])[0],
        "content_length": declared,
        "body_bytes": len(body),
        "boundary_field": field,
        "framing": framing,
        "closing_boundary": closed,
        "parts": [
            {"content_range": content_range, "bytes": len(data), "matches_reference": True}
            for content_range, data in zip(part_ranges, bodies)
        ],
    }


def run_cli(work, name, port):
    path = work / f"{name}.json"
    cmd = [
        str(work / "rangeprobe"), "multipart", f"http://127.0.0.1:{port}/strong",
        "--range", "0-2", "--range", "8-10", "--reference", str(FIXTURE),
        "--json", str(path),
    ]
    run = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    (work / f"{name}.txt").write_text(run.stdout + run.stderr)
    assert path.exists(), (cmd, run.returncode, run.stderr)
    return run.returncode, json.loads(path.read_text())


def compare(report, code, evidence):
    assert report["status"] == evidence["status"], report
    assert report["range"] == RANGE and report["exit_code"] == code, report
    assert report["content_length"] == evidence["content_length"], report
    assert report["bytes_read"] == evidence["body_bytes"], report
    assert report["body_complete"] == evidence["closing_boundary"], report
    finding_ids = {finding["id"] for finding in (report["findings"] or [])}
    if not evidence["closing_boundary"]:
        assert report["observation_issue"] == "truncated", report
        assert "BODY_TRUNCATED" in finding_ids, report
    if evidence["boundary_field"] == "content-range":
        assert report["response_form"] == "single_206", report
        assert code == 1 and report["result"] == "problem", report
        assert report["content_type"] == evidence["content_type"], report
        assert report["content_range"].startswith("multipart/byteranges; boundary="), report
        assert "CONTENT_RANGE_INVALID" in finding_ids, report
        return

    assert report["response_form"] == "multipart_206", report
    assert report["content_type"].startswith("multipart/byteranges; boundary="), report
    assert "content_range" not in report, report
    assert report["closing_boundary"] == evidence["closing_boundary"], report
    if evidence["framing"] == "lf":
        assert code == 1 and report["result"] == "problem", report
        assert report["multipart_framing"] == "invalid", report
        assert "MULTIPART_FRAMING" in finding_ids, report
        verified_parts = 1  # The second part has no terminating delimiter.
    else:
        assert code == 0 and report["result"] == "pass", report
        assert report["multipart_framing"] == "valid", report
        assert report["coverage"] == "complete", report
        verified_parts = len(RANGES)
    assert len(report["parts"]) >= verified_parts, report
    for part, (start, end), observed in zip(
        report["parts"][:verified_parts], RANGES, evidence["parts"]
    ):
        assert (part["first"], part["last"]) == (start, end), part
        assert part["content_range"] == observed["content_range"], part
        assert part["bytes_read"] == part["bytes_compared"] == observed["bytes"], part
        assert part["comparison"] == "match", part


def main(work):
    observations = []
    for name, sha, field, framing in CASES:
        source, digest = download(work, sha)
        with serve(source, work / f"{name}.log") as port:
            evidence = oracle(port)
            assert (evidence["boundary_field"], evidence["framing"]) == (field, framing), evidence
            code, report = run_cli(work, name, port)
            compare(report, code, evidence)
            observations.append({
                "revision": name, "commit": sha, "archive_sha256": digest,
                "cli_exit": code, "cli_result": report["result"], **evidence,
            })
            print(
                f"{name:12} {evidence['status']} "
                f"{evidence['body_bytes']}/{evidence['content_length']} B  "
                f"boundary in {field:13}  {framing.upper():4}  CLI exit={code}"
            )
    (work / "multipart-oracle.json").write_text(json.dumps(observations, indent=2) + "\n")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
