import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
import time
import urllib.request
import urllib.error
import tempfile
import threading
import re
from werkzeug.serving import make_server
from web.server import create_app


def _req(method, url, data=None, headers=None):
    """Send an HTTP request using urllib. Returns (status_code, response_text)."""
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req_headers = headers or {}
    if body is not None:
        req_headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def _get(url, headers=None):
    return _req("GET", url, headers=headers)


def _post(url, data=None, headers=None):
    return _req("POST", url, data=data, headers=headers)


def _json(text):
    return json.loads(text)


def get_csrf(base_url):
    status, text = _get(base_url)
    if status != 200:
        raise RuntimeError(f"GET / returned {status}: {text[:200]}")
    match = re.search(r'<meta name="csrf-token" content="(.*?)">', text)
    if not match:
        raise ValueError("CSRF token not found in index page")
    return match.group(1)


def run_smoke_test():
    with tempfile.TemporaryDirectory() as tmpdir:
        storage_dir = Path(tmpdir) / "secure_storage"
        storage_dir.mkdir()

        # Start server on a dynamically assigned port (port=0 → OS picks one)
        app = create_app(str(storage_dir), testing=False)
        server = make_server('127.0.0.1', 0, app)
        port = server.server_address[1]           # actual bound port
        base_url = f"http://127.0.0.1:{port}"

        # Diagnostics: print port and base_url BEFORE first request
        print(f"[smoke_test] Server subprocess port  : {port}")
        print(f"[smoke_test] base_url for all calls  : {base_url}")

        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()

        try:
            # Give the server a moment to start accepting connections
            time.sleep(0.5)

            # 1. Fetch CSRF token
            csrf = get_csrf(base_url)
            headers = {
                "X-CSRF-Token": csrf,
                "Origin": base_url,
            }
            print("CSRF token obtained.")

            # 2. Initialize
            status, text = _post(f"{base_url}/api/init",
                                  data={"passphrase": "password123", "confirm": "password123"},
                                  headers=headers)
            if status != 200:
                raise RuntimeError(f"Init failed {status}: {text[:200]}")
            print("Init successful.")

            # 3. Unlock
            status, text = _post(f"{base_url}/api/unlock",
                                  data={"passphrase": "password123"},
                                  headers=headers)
            if status != 200:
                raise RuntimeError(f"Unlock failed {status}: {text[:200]}")
            print("Unlock successful.")

            # 4. Hash text
            status, text = _post(f"{base_url}/api/hash/text",
                                  data={"text": "hello"},
                                  headers=headers)
            if status != 200:
                raise RuntimeError(f"Hash text failed {status}: {text[:200]}")
            print("Hash text successful.")

            # 5. Encrypt with removal
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("my secret content", encoding="utf-8")

            status, text = _post(f"{base_url}/api/encrypt",
                                  data={"path": str(test_file), "delete_originals": True},
                                  headers=headers)
            if status != 200:
                raise RuntimeError(f"Encrypt failed {status}: {text[:200]}")
            job_id = _json(text)["job_id"]

            # Poll job
            for _ in range(50):
                st, txt = _get(f"{base_url}/api/jobs/{job_id}")
                if _json(txt)["state"] == "done":
                    break
                time.sleep(0.1)

            if test_file.exists():
                raise AssertionError("File was not removed after encryption")
            print("Encrypt with removal successful.")

            # 5b. Encrypt with lock_in_place
            test_file2 = Path(tmpdir) / "test2.txt"
            test_file2.write_text("lock me", encoding="utf-8")
            
            status, text = _post(f"{base_url}/api/encrypt",
                                  data={"path": str(test_file2), "delete_originals": False, "lock_in_place": True},
                                  headers=headers)
            if status != 200:
                raise RuntimeError(f"Encrypt lock_in_place failed {status}: {text[:200]}")
            job_id2 = _json(text)["job_id"]
            for _ in range(50):
                st, txt = _get(f"{base_url}/api/jobs/{job_id2}")
                if _json(txt)["state"] == "done":
                    break
                time.sleep(0.1)
                
            locked_file = Path(tmpdir) / "test2.txt.encrypt"
            if not locked_file.exists():
                raise AssertionError("Locked .encrypt file was not created")
            if test_file2.exists():
                raise AssertionError("Original file was not removed after lock_in_place")
            print("Encrypt lock_in_place successful.")

            # 6. List files
            st, txt = _get(f"{base_url}/api/files")
            file_ids = _json(txt)["files"]
            fid = file_ids[0]["file_id"]

            # 7. Proof verification
            status, text = _get(f"{base_url}/api/files/{fid}/proof")
            if status != 200:
                raise RuntimeError(f"Proof failed {status}: {text[:200]}")
            print("Proof verification successful.")

            # 8. Verify all
            status, text = _post(f"{base_url}/api/verify-all", headers=headers)
            if status != 200:
                raise RuntimeError(f"Verify-all failed {status}: {text[:200]}")
            print("Verify all successful.")

            # 9. Decrypt SAFE
            dest = Path(tmpdir) / "decrypted"
            status, text = _post(f"{base_url}/api/decrypt",
                                  data={"file_ids": [fid], "dest": str(dest)},
                                  headers=headers)
            if status != 200:
                raise RuntimeError(f"Decrypt POST failed {status}: {text[:200]}")
            dec_job_id = _json(text)["job_id"]
            for _ in range(50):
                st, txt = _get(f"{base_url}/api/jobs/{dec_job_id}")
                if _json(txt)["state"] == "done":
                    break
                time.sleep(0.1)
            print("Decrypt SAFE successful.")

            # 10. Corrupt data.enc and verify TAMPERED detection
            enc_file = storage_dir / "files" / fid / "data.enc"
            raw = bytearray(enc_file.read_bytes())
            raw[0] ^= 0xFF
            enc_file.write_bytes(bytes(raw))

            dest2 = Path(tmpdir) / "decrypted2"
            status, text = _post(f"{base_url}/api/decrypt",
                                  data={"file_ids": [fid], "dest": str(dest2)},
                                  headers=headers)
            if status != 200:
                raise RuntimeError(f"Corrupt decrypt POST failed {status}: {text[:200]}")
            dec2_job_id = _json(text)["job_id"]
            for _ in range(50):
                st, txt = _get(f"{base_url}/api/jobs/{dec2_job_id}")
                if _json(txt)["state"] == "done":
                    break
                time.sleep(0.1)

            result = _json(txt)["results"][0]["status"]
            if result != "TAMPERED":
                raise AssertionError(f"Tampered file was not detected, got: {result!r}")
            print("Corrupt data.enc TAMPERED detected successful.")

        finally:
            server.shutdown()
            thread.join()


if __name__ == "__main__":
    run_smoke_test()
    print("Smoke test passed.")
