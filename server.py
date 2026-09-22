import os
import sys
import secrets
import hmac
import subprocess
import traceback
import logging
from pathlib import Path
import hashlib
from datetime import datetime, timezone
import shutil
from flask import Flask, request, jsonify, render_template, abort, make_response
from werkzeug.exceptions import HTTPException

from core.keys import Session, init_user, _attempts_path, change_passphrase
from core.errors import (
    SecureFolderError, AuthError, WrongPassphraseError, LockedOutError,
    TamperedError, PathSafetyError, StorageError
)
from core.pipeline import (
    list_entries, export_public_key, verify_vault_integrity
)
from core.storage import (
    read_meta, key_enc_path, data_enc_path
)
from core.crypto_rsa import unwrap_key
from core.crypto_aes import decrypt_bytes
from web.jobs import JobManager
from web.fsbrowse import (
    list_directory, preview_directory, is_same_or_inside, is_parent_of, is_protected
)

def create_app(storage_dir_str: str, testing: bool = False):
    app = Flask(__name__, template_folder='templates', static_folder='static')
    app.config['TESTING'] = testing
    
    storage_dir = Path(storage_dir_str).resolve()
    storage_dir.mkdir(parents=True, exist_ok=True)
    
    session = Session()
    job_manager = JobManager(storage_dir)

    app.session = session
    app.job_manager = job_manager

    # CSRF generation per launch
    app.config['CSRF_TOKEN'] = secrets.token_urlsafe(32)

    @app.before_request
    def security_checks():
        # Reject non-localhost Host header.
        # Accept 127.0.0.1 and localhost with any valid TCP port (1-65535),
        # or no port at all (browser default).
        host = request.headers.get('Host', '')
        if not host:
            logging.warning("[Host-check] REJECTED: empty Host header")
            abort(403)

        parts = host.split(':')
        host_name = parts[0]
        if host_name not in ('127.0.0.1', 'localhost'):
            logging.warning("[Host-check] REJECTED: host_name=%r not in allowed set", host_name)
            abort(403)

        if len(parts) > 1:
            try:
                port_num = int(parts[1])
                if not (1 <= port_num <= 65535):
                    logging.warning("[Host-check] REJECTED: port %d out of valid range", port_num)
                    abort(403)
            except ValueError:
                logging.warning("[Host-check] REJECTED: non-integer port in Host=%r", host)
                abort(403)

        # POST requests: check CSRF and Origin
        if request.method == 'POST':
            csrf_token = request.headers.get('X-CSRF-Token', '')
            if not hmac.compare_digest(csrf_token, app.config['CSRF_TOKEN']):
                abort(403)
                
            origin = request.headers.get('Origin')
            if origin:
                # We don't have request.host_url reliably without scheme in origin,
                # just check if origin contains localhost or 127.0.0.1
                if '127.0.0.1' not in origin and 'localhost' not in origin:
                    abort(403)

        # Auto-lock check for API requests
        if request.path.startswith('/api/') and request.path not in ('/api/status', '/api/init', '/api/unlock', '/api/reset-vault'):
            if session.is_expired():
                session.lock()
                return jsonify({"error": "AuthError", "message": "Session expired."}), 401
            if session.is_unlocked:
                session.touch()
            elif request.path not in ('/api/status', '/api/init', '/api/unlock', '/api/reset-vault'):
                # Not unlocked and requires auth
                return jsonify({"error": "AuthError", "message": "Locked."}), 401

    @app.after_request
    def add_security_headers(response):
        response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self'"
        response.headers['X-Content-Type-Options'] = "nosniff"
        response.headers['X-Frame-Options'] = "DENY"
        response.headers['Referrer-Policy'] = "no-referrer"
        response.headers['Cache-Control'] = "no-store"
        return response

    @app.errorhandler(SecureFolderError)
    def handle_secure_folder_error(error):
        # Map specific errors to status codes
        code = 500
        if isinstance(error, AuthError) or isinstance(error, WrongPassphraseError):
            code = 401
        elif isinstance(error, LockedOutError):
            code = 429
        elif isinstance(error, TamperedError):
            return jsonify({
                "error": "TamperedError",
                "message": str(error),
                "status": "TAMPERED"
            }), 200
        elif isinstance(error, PathSafetyError):
            return jsonify({"error": "protected_path", "message": str(error)}), 400
        elif isinstance(error, StorageError):
            code = 500
            
        return jsonify({"error": error.__class__.__name__, "message": str(error)}), code

    @app.errorhandler(Exception)
    def handle_generic_error(error):
        if isinstance(error, HTTPException):
            return error
        logging.exception("Internal Server Error [%s]: %s", type(error).__name__, error)
        return jsonify({"error": "ServerError", "message": "An internal error occurred."}), 500

    @app.route('/')
    def index():
        return render_template('index.html', csrf_token=app.config['CSRF_TOKEN'])

    @app.route('/preview')
    def preview():
        return render_template('preview.html', csrf_token=app.config['CSRF_TOKEN'])


    @app.route('/api/status', methods=['GET'])
    def status():
        pub_path = storage_dir / "keys" / "public.pem"
        priv_path = storage_dir / "keys" / "private.pem"
        initialized = pub_path.exists()
        passphrase_set = priv_path.exists()
        
        keys_created_at = None
        if initialized:
            try:
                st = pub_path.stat()
                # Windows uses st_ctime for creation time, Unix uses it for metadata change.
                # Use min(st_ctime, st_mtime) to be safe across platforms.
                created_ts = min(st.st_ctime, st.st_mtime)
                keys_created_at = datetime.fromtimestamp(created_ts, timezone.utc).isoformat()
            except OSError:
                pass
        
        seconds_left = 0
        if session.is_unlocked:
            # max 300
            elapsed = session._clock() - session._last_activity
            seconds_left = max(0, 300 - int(elapsed))
            
        return jsonify({
            "initialized": initialized,
            "passphrase_set": passphrase_set,
            "keys_created_at": keys_created_at,
            "unlocked": session.is_unlocked,
            "seconds_left": seconds_left,
            "storage_dir": str(storage_dir),
            "next_delay": Session.next_delay_seconds(storage_dir)
        })

    @app.route('/api/init', methods=['POST'])
    def init():
        data = request.get_json() or {}
        passphrase = data.get('passphrase', '')
        confirm = data.get('confirm', '')
        if passphrase != confirm:
            raise AuthError("Passphrases do not match.")
        
        init_user(storage_dir, passphrase)
        return jsonify({"success": True})

    @app.route('/api/unlock', methods=['POST'])
    def unlock():
        data = request.get_json() or {}
        passphrase = data.get('passphrase', '')
        try:
            session.unlock(storage_dir, passphrase)
            return jsonify({"success": True})
        except WrongPassphraseError as e:
            delay = Session.next_delay_seconds(storage_dir)
            return jsonify({
                "error": "WrongPassphraseError",
                "message": str(e),
                "next_delay": delay
            }), 401

    @app.route('/api/logout', methods=['POST'])
    def logout():
        session.lock()
        return jsonify({"success": True})
        
    @app.route('/api/change-passphrase', methods=['POST'])
    def change_passphrase_api():
        data = request.get_json() or {}
        old_pass = data.get('old', '')
        new_pass = data.get('new', '')
        confirm = data.get('confirm', '')
        
        if new_pass != confirm:
            raise AuthError("New passphrases do not match.")
            
        change_passphrase(storage_dir, old_pass, new_pass)
        return jsonify({"success": True})

    @app.route('/api/reset-vault', methods=['POST'])
    def reset_vault():
        data = request.get_json() or {}
        if data.get('confirm') != "RESET":
            raise AuthError("Reset confirmation must be exactly 'RESET'.")
            
        session.lock()
        
        if storage_dir.exists():
            ts = int(datetime.now(timezone.utc).timestamp())
            old_dir = storage_dir.parent / f"{storage_dir.name}_old_{ts}"
            try:
                shutil.move(str(storage_dir), str(old_dir))
            except Exception as e:
                raise StorageError(f"Failed to move vault directory: {e}")
                
        # Re-create the empty directory structure
        storage_dir.mkdir(parents=True, exist_ok=True)
        return status().get_data(as_text=False)

    @app.route('/api/fs/list', methods=['GET'])
    def fs_list():
        path = request.args.get('path', '')
        return jsonify(list_directory(path, storage_dir))

    @app.route('/api/fs/preview', methods=['GET', 'POST'])
    def fs_preview():
        if request.method == 'POST':
            data = request.get_json() or {}
            path = data.get('path', '')
        else:
            path = request.args.get('path', '')
        return jsonify(preview_directory(path, storage_dir))

    @app.route('/api/files', methods=['GET'])
    def files():
        """List all encrypted files. Returns {"files": [...]} with HTTP 200.
        An empty vault (no files/ folder yet) is not an error."""
        try:
            entries = list_entries(session, storage_dir)
            return jsonify({"files": [e.__dict__ for e in entries]})
        except (StorageError, FileNotFoundError, OSError):
            # Missing files/ folder or storage not yet initialised — return empty
            return jsonify({"files": []})

    @app.route('/api/encrypt', methods=['POST'])
    def encrypt_api():
        data = request.get_json() or {}
        path = data.get('path')
        delete_originals = data.get('delete_originals', True)
        lock_in_place = data.get('lock_in_place', False)
        if not path or '..' in Path(path).parts:
            raise PathSafetyError("Invalid path or path traversal is not allowed.")
        if is_same_or_inside(path, storage_dir):
            raise PathSafetyError("Cannot encrypt the secure storage directory itself or its contents.")
        if is_parent_of(path, storage_dir):
            raise PathSafetyError("This folder contains your secure vault. Choose a different folder.")
        job_id = job_manager.submit_encrypt(session, path, delete_originals, lock_in_place)
        return jsonify({"job_id": job_id})

    @app.route('/api/decrypt', methods=['POST'])
    def decrypt_api():
        data = request.get_json() or {}
        file_ids = data.get('file_ids')
        dest = data.get('dest')
        if not file_ids or not dest:
            abort(400)
        if '..' in Path(dest).parts:
            raise PathSafetyError("Invalid destination path.")
        if is_same_or_inside(dest, storage_dir):
            raise PathSafetyError("Cannot decrypt files into the secure storage directory.")
        dest_path = Path(dest).resolve()
        dest_path.mkdir(parents=True, exist_ok=True)
        job_id = job_manager.submit_decrypt(session, file_ids, str(dest_path))
        return jsonify({"job_id": job_id})

    @app.route('/api/jobs/<job_id>', methods=['GET'])
    def get_job(job_id):
        job = job_manager.get_job(job_id)
        if not job:
            return jsonify({"error": "NotFound", "message": "Job not found"}), 404
        try:
            return jsonify(job)
        except Exception as e:
            logging.exception("Failed to jsonify job %s: %s", job_id, e)
            safe_job = {
                "id": job.get("id", job_id),
                "type": job.get("type", "unknown"),
                "state": "failed",
                "progress": job.get("progress", 0.0),
                "events": job.get("events", []),
                "results": None,
                "error": "Failed to serialize job result"
            }
            return jsonify(safe_job), 200

    @app.route('/api/jobs/<job_id>/cancel', methods=['POST'])
    def cancel_job(job_id):
        success = job_manager.cancel_job(job_id)
        return jsonify({"success": success})

    @app.route('/api/share', methods=['POST'])
    def share():
        from core.pipeline import share_file
        data = request.get_json() or {}
        file_id = data.get('file_id')
        pubkey_path = data.get('recipient_public_key_path')
        out_dir = data.get('out_dir')
        if not all([file_id, pubkey_path, out_dir]):
            abort(400)
        pubkey_pem = Path(pubkey_path).read_bytes()
        share_file(session, file_id, storage_dir, pubkey_pem, out_dir)
        return jsonify({"success": True})

    @app.route('/api/export-pubkey', methods=['GET'])
    def export_pubkey():
        # Instead of saving to a path, we can just send the file
        pub_path = storage_dir / "keys" / "public.pem"
        if not pub_path.exists():
            abort(404)
        from flask import send_file
        return send_file(str(pub_path), as_attachment=True, download_name="public.pem")

    @app.route('/api/open-folder', methods=['POST'])
    def open_folder():
        data = request.get_json() or {}
        path_str = data.get('path')
        if not path_str:
            abort(400)
        p = Path(path_str).resolve()
        if not p.exists():
            abort(404)
        if sys.platform == 'win32':
            os.startfile(str(p))
        elif sys.platform == 'darwin':
            subprocess.Popen(['open', str(p)])
        else:
            subprocess.Popen(['xdg-open', str(p)])
        return jsonify({"success": True})

    # -------------------------------------------------------------------------
    # Native OS picker endpoints
    # -------------------------------------------------------------------------

    def _run_picker(mode: str) -> dict:
        """Run a tkinter file/folder picker in a subprocess.

        mode: 'folder' | 'file'
        Returns {"path": str} | {"path": None} | {"fallback": True}
        """
        script = (
            "import sys, tkinter as tk\n"
            "from tkinter import filedialog\n"
            "root = tk.Tk()\n"
            "root.withdraw()\n"
            "root.attributes('-topmost', True)\n"
        )
        if mode == 'folder':
            script += (
                "result = filedialog.askdirectory(title='Choose Folder')\n"
            )
        else:
            script += (
                "result = filedialog.askopenfilename(title='Choose File')\n"
            )
        script += (
            "print(result if result else '', end='')\n"
            "sys.exit(0)\n"
        )

        try:
            proc = subprocess.run(
                [sys.executable, '-c', script],
                capture_output=True,
                text=True,
                timeout=120,
            )
            chosen = proc.stdout.strip()
            if chosen:
                if is_protected(chosen, storage_dir):
                    return {"path": None, "error": "protected_path", "message": "Cannot select protected vault directory or its contents."}
                return {"path": chosen}
            return {"path": None}
        except FileNotFoundError:
            # tkinter not installed
            return {"fallback": True}
        except subprocess.TimeoutExpired:
            return {"path": None}
        except Exception:
            return {"fallback": True}

    @app.route('/api/pick-folder', methods=['POST'])
    def pick_folder():
        """Open native OS folder picker dialog.
        Requires unlocked session (handled by before_request) and CSRF.
        Returns {"path": "C:\\..."}  or  {"path": null}  or  {"fallback": true}.
        """
        result = _run_picker('folder')
        return jsonify(result)

    @app.route('/api/pick-file', methods=['POST'])
    def pick_file():
        """Open native OS file picker dialog.
        Requires unlocked session (handled by before_request) and CSRF.
        Returns {"path": "C:\\..."}  or  {"path": null}  or  {"fallback": true}.
        """
        result = _run_picker('file')
        return jsonify(result)

    @app.route('/api/hash/text', methods=['POST'])
    def hash_text_api():
        data = request.get_json() or {}
        text = data.get('text')
        if text is None or not isinstance(text, str):
            return jsonify({"error": "InvalidInput", "message": "Text parameter is required."}), 400
        raw_bytes = text.encode("utf-8")
        if len(raw_bytes) > 1_000_000:
            return jsonify({"error": "PayloadTooLarge", "message": "Text exceeds 1 MB limit."}), 400
        h = hashlib.sha256(raw_bytes).hexdigest()
        return jsonify({
            "hash": h,           # primary field app.js reads
            "sha256": h,         # also keep for test_api_contract.py
            "length_chars": len(text),
            "length_bytes": len(raw_bytes),
            "encoding": "utf-8"
        })

    @app.route('/api/hash/compare', methods=['POST'])
    def hash_compare_api():
        data = request.get_json() or {}
        text_a = data.get('text_a')
        text_b = data.get('text_b')
        if text_a is None or text_b is None or not isinstance(text_a, str) or not isinstance(text_b, str):
            return jsonify({"error": "InvalidInput", "message": "Both text_a and text_b are required."}), 400
        bytes_a = text_a.encode("utf-8")
        bytes_b = text_b.encode("utf-8")
        if len(bytes_a) > 1_000_000 or len(bytes_b) > 1_000_000:
            return jsonify({"error": "PayloadTooLarge", "message": "Text exceeds 1 MB limit."}), 400

        h_a = hashlib.sha256(bytes_a).hexdigest()
        h_b = hashlib.sha256(bytes_b).hexdigest()
        raw_a = bytes.fromhex(h_a)
        raw_b = bytes.fromhex(h_b)

        differing_bits = sum(bin(b1 ^ b2).count("1") for b1, b2 in zip(raw_a, raw_b))
        differing_bits_percent = round((differing_bits / 256.0) * 100, 2)
        differing_hex_positions = [i for i, (c1, c2) in enumerate(zip(h_a, h_b)) if c1 != c2]
        match = (differing_bits == 0)

        return jsonify({
            "hash_a": h_a,         # alias app.js reads
            "hash_b": h_b,         # alias app.js reads
            "sha256_a": h_a,       # keep for test contract
            "sha256_b": h_b,       # keep for test contract
            "match": match,
            "bits_changed": differing_bits,          # alias app.js reads
            "differing_bits": differing_bits,
            "differing_bits_percent": differing_bits_percent,
            "differing_hex_positions": differing_hex_positions
        })

    @app.route('/api/hash/file', methods=['POST'])
    def hash_file_api():
        data = request.get_json() or {}
        path_str = data.get('path')
        if not path_str or '..' in Path(path_str).parts:
            raise PathSafetyError("Invalid path or traversal sequence.")
        if is_same_or_inside(path_str, storage_dir) or is_parent_of(path_str, storage_dir):
            raise PathSafetyError("Cannot access secure storage or its parent.")
        p = Path(path_str).resolve()
        if not p.is_file():
            return jsonify({"error": "NotFound", "message": "File not found."}), 404

        hasher = hashlib.sha256()
        size = 0
        with open(p, "rb") as fh:
            while chunk := fh.read(1024 * 1024):
                hasher.update(chunk)
                size += len(chunk)

        return jsonify({
            "hash": hasher.hexdigest(),    # alias app.js reads
            "sha256": hasher.hexdigest(),  # keep for test contract
            "size": size,
            "name": p.name
        })

    @app.route('/api/files/<file_id>/proof', methods=['GET'])
    def file_proof_api(file_id):
        try:
            meta = read_meta(storage_dir, file_id)
            wrapped = key_enc_path(storage_dir, file_id).read_bytes()
            aes_key = unwrap_key(wrapped, session.private_key)
            name = decrypt_bytes(meta["name_enc"], aes_key).decode("utf-8")
            aes_key = None

            data_path = data_enc_path(storage_dir, file_id)
            enc_size = data_path.stat().st_size
            with open(data_path, "rb") as fh:
                c_preview = fh.read(48)

            # Read the nonce/IV from meta
            nonce_prefix = meta.get("nonce_prefix", b"")
            if isinstance(nonce_prefix, str):
                import base64
                nonce_prefix = base64.b64decode(nonce_prefix)

            return jsonify({
                "file_id": file_id,
                "original_name": name,
                "original_size": meta["size"],
                # SHA-256 fields
                "sha256": meta["sha256"],
                "original_sha256": meta["sha256"],   # alias app.js reads
                # AES envelope
                "aes_iv": nonce_prefix.hex() if nonce_prefix else "",
                "aes_tag": c_preview.hex(),           # first 48 bytes as "auth tag preview"
                "ciphertext_preview_hex": c_preview.hex(),
                # RSA key fields
                "encrypted_key_length": len(wrapped),
                "rsa_key_length_bytes": len(wrapped),  # keep for tests
                "rsa_padding": "OAEP-SHA256",
                "rsa_key_preview_hex": wrapped[:24].hex(),
                # Stored file
                "stored_name": f"{name}.enc",
                "stored_size": enc_size,
                # Original file removal status
                "original_status": meta.get("original_status", "unknown"),
                "original_reason": meta.get("original_reason", ""),
            })
        except FileNotFoundError:
            return jsonify({"error": "NotFound", "message": "File not found."}), 404

    @app.route('/api/verify-all', methods=['POST'])
    def verify_all_api():
        raw = verify_vault_integrity(session, storage_dir)
        safe = sum(1 for r in raw if r.get("status") == "SAFE")
        tampered = sum(1 for r in raw if r.get("status") == "TAMPERED")
        errors = sum(1 for r in raw if r.get("status") not in ("SAFE", "TAMPERED"))
        return jsonify({
            "safe": safe,
            "tampered": tampered,
            "errors": errors,
            "details": raw,
        })

    return app
