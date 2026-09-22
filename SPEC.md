# Cryptix: Secure Folder System Specification

## Algorithm roles (all mandatory)
- AES-256-GCM: encrypts and decrypts the actual files
- RSA-3072 with OAEP (MGF1-SHA256, SHA256, no label): encrypts the AES key
- SHA-256: hash of each original file, stored, used to verify integrity and detect tampering

## Flow 1: Encryption
USER (unlock private key with passphrase) -> Secure Folder -> Select File
Select File splits into two branches:
  Branch A: SHA-256 creates hash of the original -> Hash Stored
  Branch B: AES encrypts the file -> Encrypted File
AES key -> RSA encryption (public key) -> Encrypted AES key
Secure Storage holds: Encrypted File + Encrypted AES Key + Stored Hash

## Flow 2: Decryption and verification
Secure Storage (Encrypted File + Encrypted AES Key)
-> RSA decrypt the AES key (private key) -> AES key
-> AES decryption -> Original File (written to a TEMP file first)
-> SHA-256 of decrypted file -> compare with stored hash
-> MATCH = SAFE (move file to destination)
-> NO MATCH or GCM failure = TAMPERED (delete temp file, release nothing)

## Security rules
- Fresh random 256-bit AES key per file, never reused
- AES-GCM in 1 MiB chunks (streaming); nonce = 8-byte random prefix + 4-byte chunk counter
- AAD = file_id + chunk index + final-chunk flag + stored SHA-256 hex, so truncation, reordering, chunk swapping, and editing the stored hash are all detected
- Private key stored as PKCS8 PEM encrypted with the user's passphrase (min 10 characters)
- Failed-login counter persisted; delays 1s, 2s, 4s ... capped at 60s; reset on success
- Session holds the unlocked private key in memory only; auto-lock after 5 minutes of inactivity
- Original filenames never appear in plaintext on disk (stored as name_enc inside meta.json)
- Atomic writes (temp file then os.replace); full rollback on failure; source folder untouched
- Path traversal on decrypt is rejected (PathSafetyError)
- Never log or print passphrases or keys; use only modern cryptography APIs (no backend= argument, no PKCS1v15, no ECB/CBC)
- Skip symlinks and report them; never overwrite files silently

## Secure Storage layout (created at runtime inside cryptix/, default ./secure_storage)
secure_storage/
  keys/public.pem, keys/private.pem
  files/<uuid4>/data.enc, key.enc, meta.json
meta.json fields: version, file_id, sha256, nonce_prefix, chunk_size, size, created_at, name_enc

## Branding
App name: Cryptix. Window title: "Cryptix | Secure Folder System". Header text: "CRYPTIX".

## Modules
core/errors.py, hashing.py, crypto_aes.py, crypto_rsa.py, keys.py, storage.py, pipeline.py
ui/theme.py, ui/widgets.py, ui/app.py, ui/controller.py
app_cli.py, app_gui.py

## Rules for every step
- Use pathlib, type hints, binary file modes, no hardcoded paths or secrets
- Run the tests for the current step and show me the output before finishing
- Do not start the next step

## Web addendum
- The GUI is now a local web app served on 127.0.0.1 only (never 0.0.0.0), Flask, vanilla HTML/CSS/JS, no frameworks, no build step, no CDN and no external requests of any kind (fonts, icons, and scripts are all local or inline).
- Modules: web/server.py, web/jobs.py, web/fsbrowse.py, web/templates/index.html, web/static/css/style.css, web/static/js/app.js, app_web.py, tests/test_web.py
- The Tkinter files (ui/, app_gui.py) are no longer used; leave them untouched.
