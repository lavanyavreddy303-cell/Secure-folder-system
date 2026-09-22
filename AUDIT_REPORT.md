# Cryptix Audit Report (Phase 0 Baseline)

Date: 2026-09-21
Auditor: Antigravity Automated Verification Agent
Scope: Verification of Cryptix against Requirements R1–R7

| Requirement | Requirement Summary | What Actually Happens | Evidence / Source | Status |
| :--- | :--- | :--- | :--- | :--- |
| **R1** | Unreadable ciphertext with AES; original plaintext must not remain in normal folder after verified encryption. | By default, `delete_originals` is `False`. The toggle is off by default, so originals remain accessible in normal folder. Single-file encryption in `JobManager` does not verify before deleting. | `web/server.py` line 259: `delete_originals = data.get('delete_originals', False)`. `web/static/js/app.js` toggle unselected by default. | **FAIL** |
| **R2** | Decryption with correct key restores original file, byte for byte. | Decryption recovers AES key via RSA, decrypts AES-256-GCM stream, and verifies SHA-256 matches. Files match byte-for-byte. | `core/pipeline.py` (`decrypt_file`, `decrypt_stream`), `tests/test_aes.py`, `tests/test_pipeline.py`. | **PASS** |
| **R3** | AES encrypts content; RSA wraps AES key; SHA-256 is integrity fingerprint only. | Content is encrypted with AES-256-GCM (`data.enc`); 256-bit AES key is RSA-3072 OAEP wrapped (`key.enc`); SHA-256 stored in `meta.json`. | `core/pipeline.py` lines 177–208, `core/crypto_aes.py`, `core/crypto_rsa.py`. | **PASS** |
| **R4** | SHA-256 converts content into fixed-length hash; avalanche effect on tiny changes. | SHA-256 algorithm exhibits standard avalanche behavior, but UI lacks the required interactive "Hash Lab" panel to demonstrate this. | `core/hashing.py`; missing `/api/hash/*` endpoints and Hash Lab UI in `web/templates/index.html`. | **FAIL** |
| **R5** | File -> original hash; Decrypt -> new hash; Equal = SAFE, Different = TAMPERED. | Tampering is caught by HMAC/tag and SHA-256 check, but UI truncates hashes to 8 or 16 characters (`(expected_hash).substring(0, 16)...`), omitting full 64-char comparison and diff highlighting. | `web/static/js/app.js` line 1338: `substring(0, 16)...`. | **FAIL** |
| **R6** | Workflow: SHA-256 -> AES -> RSA -> store -> verify. Decrypt: RSA -> AES -> SHA-256 verify. | Functional pipeline implements order, but pipeline trace labels in UI do not follow R6 exact naming, and trace spinner keeps spinning indefinitely after job completion. | `web/static/js/app.js` line 105; `web/jobs.py` events record `state: "running"` perpetually. | **FAIL** |
| **R7** | Folder encrypted file by file; structure restored on decrypt; originals no longer accessible. | Folder files are encrypted separately and restored, but originals are kept by default, and empty directories are not cleaned up bottom-up. | `core/pipeline.py` line 291: only unlinks files if `delete_originals=True`, does not remove empty folders or verify before deletion. | **FAIL** |

### Summary
- **Passed**: 2 / 7 (R2, R3)
- **Failed**: 5 / 7 (R1, R4, R5, R6, R7)
- **Next Step**: Proceed to Phase 1 (Known Bugs) and Phase 2 (Safe Original Removal) to address all failed requirements.
