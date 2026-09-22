#!/usr/bin/env bash
# ============================================================================
# Cryptix CLI Demo Script (Bash)
# ============================================================================
# DEMO ONLY – The passphrase is passed via an environment variable so this
# script can run non-interactively.  NEVER do this in production; always use
# interactive getpass input.
# ============================================================================

set -euo pipefail

# Demo-only passphrase (≥ 10 characters).  In real usage, the CLI prompts
# interactively via getpass.
export CRYPTIX_PASSPHRASE="demo-passphrase-123"

STORAGE="./demo_secure_storage"
SAMPLE="./demo_sample"
OUTPUT="./demo_output"

echo "============================================"
echo " Cryptix CLI Demo"
echo "============================================"
echo ""

# Clean up from any previous run
rm -rf "$STORAGE" "$SAMPLE" "$OUTPUT"

# ------------------------------------------------------------------
# 1. Create a sample folder with a few files
# ------------------------------------------------------------------
echo ">>> Creating sample folder …"
mkdir -p "$SAMPLE/subdir"
echo "Hello from Cryptix!"           > "$SAMPLE/readme.txt"
echo "Nested secret file"            > "$SAMPLE/subdir/secret.txt"
printf '\x00\x01\x02\x03\x04\x05'   > "$SAMPLE/binary.dat"
echo ""

# ------------------------------------------------------------------
# 2. Init – generate RSA keypair
# ------------------------------------------------------------------
echo ">>> cryptix init"
python app_cli.py --storage "$STORAGE" init
echo ""

# ------------------------------------------------------------------
# 3. Encrypt the sample folder
# ------------------------------------------------------------------
echo ">>> cryptix encrypt $SAMPLE"
python app_cli.py --storage "$STORAGE" encrypt "$SAMPLE"
echo ""

# ------------------------------------------------------------------
# 4. List encrypted files
# ------------------------------------------------------------------
echo ">>> cryptix list"
python app_cli.py --storage "$STORAGE" list
echo ""

# ------------------------------------------------------------------
# 5. Decrypt all → should be SAFE
# ------------------------------------------------------------------
echo ">>> cryptix decrypt all $OUTPUT  (expect SAFE)"
python app_cli.py --storage "$STORAGE" decrypt all "$OUTPUT" || true
echo ""

# ------------------------------------------------------------------
# 6. Corrupt one byte of a data.enc, then decrypt → TAMPERED
# ------------------------------------------------------------------
echo ">>> Corrupting one data.enc …"
# Find the first data.enc
DATA_ENC=$(find "$STORAGE/files" -name "data.enc" | head -n1)
python -c "
import sys
p = sys.argv[1]
d = bytearray(open(p,'rb').read())
d[0] ^= 0xFF
open(p,'wb').write(d)
print(f'   Flipped byte 0 in {p}')
" "$DATA_ENC"
echo ""

echo ">>> cryptix decrypt all ${OUTPUT}_tampered  (expect TAMPERED)"
python app_cli.py --storage "$STORAGE" decrypt all "${OUTPUT}_tampered" || echo "   (exit code $? — expected non-zero for TAMPERED)"
echo ""

# ------------------------------------------------------------------
# Done
# ------------------------------------------------------------------
echo "============================================"
echo " Demo complete!"
echo "============================================"
