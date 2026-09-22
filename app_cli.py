#!/usr/bin/env python3
"""Cryptix – Secure Folder System CLI.

Usage:
    python app_cli.py <command> [options]

Commands:
    init              Generate a new RSA keypair and initialise secure storage
    encrypt <path>    Encrypt a file or folder into secure storage
    decrypt <id|all>  Decrypt a file (or all files) to a destination directory
    list              List all encrypted files in storage
    share             Share an encrypted file with another user
    export-pubkey     Export your public key for sharing

Run ``python app_cli.py <command> --help`` for per-command usage.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from core.errors import (
    AuthError,
    KeyUnwrapError,
    PathSafetyError,
    SecureFolderError,
    StorageError,
    TamperedError,
    WrongPassphraseError,
)
from core.keys import Session, init_user
from core.pipeline import (
    decrypt_all,
    decrypt_file,
    encrypt_file,
    encrypt_folder,
    export_public_key,
    list_entries,
    share_file,
)
from core.storage import data_enc_path, list_files

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_BANNER = r"""
   ██████╗██████╗ ██╗   ██╗██████╗ ████████╗██╗██╗  ██╗
  ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██║╚██╗██╔╝
  ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║ ╚███╔╝
  ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║ ██╔██╗
  ╚██████╗██║  ██║   ██║   ██║        ██║   ██║██╔╝ ██╗
   ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   ╚═╝╚═╝  ╚═╝
  Secure Folder System
"""

_DEFAULT_STORAGE = "./secure_storage"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_passphrase(prompt: str = "Passphrase: ") -> str:
    """Read a passphrase from the environment (demo only) or via getpass."""
    # CRYPTIX_PASSPHRASE is for non-interactive demos only.
    env = os.environ.get("CRYPTIX_PASSPHRASE")
    if env is not None:
        return env
    return getpass.getpass(prompt)


def _event_printer(step: str, detail: str) -> None:
    """Print pipeline events to stderr as they fire."""
    icon = {
        "sha256_hash": "🔍",
        "aes_encrypt": "🔒",
        "rsa_wrap_key": "🔑",
        "store": "💾",
        "verify": "✅",
        "rsa_unwrap_key": "🔑",
        "aes_decrypt": "🔓",
        "sha256_compare": "🔍",
        "result": "📋",
    }.get(step, "•")
    print(f"  {icon}  [{step}] {detail}", file=sys.stderr)


def _fatal(msg: str, code: int = 1) -> None:
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(code)


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> None:
    storage = Path(args.storage)
    passphrase = _get_passphrase("New passphrase (min 10 characters): ")
    confirm = _get_passphrase("Confirm passphrase: ")
    if passphrase != confirm:
        _fatal("Passphrases do not match.")
    try:
        init_user(storage, passphrase)
    except AuthError as e:
        _fatal(str(e))
    except FileExistsError as e:
        _fatal(str(e))
    print(f"✅ Keypair created in {storage / 'keys'}")


def cmd_encrypt(args: argparse.Namespace) -> None:
    storage = Path(args.storage)
    target = Path(args.path)
    passphrase = _get_passphrase()
    sess = Session()
    try:
        sess.unlock(storage, passphrase)
    except WrongPassphraseError:
        _fatal("Wrong passphrase.")
    except FileNotFoundError:
        _fatal(f"Storage not found at {storage}. Run 'init' first.")

    if target.is_file():
        try:
            fid = encrypt_file(
                sess, target, storage,
                on_event=_event_printer,
            )
            print(f"✅ Encrypted → {fid}")
        except SecureFolderError as e:
            _fatal(str(e))
    elif target.is_dir():
        try:
            summary = encrypt_folder(
                sess, target, storage,
                on_event=_event_printer,
            )
            print(f"✅ Encrypted {summary.encrypted} file(s)")
            if summary.skipped:
                print(f"⚠️  Skipped: {', '.join(summary.skipped)}")
            if summary.errors:
                print(f"❌ Errors: {len(summary.errors)}")
                for e in summary.errors:
                    print(f"   {e}")
        except SecureFolderError as e:
            _fatal(str(e))
    else:
        _fatal(f"Path not found: {target}")


def cmd_decrypt(args: argparse.Namespace) -> None:
    storage = Path(args.storage)
    dest = Path(args.dest)
    passphrase = _get_passphrase()
    sess = Session()
    try:
        sess.unlock(storage, passphrase)
    except WrongPassphraseError:
        _fatal("Wrong passphrase.")
    except FileNotFoundError:
        _fatal(f"Storage not found at {storage}. Run 'init' first.")

    tampered_any = False

    if args.target == "all":
        try:
            results = decrypt_all(sess, storage, dest, on_event=_event_printer)
        except SecureFolderError as e:
            _fatal(str(e))
        for vr in results:
            _print_result(vr)
            if vr.status == "TAMPERED":
                tampered_any = True
    else:
        file_id = args.target
        try:
            vr = decrypt_file(sess, file_id, storage, dest, on_event=_event_printer)
        except KeyUnwrapError as e:
            _fatal(f"Key unwrap failed (corrupted key.enc?): {e}")
        except SecureFolderError as e:
            _fatal(str(e))
        _print_result(vr)
        if vr.status == "TAMPERED":
            tampered_any = True

    if tampered_any:
        sys.exit(2)


def _print_result(vr) -> None:
    if vr.status == "SAFE":
        print(f"  ✅ SAFE   {vr.file_id}  →  {vr.dest_path}")
        print(f"           SHA-256: {vr.expected_hash[:16]}…")
    else:
        print(f"  ❌ TAMPERED  {vr.file_id}")
        print(f"     Expected: {vr.expected_hash[:16]}…")
        actual = vr.actual_hash[:16] + "…" if vr.actual_hash else "(n/a)"
        print(f"     Actual:   {actual}")
        if vr.reason:
            print(f"     Reason:   {vr.reason}")


def cmd_list(args: argparse.Namespace) -> None:
    storage = Path(args.storage)
    passphrase = _get_passphrase()
    sess = Session()
    try:
        sess.unlock(storage, passphrase)
    except WrongPassphraseError:
        _fatal("Wrong passphrase.")
    except FileNotFoundError:
        _fatal(f"Storage not found at {storage}. Run 'init' first.")

    try:
        entries = list_entries(sess, storage)
    except SecureFolderError as e:
        _fatal(str(e))

    if not entries:
        print("(no files in storage)")
        return

    print(f"{'Name':<40} {'Size':>10}  {'SHA-256 prefix':<18} {'File ID'}")
    print("─" * 110)
    for e in entries:
        size_str = _human_size(e.size)
        print(f"{e.name:<40} {size_str:>10}  {e.sha256_prefix:<18} {e.file_id}")
    print(f"\n{len(entries)} file(s) in storage.")


def _human_size(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def cmd_share(args: argparse.Namespace) -> None:
    storage = Path(args.storage)
    passphrase = _get_passphrase()
    sess = Session()
    try:
        sess.unlock(storage, passphrase)
    except WrongPassphraseError:
        _fatal("Wrong passphrase.")

    recipient_pem = Path(args.recipient_pem).read_bytes()
    out_dir = Path(args.out_dir)

    try:
        share_file(sess, args.file_id, storage, recipient_pem, out_dir)
    except SecureFolderError as e:
        _fatal(str(e))

    print(f"✅ Bundle written to {out_dir}")


def cmd_export_pubkey(args: argparse.Namespace) -> None:
    storage = Path(args.storage)
    out = Path(args.out)
    try:
        export_public_key(storage, out)
    except FileNotFoundError:
        _fatal(f"Storage not found at {storage}. Run 'init' first.")
    print(f"✅ Public key exported to {out}")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptix",
        description="Cryptix | Secure Folder System",
        epilog="Run 'cryptix <command> --help' for per-command help.",
    )
    parser.add_argument(
        "--storage", default=_DEFAULT_STORAGE,
        help=f"Path to the secure storage directory (default: {_DEFAULT_STORAGE})",
    )

    sub = parser.add_subparsers(dest="command", title="commands")

    # init
    sub.add_parser("init", help="Generate keypair and initialise storage")

    # encrypt
    p_enc = sub.add_parser("encrypt", help="Encrypt a file or folder")
    p_enc.add_argument("path", help="File or directory to encrypt")

    # decrypt
    p_dec = sub.add_parser("decrypt", help="Decrypt a file or all files")
    p_dec.add_argument("target", help="File ID or 'all'")
    p_dec.add_argument("dest", help="Destination directory")

    # list
    sub.add_parser("list", help="List all encrypted files")

    # share
    p_share = sub.add_parser("share", help="Share an encrypted file")
    p_share.add_argument("file_id", help="File ID to share")
    p_share.add_argument("recipient_pem", help="Path to recipient's public.pem")
    p_share.add_argument("out_dir", help="Output directory for the bundle")

    # export-pubkey
    p_exp = sub.add_parser("export-pubkey", help="Export your public key")
    p_exp.add_argument("out", help="Output path for the PEM file")

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print(_BANNER, file=sys.stderr)
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "init": cmd_init,
        "encrypt": cmd_encrypt,
        "decrypt": cmd_decrypt,
        "list": cmd_list,
        "share": cmd_share,
        "export-pubkey": cmd_export_pubkey,
    }

    try:
        dispatch[args.command](args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
    except SecureFolderError as e:
        _fatal(str(e))


if __name__ == "__main__":
    main()
