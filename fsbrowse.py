import os
import string
from pathlib import Path
from typing import Dict, List, Any

from core.errors import PathSafetyError


def is_same_or_inside(path: Path | str, storage_dir: Path | str) -> bool:
    """True when path equals storage_dir or is nested inside it."""
    try:
        p_norm = Path(os.path.normcase(str(Path(path).resolve())))
        s_norm = Path(os.path.normcase(str(Path(storage_dir).resolve())))
        return p_norm == s_norm or s_norm in p_norm.parents
    except Exception:
        return False


def is_parent_of(path: Path | str, storage_dir: Path | str) -> bool:
    """True when path is a parent (ancestor) of storage_dir."""
    try:
        p_norm = Path(os.path.normcase(str(Path(path).resolve())))
        s_norm = Path(os.path.normcase(str(Path(storage_dir).resolve())))
        return p_norm != s_norm and p_norm in s_norm.parents
    except Exception:
        return False


def is_protected(path: Path | str, storage_dir: Path | str) -> bool:
    """True when path equals storage_dir, is inside it, or is a parent of it."""
    return is_same_or_inside(path, storage_dir) or is_parent_of(path, storage_dir)


def list_drives() -> List[str]:
    """Return available Windows drives, e.g., ['C:\\', 'D:\\']. Empty on non-Windows."""
    if os.name != 'nt':
        return []
    drives = []
    for letter in string.ascii_uppercase:
        drive = f"{letter}:\\"
        if Path(drive).exists():
            drives.append(drive)
    return drives


def _build_breadcrumbs(path: Path) -> List[Dict[str, str]]:
    """Build breadcrumb list from root to path."""
    crumbs = []
    parts = path.parts  # e.g. ('C:\\', 'Users', 'foo')
    accumulated = Path(parts[0]) if parts else path
    crumbs.append({"name": parts[0] if parts else str(path), "path": str(accumulated)})
    for part in parts[1:]:
        accumulated = accumulated / part
        crumbs.append({"name": part, "path": str(accumulated)})
    return crumbs


def list_directory(path_str: str, storage_dir: Path) -> Dict[str, Any]:
    """Safe directory listing for fsbrowse.

    Returns a dict with keys:
      current_path, parent, breadcrumbs, readable, items, drives
    where items is a list of {name, path, is_dir, size}.
    """
    if not path_str:
        # Default to home directory
        path = Path.home().resolve()
    else:
        # Reject raw path-traversal sequences before resolving
        if '..' in Path(path_str).parts:
            raise PathSafetyError("Path traversal is not allowed.")
        path = Path(path_str).resolve()

    if not path.is_dir():
        raise PathSafetyError("Path is not a directory.")

    # Secure storage directory itself or anything inside it cannot be browsed
    if is_same_or_inside(path, storage_dir):
        raise PathSafetyError("Cannot select the secure storage directory itself or its contents.")

    parent = str(path.parent) if path.parent != path else None
    breadcrumbs = _build_breadcrumbs(path)

    items = []
    readable = True
    try:
        for entry in os.scandir(path):
            try:
                entry_resolved = Path(entry.path).resolve()
                # Hide secure storage folder from parent directory listings
                if is_same_or_inside(entry_resolved, storage_dir):
                    continue

                is_dir = entry.is_dir(follow_symlinks=False)
                size = None if is_dir else entry.stat(follow_symlinks=False).st_size
                items.append({
                    "name": entry.name,
                    "path": str(entry_resolved),
                    "is_dir": is_dir,
                    "size": size,
                })
            except PermissionError:
                continue
    except PermissionError:
        readable = False

    items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))

    return {
        "current_path": str(path),
        "parent": parent,
        "breadcrumbs": breadcrumbs,
        "readable": readable,
        "items": items,
        "drives": list_drives(),
    }


def preview_directory(path_str: str, storage_dir: Path) -> Dict[str, Any]:
    """Preview what encrypt_folder would do.

    Returns: file_count, total_size, skipped_symlinks (count).
    """
    if not path_str:
        raise PathSafetyError("No path provided.")

    if '..' in Path(path_str).parts:
        raise PathSafetyError("Path traversal is not allowed.")

    path = Path(path_str).resolve()

    if is_same_or_inside(path, storage_dir):
        raise PathSafetyError("Cannot select the secure storage directory itself or its contents.")

    if is_parent_of(path, storage_dir):
        raise PathSafetyError("This folder contains your secure vault. Choose a different folder.")

    if path.is_file():
        if path.is_symlink():
            return {"file_count": 0, "total_size": 0, "skipped_symlinks": 1}
        return {"file_count": 1, "total_size": path.stat().st_size, "skipped_symlinks": 0}

    if not path.is_dir():
        raise PathSafetyError("Path is not a file or directory.")

    file_count = 0
    total_size = 0
    skipped_symlinks = 0

    try:
        for root, dirs, files in os.walk(path):
            root_path = Path(root)
            for name in files:
                full = root_path / name
                if full.is_symlink():
                    skipped_symlinks += 1
                    continue
                file_count += 1
                total_size += full.stat().st_size
    except PermissionError:
        raise PathSafetyError("Permission denied reading directory for preview.")

    return {
        "file_count": file_count,
        "total_size": total_size,
        "skipped_symlinks": skipped_symlinks,
    }
