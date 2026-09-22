"""Controller logic for decoupling background crypto tasks from Tkinter."""

import queue
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List

from core.errors import SecureFolderError
from core.pipeline import (
    FolderSummary,
    VerifyResult,
    decrypt_file,
    encrypt_file,
    encrypt_folder,
)


@dataclass
class EventMsg:
    step: str
    detail: str


@dataclass
class ProgressMsg:
    fraction: float


@dataclass
class ResultMsg:
    # For encrypt: dict with 'file_id' or 'summary' (FolderSummary)
    # For decrypt: list of VerifyResult
    data: Any


@dataclass
class ErrorMsg:
    error: str


class TaskController:
    """Manages background execution of encrypt/decrypt tasks."""

    def __init__(self):
        self.q = queue.Queue()
        self.cancel_evt = threading.Event()
        self._thread = None

    def _fire_event(self, step: str, detail: str) -> None:
        self.q.put(EventMsg(step, detail))

    def _fire_progress(self, fraction: float) -> None:
        self.q.put(ProgressMsg(fraction))

    def poll(self) -> List[Any]:
        """Yield all messages currently in the queue."""
        messages = []
        while True:
            try:
                messages.append(self.q.get_nowait())
            except queue.Empty:
                break
        return messages

    def cancel(self) -> None:
        """Signal the background task to cancel."""
        self.cancel_evt.set()

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start_encrypt(self, session, path: Path, storage_dir: Path, delete_originals: bool = False) -> None:
        """Start encryption in a background thread."""
        self.cancel_evt.clear()
        self._thread = threading.Thread(
            target=self._run_encrypt,
            args=(session, path, storage_dir, delete_originals),
            daemon=True,
        )
        self._thread.start()

    def _run_encrypt(self, session, path: Path, storage_dir: Path, delete_originals: bool) -> None:
        try:
            if path.is_dir():
                summary = encrypt_folder(
                    session, path, storage_dir,
                    on_event=self._fire_event,
                    on_progress=self._fire_progress,
                    cancel=self.cancel_evt,
                    delete_originals=delete_originals
                )
                self.q.put(ResultMsg({"summary": summary}))
            else:
                fid = encrypt_file(
                    session, path, storage_dir,
                    on_event=self._fire_event,
                    on_progress=self._fire_progress,
                    cancel=self.cancel_evt
                )
                if delete_originals:
                    path.unlink(missing_ok=True)
                self.q.put(ResultMsg({"file_id": fid}))
        except InterruptedError:
            self.q.put(ErrorMsg("Cancelled by user."))
        except SecureFolderError as e:
            self.q.put(ErrorMsg(str(e)))
        except Exception as e:
            self.q.put(ErrorMsg(f"Unexpected error: {e}"))

    def start_decrypt(self, session, file_ids: List[str], storage_dir: Path, dest_dir: Path) -> None:
        """Start decryption in a background thread."""
        self.cancel_evt.clear()
        self._thread = threading.Thread(
            target=self._run_decrypt,
            args=(session, file_ids, storage_dir, dest_dir),
            daemon=True,
        )
        self._thread.start()

    def _run_decrypt(self, session, file_ids: List[str], storage_dir: Path, dest_dir: Path) -> None:
        try:
            results = []
            total = len(file_ids)
            for idx, fid in enumerate(file_ids):
                if self.cancel_evt.is_set():
                    raise InterruptedError("Operation cancelled.")
                
                # We need to adapt the on_progress to account for multiple files
                def _prog(frac):
                    overall = (idx + frac) / max(total, 1)
                    self._fire_progress(overall)
                    
                vr = decrypt_file(
                    session, fid, storage_dir, dest_dir,
                    on_event=self._fire_event,
                    on_progress=_prog,
                    cancel=self.cancel_evt
                )
                results.append(vr)
            
            self.q.put(ResultMsg(results))
        except InterruptedError:
            self.q.put(ErrorMsg("Cancelled by user."))
        except SecureFolderError as e:
            self.q.put(ErrorMsg(str(e)))
        except Exception as e:
            self.q.put(ErrorMsg(f"Unexpected error: {e}"))
