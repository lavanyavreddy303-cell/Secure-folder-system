import threading
import uuid
from typing import Dict, Any, Optional
from pathlib import Path

from core.pipeline import (
    encrypt_folder,
    encrypt_file,
    decrypt_all,
    decrypt_file,
    FolderSummary,
    is_critical_path,
    _safe_unlink,
    lock_file_in_place,
)
from core.hashing import sha256_file
from core.keys import Session

def _make_serializable(obj: Any) -> Any:
    """Recursively convert results into JSON-serializable primitives."""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, dict):
        return {str(k): _make_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_make_serializable(x) for x in obj]
    if hasattr(obj, "__dict__"):
        return _make_serializable(obj.__dict__)
    if isinstance(obj, Exception):
        return str(obj)
    return str(obj)

class JobManager:
    def __init__(self, storage_dir: Path):
        self.storage_dir = Path(storage_dir)
        self._jobs: Dict[str, dict] = {}
        self._lock = threading.Lock()
        self._max_jobs = 50

    def _create_job(self, type_: str) -> str:
        job_id = str(uuid.uuid4())
        with self._lock:
            self._jobs[job_id] = {
                "id": job_id,
                "type": type_,
                "state": "pending", # pending, running, done, failed, cancelled
                "progress": 0.0,
                "events": [],
                "results": None,
                "error": None,
                "cancel_event": threading.Event()
            }
            # Trim to max 50 jobs (keep newest)
            if len(self._jobs) > self._max_jobs:
                oldest = list(self._jobs.keys())[0]
                del self._jobs[oldest]
        return job_id

    def get_job(self, job_id: str) -> Optional[dict]:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
            # Return a copy without cancel_event
            ret = dict(job)
            ret.pop("cancel_event", None)
            return ret

    def cancel_job(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return False
            if job["state"] in ("pending", "running"):
                job["cancel_event"].set()
                return True
            return False

    def _job_worker(self, job_id: str, target: callable, *args, **kwargs):
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job["state"] = "running"
            cancel_event = job["cancel_event"]

        def on_event(step: str, detail: str):
            with self._lock:
                j = self._jobs.get(job_id)
                if j:
                    j["events"].append({
                        "step": step,
                        "state": j["state"],
                        "detail": detail
                    })

        def on_progress(frac: float):
            with self._lock:
                j = self._jobs.get(job_id)
                if j:
                    j["progress"] = frac

        kwargs["on_event"] = on_event
        kwargs["on_progress"] = on_progress
        kwargs["cancel"] = cancel_event

        try:
            res = target(*args, **kwargs)
            with self._lock:
                j = self._jobs.get(job_id)
                if j:
                    j["state"] = "done"
                    j["results"] = _make_serializable(res)
                    j["progress"] = 1.0
                    for ev in j["events"]:
                        ev["state"] = "done"
        except InterruptedError:
            with self._lock:
                j = self._jobs.get(job_id)
                if j:
                    j["state"] = "cancelled"
                    for ev in j["events"]:
                        if ev.get("state") == "running":
                            ev["state"] = "pending"
        except Exception as e:
            with self._lock:
                j = self._jobs.get(job_id)
                if j:
                    j["state"] = "failed"
                    j["error"] = str(e)
                    if j["events"]:
                        for ev in j["events"][:-1]:
                            ev["state"] = "done"
                        j["events"][-1]["state"] = "failed"

    def submit_encrypt(self, session: Session, path: str, delete_originals: bool, lock_in_place: bool = False) -> str:
        job_id = self._create_job("encrypt")
        p = Path(path)

        if p.is_dir():
            target = encrypt_folder
            args = (session, p, self.storage_dir)
            kwargs = {"delete_originals": delete_originals, "lock_in_place": lock_in_place}
        else:
            def wrapped_encrypt_file(*a, **kw):
                cancel = kw.get("cancel")
                on_event = kw.get("on_event")
                on_progress = kw.get("on_progress")

                summary = FolderSummary()
                p_file = Path(path)
                try:
                    file_size = p_file.stat().st_size
                    sha_hex = sha256_file(p_file)

                    fid = encrypt_file(
                        session, p_file, self.storage_dir,
                        on_event=on_event, on_progress=on_progress, cancel=cancel,
                        delete_original=False, lock_in_place=False,
                    )
                    summary.encrypted = 1
                    summary.file_ids.append(fid)
                    summary.files.append({
                        "name": p_file.name,
                        "sha256": sha_hex,
                        "size": file_size,
                    })

                    if lock_in_place:
                        if is_critical_path(p_file, self.storage_dir):
                            summary.kept_unlocked.append(f"{p_file.name}: protected path cannot be locked")
                        else:
                            try:
                                lock_file_in_place(p_file, self.storage_dir, fid)
                                summary.locked_in_place = 1
                            except Exception as err:
                                summary.kept_unlocked.append(f"{p_file.name}: could not lock ({err})")
                    elif delete_originals:
                        if is_critical_path(p_file, self.storage_dir):
                            summary.originals_kept.append(f"{p_file.name}: protected path cannot be deleted")
                        else:
                            ok, err = _safe_unlink(p_file)
                            if ok:
                                summary.originals_removed = 1
                            else:
                                summary.originals_kept.append(f"{p_file.name}: could not delete ({err})")
                except InterruptedError:
                    raise
                except Exception as exc:
                    summary.errors.append(f"{Path(path).name}: {exc}")
                    raise
                # Add file_id field for backward compatibility with tests
                # that read job["results"]["file_id"] (singular)
                if summary.file_ids:
                    summary.file_id = summary.file_ids[0]
                return summary

            target = wrapped_encrypt_file
            args = ()
            kwargs = {}

        t = threading.Thread(target=self._job_worker, args=(job_id, target, *args), kwargs=kwargs)
        t.start()
        return job_id

    def submit_decrypt(self, session: Session, file_ids: Any, dest: str) -> str:
        job_id = self._create_job("decrypt")
        dest_path = Path(dest).resolve()
        dest_path.mkdir(parents=True, exist_ok=True)
        
        def wrapped_decrypt(*a, **kw):
            cancel = kw.get("cancel")
            if file_ids == "all":
                return decrypt_all(*a, **kw)
            else:
                results = []
                total = len(file_ids)
                on_progress = kw.get("on_progress")
                for i, fid in enumerate(file_ids):
                    if cancel and cancel.is_set():
                        raise InterruptedError("Operation cancelled.")
                    def sub_prog(frac):
                        if on_progress:
                            on_progress((i + frac) / max(total, 1))
                    
                    kw["on_progress"] = sub_prog
                    res = decrypt_file(a[0], fid, a[1], a[2], on_event=kw.get("on_event"), on_progress=sub_prog, cancel=cancel)
                    results.append(res)
                return results

        args = (session, self.storage_dir, dest_path)
        t = threading.Thread(target=self._job_worker, args=(job_id, wrapped_decrypt, *args), kwargs={})
        t.start()
        return job_id
