import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Callable

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.job import Job
from app.security.kill_switch import kill_switch


class TaskManager:
    """Runs long-running pipeline stages.

    By default uses a local ThreadPoolExecutor so the platform runs without
    Redis/Celery. When CELERY_BROKER_URL is configured the same functions can be
    dispatched through Celery (see app/tasks/celery_app.py).
    """

    _executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="pentest-job")
    _stop_flags: dict[int, threading.Event] = {}
    _lock = threading.Lock()

    @classmethod
    def submit(
        cls,
        job_id: int,
        func: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> None:
        with cls._lock:
            cls._stop_flags[job_id] = threading.Event()
        cls._executor.submit(cls._run, job_id, func, args, kwargs)

    @classmethod
    def _run(cls, job_id: int, func, args, kwargs) -> None:
        db = SessionLocal()
        try:
            job = db.get(Job, job_id)
            if not job:
                return
            job.status = "running"
            job.started_at = datetime.utcnow()
            db.commit()

            stop_flag = cls._stop_flags.get(job_id)
            if stop_flag is None:
                stop_flag = threading.Event()
                with cls._lock:
                    cls._stop_flags[job_id] = stop_flag

            cls._append_log(db, job_id, f"Job {job.task_type} started.")
            result = func(
                *args, **kwargs,
                _job_id=job_id,
                _job_log=cls._append_log,
                _job_is_stopped=lambda: stop_flag.is_set() or kill_switch.is_armed,
            )
            db = SessionLocal()
            job = db.get(Job, job_id)
            if not job:
                return
            job.status = "stopped" if stop_flag.is_set() or kill_switch.is_armed else "completed"
            job.finished_at = datetime.utcnow()
            job.progress = 100.0 if job.status == "completed" else job.progress
            job.result_json = result or {}
            db.commit()
        except Exception as exc:  # noqa: BLE001
            db = SessionLocal()
            job = db.get(Job, job_id)
            if job:
                job.status = "failed"
                job.error = str(exc)
                job.finished_at = datetime.utcnow()
                db.commit()
        finally:
            with cls._lock:
                cls._stop_flags.pop(job_id, None)

    @classmethod
    def _append_log(cls, db: Session, job_id: int, message: str) -> None:
        job = db.get(Job, job_id)
        if job:
            job.log = (job.log + "\n" + message).strip()
            db.commit()

    @classmethod
    def stop(cls, job_id: int) -> None:
        with cls._lock:
            flag = cls._stop_flags.get(job_id)
            if flag:
                flag.set()

    @classmethod
    def pause(cls, job_id: int) -> None:
        """Pause support: sets a flag the pipeline checks between stages."""
        with cls._lock:
            flag = cls._stop_flags.get(job_id)
            if flag and not flag.is_set():
                # Reuse the same event for pause/resume by flagging contents
                flag.set()

    @classmethod
    def resume(cls, job_id: int) -> None:
        with cls._lock:
            flag = cls._stop_flags.get(job_id)
            if flag and flag.is_set():
                flag.clear()

    @classmethod
    def update_progress(cls, db: Session, job_id: int, progress: float) -> None:
        job = db.get(Job, job_id)
        if job:
            job.progress = max(job.progress, progress)
            db.commit()


task_manager = TaskManager()