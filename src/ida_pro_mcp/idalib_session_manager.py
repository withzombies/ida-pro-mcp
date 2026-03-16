"""IDALib session and context management for headless workflows."""

from __future__ import annotations

import logging
import os
import shutil
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import ida_auto
import idapro

from .state import ensure_state_dir

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now()


@dataclass
class ContextRecord:
    """Represents a generic agent context bound to a default session."""

    context_id: str
    parent_context_id: Optional[str] = None
    created_at: datetime = field(default_factory=_utcnow)
    last_seen_at: datetime = field(default_factory=_utcnow)
    label: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "context_id": self.context_id,
            "parent_context_id": self.parent_context_id,
            "created_at": self.created_at.isoformat(),
            "last_seen_at": self.last_seen_at.isoformat(),
            "label": self.label,
            "metadata": self.metadata,
        }


@dataclass
class IDASession:
    """Represents a tracked IDA database session."""

    session_id: str
    input_path: Path
    working_input_path: Path
    database_path: Optional[Path] = None
    open_args: Optional[str] = None
    alias: Optional[str] = None
    created_at: datetime = field(default_factory=_utcnow)
    last_accessed: datetime = field(default_factory=_utcnow)
    is_analyzing: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "input_path": str(self.input_path),
            "working_input_path": str(self.working_input_path),
            "database_path": str(self.database_path) if self.database_path else None,
            "open_args": self.open_args,
            "filename": self.input_path.name,
            "alias": self.alias,
            "created_at": self.created_at.isoformat(),
            "last_accessed": self.last_accessed.isoformat(),
            "is_analyzing": self.is_analyzing,
            "metadata": self.metadata,
        }


@dataclass
class SessionOpenJob:
    """Represents an asynchronous session-open request."""

    job_id: str
    input_path: Path
    context_id: Optional[str] = None
    requested_alias: Optional[str] = None
    requested_session_id: Optional[str] = None
    database_path: Optional[Path] = None
    run_auto_analysis: bool = True
    status: str = "queued"
    created_at: datetime = field(default_factory=_utcnow)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    session_id: Optional[str] = None
    error: Optional[str] = None
    event: threading.Event = field(default_factory=threading.Event, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "input_path": str(self.input_path),
            "context_id": self.context_id,
            "requested_alias": self.requested_alias,
            "requested_session_id": self.requested_session_id,
            "database_path": str(self.database_path) if self.database_path else None,
            "run_auto_analysis": self.run_auto_analysis,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "session_id": self.session_id,
            "error": self.error,
        }


@dataclass
class _OpenSessionPlan:
    session_id: str
    input_path: Path
    working_input_path: Path
    database_path: Optional[Path]
    open_args: Optional[str]
    target_path: str
    alias: Optional[str]
    run_auto_analysis: bool


class IDASessionManager:
    """Manages tracked sessions, context bindings, and active IDB activation."""

    def __init__(self):
        self._sessions: Dict[str, IDASession] = {}
        self._contexts: Dict[str, ContextRecord] = {}
        self._active_session_id: Optional[str] = None
        self._context_bindings: Dict[str, str] = {}
        self._lock = threading.RLock()
        self._activation_lock = threading.Lock()
        self._jobs: Dict[str, SessionOpenJob] = {}
        logger.info("IDASessionManager initialized")

    def ensure_context(
        self,
        context_id: Optional[str] = None,
        *,
        force_new: bool = False,
        parent_context_id: Optional[str] = None,
        label: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> ContextRecord:
        with self._lock:
            effective_context_id = (context_id or "").strip()
            if effective_context_id and not force_new:
                existing = self._contexts.get(effective_context_id)
                if existing is not None:
                    existing.last_seen_at = _utcnow()
                    if label is not None:
                        existing.label = label
                    if metadata:
                        existing.metadata.update(metadata)
                    return existing

            parent = parent_context_id
            if force_new:
                if not parent and effective_context_id:
                    parent = effective_context_id
                effective_context_id = self._generate_context_id()

            if not effective_context_id:
                effective_context_id = self._generate_context_id()

            existing = self._contexts.get(effective_context_id)
            if existing is not None:
                existing.last_seen_at = _utcnow()
                if label is not None:
                    existing.label = label
                if metadata:
                    existing.metadata.update(metadata)
                if parent and existing.parent_context_id is None:
                    existing.parent_context_id = parent
                return existing

            record = ContextRecord(
                context_id=effective_context_id,
                parent_context_id=parent,
                label=label,
                metadata=dict(metadata or {}),
            )
            self._contexts[effective_context_id] = record
            return record

    def get_context(self, context_id: str) -> Optional[ContextRecord]:
        with self._lock:
            context = self._contexts.get(context_id)
            if context is not None:
                context.last_seen_at = _utcnow()
            return context

    def release_context(self, context_id: str) -> bool:
        with self._lock:
            released = self._contexts.pop(context_id, None)
            self._context_bindings.pop(context_id, None)
            return released is not None

    def open_binary(
        self,
        input_path: Path | str,
        run_auto_analysis: bool = True,
        session_id: Optional[str] = None,
        alias: Optional[str] = None,
        database_path: Path | str | None = None,
    ) -> str:
        input_path = Path(input_path).resolve()
        plan, existing_session_id = self._prepare_open_plan(
            input_path,
            run_auto_analysis=run_auto_analysis,
            session_id=session_id,
            alias=alias,
            database_path=database_path,
        )
        if existing_session_id is not None:
            return existing_session_id

        assert plan is not None
        session = self._execute_open_plan(plan)
        return session.session_id

    def submit_open_job(
        self,
        input_path: Path | str,
        *,
        context_id: Optional[str] = None,
        run_auto_analysis: bool = True,
        session_id: Optional[str] = None,
        alias: Optional[str] = None,
        database_path: Path | str | None = None,
    ) -> SessionOpenJob:
        resolved_input = Path(input_path).resolve()
        existing_session_id = self._validate_open_request(
            resolved_input,
            session_id=session_id,
            alias=alias,
        )
        job = SessionOpenJob(
            job_id=self._generate_job_id(),
            input_path=resolved_input,
            context_id=context_id,
            requested_alias=alias,
            requested_session_id=session_id,
            database_path=Path(database_path).expanduser().resolve() if database_path else None,
            run_auto_analysis=run_auto_analysis,
        )
        if existing_session_id is not None:
            if context_id:
                self.bind_context(context_id, existing_session_id, activate=False)
            job.status = "succeeded"
            job.started_at = _utcnow()
            job.finished_at = job.started_at
            job.session_id = existing_session_id
            job.event.set()
            with self._lock:
                self._jobs[job.job_id] = job
            return job

        with self._lock:
            self._jobs[job.job_id] = job
        return job

    def get_job(self, job_id: str) -> Optional[SessionOpenJob]:
        with self._lock:
            return self._jobs.get(job_id)

    def list_jobs(self) -> list[dict[str, Any]]:
        with self._lock:
            return [job.to_dict() for job in self._jobs.values()]

    def wait_for_job(self, job_id: str, timeout: Optional[float] = None) -> SessionOpenJob:
        job = self.get_job(job_id)
        if job is None:
            raise ValueError(f"Job not found: {job_id}")
        finished = job.event.wait(timeout)
        if not finished:
            raise TimeoutError(f"Timed out waiting for job: {job_id}")
        return job

    def mark_job_running(self, job_id: str) -> SessionOpenJob:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise ValueError(f"Job not found: {job_id}")
            job.status = "running"
            job.started_at = _utcnow()
            return job

    def mark_job_succeeded(self, job_id: str, session_id: str) -> SessionOpenJob:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise ValueError(f"Job not found: {job_id}")
            job.status = "succeeded"
            job.session_id = session_id
            job.finished_at = _utcnow()
            job.event.set()
            return job

    def mark_job_failed(self, job_id: str, error: str) -> SessionOpenJob:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise ValueError(f"Job not found: {job_id}")
            job.status = "failed"
            job.error = error
            job.finished_at = _utcnow()
            job.event.set()
            return job

    def close_session(self, session_id: str) -> bool:
        with self._lock:
            if session_id not in self._sessions:
                return False

            if self._active_session_id == session_id:
                idapro.close_database()
                self._active_session_id = None

            del self._sessions[session_id]
            self._unbind_session_everywhere_locked(session_id)
            return True

    def bind_context(
        self, context_id: str, session_id: str, activate: bool = False
    ) -> IDASession:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise ValueError(f"Session not found: {session_id}")

            self.ensure_context(context_id)
            self._context_bindings[context_id] = session_id
            session.last_accessed = _utcnow()
        if activate:
            self.activate_session(session_id)
        with self._lock:
            current = self._sessions.get(session_id)
            if current is None:
                raise ValueError(f"Session not found: {session_id}")
            return current

    def unbind_context(self, context_id: str) -> bool:
        with self._lock:
            removed = self._context_bindings.pop(context_id, None)
            return removed is not None

    def get_context_session_id(self, context_id: str) -> Optional[str]:
        with self._lock:
            return self._context_bindings.get(context_id)

    def get_context_session(self, context_id: str) -> Optional[IDASession]:
        with self._lock:
            session_id = self._context_bindings.get(context_id)
            if session_id is None:
                return None
            return self._sessions.get(session_id)

    def activate_context(self, context_id: str) -> IDASession:
        with self._lock:
            session_id = self._context_bindings.get(context_id)
            if session_id is None:
                raise RuntimeError(
                    "No session bound for this context. "
                    "Use idalib_switch(session_id) or idalib_open(...) first."
                )

            session = self._sessions.get(session_id)
            if session is None:
                self._context_bindings.pop(context_id, None)
                raise RuntimeError(
                    f"Context binding is stale (missing session: {session_id}). "
                    "Bind to a valid session again."
                )
        self.activate_session(session_id)
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise ValueError(f"Session not found: {session_id}")
            session.last_accessed = _utcnow()
            context = self._contexts.get(context_id)
            if context is not None:
                context.last_seen_at = _utcnow()
            return session

    def activate_session(self, session_id: str) -> IDASession:
        with self._lock:
            if self._active_session_id == session_id:
                session = self._sessions.get(session_id)
                if session is None:
                    raise ValueError(f"Session not found: {session_id}")
                return session
            session = self._sessions.get(session_id)
            if session is None:
                raise ValueError(f"Session not found: {session_id}")
            if session.database_path and session.database_path.exists():
                target_path = str(session.database_path)
                open_args = None
            else:
                target_path = str(session.working_input_path)
                open_args = session.open_args
        self._activate_database_path(
            target_path,
            run_auto_analysis=False,
            args=open_args,
        )
        with self._lock:
            current = self._sessions.get(session_id)
            if current is None:
                raise ValueError(f"Session not found: {session_id}")
            self._active_session_id = session_id
            current.last_accessed = _utcnow()
            return current

    def list_sessions(self, context_id: Optional[str] = None) -> list[dict[str, Any]]:
        with self._lock:
            context_session_id = self._context_bindings.get(context_id, None)
            binding_counts: Dict[str, int] = {}
            for bound_session_id in self._context_bindings.values():
                binding_counts[bound_session_id] = (
                    binding_counts.get(bound_session_id, 0) + 1
                )

            return [
                {
                    **session.to_dict(),
                    "is_active": session.session_id == self._active_session_id,
                    "is_active_loaded": session.session_id == self._active_session_id,
                    "is_current_context": session.session_id == context_session_id,
                    "bound_contexts": binding_counts.get(session.session_id, 0),
                }
                for session in self._sessions.values()
            ]

    def list_contexts(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {
                    **context.to_dict(),
                    "session_id": self._context_bindings.get(context.context_id),
                }
                for context in self._contexts.values()
            ]

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "active_session_id": self._active_session_id,
                "session_count": len(self._sessions),
                "context_count": len(self._contexts),
                "job_count": len(self._jobs),
            }

    def get_session(self, session_id: str) -> Optional[IDASession]:
        with self._lock:
            return self._sessions.get(session_id)

    def resolve_session_id(self, session_ref: str) -> str:
        with self._lock:
            if session_ref in self._sessions:
                return session_ref

            for session in self._sessions.values():
                if session.alias == session_ref:
                    return session.session_id

        raise ValueError(f"Session not found: {session_ref}")

    def close_all_sessions(self):
        with self._lock:
            if self._active_session_id is not None:
                idapro.close_database()
                self._active_session_id = None

            self._sessions.clear()
            self._context_bindings.clear()
            self._contexts.clear()
            self._jobs.clear()

    def _activate_database_path(
        self, input_path: str, run_auto_analysis: bool, args: Optional[str] = None
    ) -> None:
        with self._activation_lock:
            with self._lock:
                had_active = self._active_session_id is not None
                self._active_session_id = None
            if had_active:
                idapro.close_database()

            result = idapro.open_database(
                input_path,
                run_auto_analysis=run_auto_analysis,
                args=args,
            )
            if result:
                raise RuntimeError(
                    f"Failed to open database: {input_path} (idapro.open_database returned {result})"
                )
            if run_auto_analysis:
                ida_auto.auto_wait()

    def _unbind_session_everywhere_locked(self, session_id: str) -> None:
        stale_contexts = [
            context_id
            for context_id, bound_session_id in self._context_bindings.items()
            if bound_session_id == session_id
        ]
        for context_id in stale_contexts:
            del self._context_bindings[context_id]

    def _ensure_alias_available(
        self, alias: str, current_session_id: Optional[str] = None
    ) -> None:
        normalized_alias = alias.strip()
        if not normalized_alias:
            raise ValueError("Alias cannot be empty")
        for session in self._sessions.values():
            if session.alias == normalized_alias and session.session_id != current_session_id:
                raise ValueError(f"Session alias already exists: {normalized_alias}")

    @staticmethod
    def _generate_context_id() -> str:
        return f"ctx_{uuid.uuid4().hex[:12]}"

    @staticmethod
    def _generate_session_id() -> str:
        return uuid.uuid4().hex[:8]

    @staticmethod
    def _generate_job_id() -> str:
        return f"job_{uuid.uuid4().hex[:10]}"

    def _prepare_working_input_path(self, input_path: Path) -> Path:
        if os.access(input_path.parent, os.W_OK):
            return input_path

        stage_root = ensure_state_dir() / "inputs"
        stage_root.mkdir(parents=True, exist_ok=True)
        staged_path = stage_root / f"{input_path.stem}-{uuid.uuid4().hex[:8]}{input_path.suffix}"
        shutil.copy2(input_path, staged_path)
        logger.info("Staged read-only input %s -> %s", input_path, staged_path)
        return staged_path

    def _prepare_open_plan(
        self,
        input_path: Path,
        *,
        run_auto_analysis: bool,
        session_id: Optional[str],
        alias: Optional[str],
        database_path: Path | str | None,
    ) -> tuple[Optional[_OpenSessionPlan], Optional[str]]:
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        with self._lock:
            resolved_input = input_path.resolve()
            existing_session_id = self._find_existing_session_id_locked(resolved_input, alias=alias)
            if existing_session_id is not None:
                return None, existing_session_id

            effective_session_id = session_id or self._generate_session_id()
            if effective_session_id in self._sessions:
                raise ValueError(f"Session already exists: {effective_session_id}")
            if alias:
                self._ensure_alias_available(alias)

        logger.info("Opening database: %s (session: %s)", input_path, effective_session_id)
        open_args = None
        database_path_obj: Optional[Path] = None
        target_path = str(input_path)
        if database_path:
            database_path_obj = Path(database_path).expanduser().resolve()
            database_path_obj.parent.mkdir(parents=True, exist_ok=True)
            working_input_path = input_path
            if database_path_obj.exists():
                target_path = str(database_path_obj)
            else:
                open_args = f"-o{database_path_obj}"
        else:
            working_input_path = self._prepare_working_input_path(input_path)
            target_path = str(working_input_path)

        return (
            _OpenSessionPlan(
                session_id=effective_session_id,
                input_path=input_path,
                working_input_path=working_input_path,
                database_path=database_path_obj,
                open_args=open_args,
                target_path=target_path,
                alias=alias,
                run_auto_analysis=run_auto_analysis,
            ),
            None,
        )

    def _find_existing_session_id_locked(self, resolved_input: Path, *, alias: Optional[str]) -> Optional[str]:
        for sid, session in self._sessions.items():
            if session.input_path.resolve() == resolved_input:
                logger.info("Binary already tracked in session: %s", sid)
                session.last_accessed = _utcnow()
                if alias:
                    self._ensure_alias_available(alias, current_session_id=sid)
                    session.alias = alias
                return sid
        return None

    def _validate_open_request(
        self,
        input_path: Path,
        *,
        session_id: Optional[str],
        alias: Optional[str],
    ) -> Optional[str]:
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        with self._lock:
            resolved_input = input_path.resolve()
            existing_session_id = self._find_existing_session_id_locked(resolved_input, alias=alias)
            if existing_session_id is not None:
                return existing_session_id

            effective_session_id = session_id or ""
            if effective_session_id and effective_session_id in self._sessions:
                raise ValueError(f"Session already exists: {effective_session_id}")
            if alias:
                self._ensure_alias_available(alias)
        return None

    def prepare_open_job(
        self,
        job_id: str,
    ) -> tuple[SessionOpenJob, Optional[_OpenSessionPlan]]:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise ValueError(f"Job not found: {job_id}")
            if job.status == "succeeded":
                return job, None
        plan, existing_session_id = self._prepare_open_plan(
            job.input_path,
            run_auto_analysis=job.run_auto_analysis,
            session_id=job.requested_session_id,
            alias=job.requested_alias,
            database_path=job.database_path,
        )
        if existing_session_id is not None:
            if job.context_id:
                self.bind_context(job.context_id, existing_session_id, activate=False)
            self.mark_job_succeeded(job_id, existing_session_id)
            return self.get_job(job_id), None
        assert plan is not None
        return self.get_job(job_id), plan

    def _execute_open_plan(self, plan: _OpenSessionPlan) -> IDASession:
        self._activate_database_path(
            plan.target_path,
            plan.run_auto_analysis,
            args=plan.open_args,
        )

        session = IDASession(
            session_id=plan.session_id,
            input_path=plan.input_path,
            working_input_path=plan.working_input_path,
            database_path=plan.database_path,
            open_args=plan.open_args,
            alias=plan.alias,
            is_analyzing=False,
        )
        with self._lock:
            self._sessions[plan.session_id] = session
            self._active_session_id = plan.session_id

        logger.info("Session created: %s for %s", plan.session_id, plan.input_path.name)
        return session



_session_manager: Optional[IDASessionManager] = None


def get_session_manager() -> IDASessionManager:
    global _session_manager
    if _session_manager is None:
        _session_manager = IDASessionManager()
    return _session_manager
