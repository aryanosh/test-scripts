"""Rolling-Window Rate Limiter for Strix Traffic-Control Gateway.

Enforces a strict global rolling-window limit of 5 HTTP requests per 60 seconds
across all concurrent agent flows and connections. Queues requests when the limit
is reached, ensuring no more than 5 requests are admitted in any rolling 60-second window.

Thread-safe, async-safe, and backed by a durable SQLite database to preserve rate limits
across process restarts and prevent concurrent race conditions.
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
import tempfile
import threading
import time
from typing import Callable, Coroutine, List, Optional, Tuple


class RateLimitError(Exception):
    """Base exception for rate limiting errors."""


class RateLimitTimeoutError(RateLimitError):
    """Raised when queue wait time exceeds maximum permitted timeout."""


class ConfigurationError(RateLimitError):
    """Raised when rate limiter configuration parameters are invalid."""


class RateLimitPersistenceError(RateLimitError):
    """Raised when persistent storage encounters an error or corruption."""


class ClockRollbackError(RateLimitPersistenceError):
    """Raised when system clock rollback is detected."""


class RollingWindowLimiter:
    """Thread-safe, async-safe, SQLite-backed rolling-window rate limiter with FIFO queuing.

    Guarantees that across any rolling interval of `window_seconds`, at most
    `max_requests` are admitted. Requests arriving when the window is full
    are queued until the oldest recorded admission timestamp in the window
    falls outside the rolling interval. State is persisted in SQLite to survive restarts.
    """

    def __init__(
        self,
        max_requests: int = 5,
        window_seconds: float = 60.0,
        db_path: Optional[str] = None,
        time_func: Optional[Callable[[], float]] = None,
        sleep_func: Optional[Callable[[float], None]] = None,
        async_sleep_func: Optional[Callable[[float], Coroutine]] = None,
        safety_margin: float = 0.001,
    ) -> None:
        """Initialize the rolling-window rate limiter.

        Args:
            max_requests: Maximum number of requests allowed in the rolling window.
            window_seconds: Duration of the rolling window in seconds.
            db_path: Path to SQLite database file. If None, uses GATEWAY_DB_PATH
                environment variable or an isolated temporary database file.
            time_func: Time provider returning seconds (defaults to time.time).
            sleep_func: Synchronous sleep provider (defaults to time.sleep).
            async_sleep_func: Asynchronous sleep provider (defaults to asyncio.sleep).
            safety_margin: Millisecond safety delta added to wait times to prevent
                floating-point boundary collisions.

        Raises:
            ConfigurationError: If max_requests or window_seconds is non-positive.
            RateLimitPersistenceError: If the SQLite database cannot be initialized.
        """
        if max_requests <= 0:
            raise ConfigurationError(
                f"max_requests must be a positive integer, got {max_requests}"
            )
        if window_seconds <= 0:
            raise ConfigurationError(
                f"window_seconds must be a positive number, got {window_seconds}"
            )
        if safety_margin < 0:
            raise ConfigurationError(
                f"safety_margin cannot be negative, got {safety_margin}"
            )

        self._max_requests: int = max_requests
        self._window_seconds: float = float(window_seconds)
        self._safety_margin: float = float(safety_margin)

        self._time_func: Callable[[], float] = time_func or time.time
        self._sleep_func: Callable[[float], None] = sleep_func or time.sleep
        self._async_sleep_func: Callable[[float], Coroutine] = (
            async_sleep_func or asyncio.sleep
        )

        # Database configuration
        self._is_temp_db: bool = False
        if db_path is not None:
            self._db_path: str = db_path
        else:
            env_path = os.environ.get("GATEWAY_DB_PATH")
            if env_path:
                self._db_path = env_path
            else:
                fd, path = tempfile.mkstemp(prefix="gateway_limiter_", suffix=".db")
                os.close(fd)
                self._db_path = path
                self._is_temp_db = True

        # Synchronization primitives
        self._state_lock: threading.RLock = threading.RLock()
        self._thread_queue_lock: threading.Lock = threading.Lock()
        self._async_lock: Optional[asyncio.Lock] = None

        # Telemetry & metrics
        self._queue_depth: int = 0
        self._total_admitted: int = 0

        # SQLite connection
        self._db_conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _init_db(self) -> None:
        """Initializes the SQLite schema and verifies database integrity."""
        try:
            with self._state_lock:
                conn = self._get_connection()
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS admissions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        admitted_at REAL NOT NULL
                    );
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_admissions_time ON admissions(admitted_at);"
                )
                # Verify integrity
                cur = conn.execute("PRAGMA quick_check;")
                result = cur.fetchone()
                if not result or result[0] != "ok":
                    raise RateLimitPersistenceError(
                        f"SQLite integrity check failed on {self._db_path}: {result}"
                    )
        except (sqlite3.DatabaseError, sqlite3.OperationalError) as err:
            raise RateLimitPersistenceError(
                f"Failed to initialize SQLite rate limit store at {self._db_path}: {err}"
            ) from err

    def _get_connection(self) -> sqlite3.Connection:
        """Returns or opens the SQLite database connection under state lock."""
        if self._db_conn is None:
            self._db_conn = sqlite3.connect(
                self._db_path,
                timeout=30.0,
                check_same_thread=False,
                isolation_level=None,  # Explicit transaction control
            )
            # Enable WAL mode for high concurrency
            try:
                self._db_conn.execute("PRAGMA journal_mode=WAL;")
                self._db_conn.execute("PRAGMA synchronous=NORMAL;")
            except sqlite3.DatabaseError:
                pass
        return self._db_conn

    def _get_async_lock(self) -> asyncio.Lock:
        """Lazily acquires or creates the asyncio.Lock with thread-safe double-checked locking."""
        if self._async_lock is None:
            with self._state_lock:
                if self._async_lock is None:
                    self._async_lock = asyncio.Lock()
        return self._async_lock

    @property
    def max_requests(self) -> int:
        """Maximum requests permitted per window."""
        return self._max_requests

    @property
    def window_seconds(self) -> float:
        """Window duration in seconds."""
        return self._window_seconds

    @property
    def db_path(self) -> str:
        """Path to SQLite database backing this limiter."""
        return self._db_path

    @property
    def queue_depth(self) -> int:
        """Number of requests currently queued and waiting for admission."""
        with self._state_lock:
            return self._queue_depth

    @property
    def window_count(self) -> int:
        """Number of active admissions currently within the rolling window."""
        with self._state_lock:
            now = self._time_func()
            try:
                conn = self._get_connection()
                cutoff = now - self._window_seconds
                cur = conn.execute(
                    "SELECT COUNT(*) FROM admissions WHERE admitted_at > ?;",
                    (cutoff,),
                )
                row = cur.fetchone()
                return int(row[0]) if row else 0
            except sqlite3.DatabaseError as err:
                raise RateLimitPersistenceError(
                    f"Failed to query window count from {self._db_path}: {err}"
                ) from err

    @property
    def total_admitted(self) -> int:
        """Lifetime count of requests admitted by this limiter instance."""
        with self._state_lock:
            return self._total_admitted

    def get_history(self) -> List[float]:
        """Returns a list of current admission timestamps within the rolling window."""
        with self._state_lock:
            now = self._time_func()
            try:
                conn = self._get_connection()
                cutoff = now - self._window_seconds
                cur = conn.execute(
                    "SELECT admitted_at FROM admissions WHERE admitted_at > ? ORDER BY admitted_at ASC;",
                    (cutoff,),
                )
                return [row[0] for row in cur.fetchall()]
            except sqlite3.DatabaseError as err:
                raise RateLimitPersistenceError(
                    f"Failed to read history from {self._db_path}: {err}"
                ) from err

    def reset(self) -> None:
        """Resets admission history and queue counters (primarily for test harness)."""
        with self._state_lock:
            try:
                conn = self._get_connection()
                conn.execute("DELETE FROM admissions;")
                self._queue_depth = 0
                self._total_admitted = 0
            except sqlite3.DatabaseError as err:
                raise RateLimitPersistenceError(
                    f"Failed to reset admissions table: {err}"
                ) from err

    def _admit_transactional(self, now: float) -> Tuple[bool, float]:
        """Atomically evaluates rolling-window limits and inserts an admission.

        Guarantees:
        - Detects system clock rollback and raises ClockRollbackError (fails closed).
        - Traps database corruption and raises RateLimitPersistenceError (fails closed).
        - Executes with exclusive write locking (BEGIN IMMEDIATE).

        Returns:
            Tuple[bool, float]: (admitted, wait_time)
            If admitted is True, wait_time is 0.0.
            If admitted is False, wait_time is the seconds until the oldest admission expires.
        """
        with self._state_lock:
            conn = self._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE;")

                # 1. Clock rollback check
                cur = conn.execute("SELECT MAX(admitted_at) FROM admissions;")
                row = cur.fetchone()
                if row and row[0] is not None:
                    max_recorded = float(row[0])
                    if now < max_recorded - self._safety_margin:
                        conn.execute("ROLLBACK;")
                        raise ClockRollbackError(
                            f"Clock rollback detected: current time {now:.3f} < latest admission {max_recorded:.3f}"
                        )

                # 2. Evict expired entries
                cutoff = now - self._window_seconds
                conn.execute("DELETE FROM admissions WHERE admitted_at <= ?;", (cutoff,))

                # 3. Check active count and oldest timestamp
                cur = conn.execute("SELECT COUNT(*), MIN(admitted_at) FROM admissions;")
                count_row = cur.fetchone()
                count = int(count_row[0]) if count_row else 0
                oldest = float(count_row[1]) if count_row and count_row[1] is not None else now

                if count < self._max_requests:
                    conn.execute("INSERT INTO admissions (admitted_at) VALUES (?);", (now,))
                    conn.execute("COMMIT;")
                    self._total_admitted += 1
                    return True, 0.0
                else:
                    conn.execute("COMMIT;")
                    wait_time = (oldest + self._window_seconds + self._safety_margin) - now
                    return False, max(0.001, wait_time)

            except (sqlite3.DatabaseError, sqlite3.OperationalError) as db_err:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:
                    pass
                raise RateLimitPersistenceError(
                    f"SQLite transaction failure in {self._db_path}: {db_err}"
                ) from db_err
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:
                    pass
                raise

    def acquire(self, timeout: Optional[float] = None) -> float:
        """Synchronously acquire permission to forward an HTTP request.

        If the rolling limit is reached, this call blocks in FIFO order until
        a slot becomes available in the persistent rolling window.

        Args:
            timeout: Optional maximum seconds to wait. If wait time exceeds
                timeout, RateLimitTimeoutError is raised (failing closed).

        Returns:
            float: Total seconds waited before admission (0.0 if admitted immediately).

        Raises:
            RateLimitTimeoutError: If waiting would exceed the specified timeout.
            RateLimitPersistenceError: If database persistence fails or is corrupted.
            ClockRollbackError: If system clock rollback is detected.
        """
        start_time = self._time_func()
        with self._state_lock:
            self._queue_depth += 1

        try:
            with self._thread_queue_lock:
                total_waited = 0.0
                while True:
                    now = self._time_func()
                    admitted, wait_time = self._admit_transactional(now)
                    if admitted:
                        return total_waited

                    if timeout is not None:
                        elapsed = self._time_func() - start_time
                        if elapsed + wait_time > timeout:
                            raise RateLimitTimeoutError(
                                f"Required wait time {wait_time:.3f}s exceeds timeout {timeout:.3f}s"
                            )

                    total_waited += wait_time
                    self._sleep_func(wait_time)
        finally:
            with self._state_lock:
                self._queue_depth -= 1

    async def acquire_async(self, timeout: Optional[float] = None) -> float:
        """Asynchronously acquire permission to forward an HTTP request.

        If the rolling limit is reached, this coroutine yields control back to
        the event loop and sleeps in FIFO order until a slot opens in the window.

        Args:
            timeout: Optional maximum seconds to wait before timing out.

        Returns:
            float: Total seconds waited before admission (0.0 if admitted immediately).

        Raises:
            RateLimitTimeoutError: If waiting would exceed the specified timeout.
            RateLimitPersistenceError: If database persistence fails or is corrupted.
            ClockRollbackError: If system clock rollback is detected.
        """
        start_time = self._time_func()
        with self._state_lock:
            self._queue_depth += 1

        try:
            lock = self._get_async_lock()
            async with lock:
                total_waited = 0.0
                while True:
                    now = self._time_func()
                    admitted, wait_time = self._admit_transactional(now)
                    if admitted:
                        return total_waited

                    if timeout is not None:
                        elapsed = self._time_func() - start_time
                        if elapsed + wait_time > timeout:
                            raise RateLimitTimeoutError(
                                f"Required wait time {wait_time:.3f}s exceeds timeout {timeout:.3f}s"
                            )

                    total_waited += wait_time
                    await self._async_sleep_func(wait_time)
        finally:
            with self._state_lock:
                self._queue_depth -= 1

    def close(self) -> None:
        """Closes the underlying database connection and removes temp files if needed."""
        with self._state_lock:
            if self._db_conn is not None:
                try:
                    self._db_conn.close()
                except Exception:
                    pass
                self._db_conn = None
            if self._is_temp_db and os.path.exists(self._db_path):
                try:
                    os.remove(self._db_path)
                except Exception:
                    pass

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
