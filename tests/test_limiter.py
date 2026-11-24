"""Unit tests for the RollingWindowLimiter.

Tests:
1. Rolling-window limits (<= 5 requests per 60s).
2. Sixth request waiting rather than being forwarded early.
3. FIFO queueing and sliding window expiration.
4. Concurrency with multi-threading and asyncio.
5. Strict rolling window invariant enforcement.
6. Fail-closed behavior on timeout or invalid configuration.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import List
import pytest

from gateway.limiter import (
    ConfigurationError,
    RateLimitError,
    RateLimitTimeoutError,
    RollingWindowLimiter,
)


class VirtualClock:
    """Simulated monotonic clock and sleep provider for precise, instantaneous testing."""

    def __init__(self, start_time: float = 1000.0) -> None:
        self.current_time: float = start_time
        self.sleep_calls: List[float] = []

    def time(self) -> float:
        return self.current_time

    def sleep(self, seconds: float) -> None:
        self.sleep_calls.append(seconds)
        self.current_time += seconds

    async def async_sleep(self, seconds: float) -> None:
        self.sleep_calls.append(seconds)
        self.current_time += seconds


class TestLimiterInitialization:
    """Verifies default parameters and configuration validation."""

    def test_default_initialization(self) -> None:
        limiter = RollingWindowLimiter()
        assert limiter.max_requests == 5
        assert limiter.window_seconds == 60.0
        assert limiter.queue_depth == 0
        assert limiter.window_count == 0
        assert limiter.total_admitted == 0
        assert limiter.get_history() == []

    def test_invalid_max_requests_fails_closed(self) -> None:
        with pytest.raises(ConfigurationError, match="max_requests must be a positive integer"):
            RollingWindowLimiter(max_requests=0)

        with pytest.raises(ConfigurationError, match="max_requests must be a positive integer"):
            RollingWindowLimiter(max_requests=-5)

    def test_invalid_window_seconds_fails_closed(self) -> None:
        with pytest.raises(ConfigurationError, match="window_seconds must be a positive number"):
            RollingWindowLimiter(window_seconds=0.0)

        with pytest.raises(ConfigurationError, match="window_seconds must be a positive number"):
            RollingWindowLimiter(window_seconds=-60.0)

    def test_invalid_safety_margin_fails_closed(self) -> None:
        with pytest.raises(ConfigurationError, match="safety_margin cannot be negative"):
            RollingWindowLimiter(safety_margin=-0.01)


class TestRollingWindowBehavior:
    """Verifies admissions, queuing, and rolling-window sliding mechanics."""

    def test_first_five_requests_admitted_immediately(self) -> None:
        clock = VirtualClock(100.0)
        limiter = RollingWindowLimiter(
            max_requests=5,
            window_seconds=60.0,
            time_func=clock.time,
            sleep_func=clock.sleep,
        )

        for i in range(5):
            wait_time = limiter.acquire()
            assert wait_time == 0.0, f"Request {i+1} should be admitted immediately"

        assert limiter.window_count == 5
        assert limiter.total_admitted == 5
        assert len(clock.sleep_calls) == 0

    def test_sixth_request_waits_rather_than_forwarded_early(self) -> None:
        """Requirement 3: Sixth request waits rather than being forwarded early."""
        clock = VirtualClock(100.0)
        limiter = RollingWindowLimiter(
            max_requests=5,
            window_seconds=60.0,
            time_func=clock.time,
            sleep_func=clock.sleep,
            safety_margin=0.001,
        )

        # Step 1: Send 5 requests at t=100.0
        for _ in range(5):
            limiter.acquire()

        # Step 2: 10 seconds later, 6th request arrives at t=110.0
        clock.current_time = 110.0

        # Before acquiring, window is full
        assert limiter.window_count == 5

        # Call acquire: must wait until oldest (t=100.0) expires at 100.0 + 60.0 = 160.0
        wait_time = limiter.acquire()

        # Expected wait: (100.0 + 60.0 + 0.001) - 110.0 = 50.001 seconds
        assert len(clock.sleep_calls) == 1
        assert pytest.approx(clock.sleep_calls[0], rel=1e-3) == 50.001
        assert pytest.approx(wait_time, rel=1e-3) == 50.001

        # Current time after sleep is now >= 160.0
        assert clock.current_time >= 160.0

        # The 6th request was admitted only after t=160.0, never forwarded early
        history = limiter.get_history()
        # All 5 requests from t=100.0 expired at t=160.0 and were evicted
        assert len(history) == 1
        assert history[0] >= 160.0

    def test_seventh_and_subsequent_requests_paced_strictly(self) -> None:
        """Verify multiple waiting requests maintain strict rolling-window pacing."""
        clock = VirtualClock(1000.0)
        limiter = RollingWindowLimiter(
            max_requests=5,
            window_seconds=60.0,
            time_func=clock.time,
            sleep_func=clock.sleep,
            safety_margin=0.001,
        )

        # 5 requests spread out across 40 seconds: t=1000, 1010, 1020, 1030, 1040
        for offset in (0, 10, 20, 30, 40):
            clock.current_time = 1000.0 + offset
            wait = limiter.acquire()
            assert wait == 0.0

        # Request 6 arrives at t=1045
        clock.current_time = 1045.0
        # Oldest is 1000.0. Expire is 1060.001. Wait = 15.001s
        wait_6 = limiter.acquire()
        assert pytest.approx(wait_6, rel=1e-3) == 15.001
        assert pytest.approx(clock.current_time, rel=1e-3) == 1060.001

        # Request 7 arrives immediately at t=1060.001
        # Now oldest in history is 1010.0! Expire is 1070.001.
        # Wait = (1010.0 + 60.0 + 0.001) - 1060.001 = 10.0s
        wait_7 = limiter.acquire()
        assert pytest.approx(wait_7, rel=1e-3) == 10.0
        assert pytest.approx(clock.current_time, rel=1e-3) == 1070.001

    def test_window_expiration_allows_immediate_admission_after_lapse(self) -> None:
        """Requests arriving after the 60s window has fully elapsed require 0 wait."""
        clock = VirtualClock(500.0)
        limiter = RollingWindowLimiter(
            max_requests=5,
            window_seconds=60.0,
            time_func=clock.time,
            sleep_func=clock.sleep,
        )

        # Saturate window at t=500
        for _ in range(5):
            limiter.acquire()

        # Advance time by 65 seconds (exceeding 60s window)
        clock.current_time = 565.0

        # Window count should have dropped to 0
        assert limiter.window_count == 0

        # Next request must be admitted immediately
        wait = limiter.acquire()
        assert wait == 0.0
        assert limiter.window_count == 1
        assert len(clock.sleep_calls) == 0

    def test_strict_rolling_window_invariant_over_arbitrary_traffic(self) -> None:
        """Mathematically verifies that across 30 rapid calls, no 60s window has > 5 requests."""
        clock = VirtualClock(0.0)
        limiter = RollingWindowLimiter(
            max_requests=5,
            window_seconds=60.0,
            time_func=clock.time,
            sleep_func=clock.sleep,
            safety_margin=0.001,
        )

        admitted_timestamps: List[float] = []

        # 30 requests submitted at 2-second intervals
        for req_idx in range(30):
            clock.current_time += 2.0
            limiter.acquire()
            admitted_timestamps.append(clock.current_time)

        # Check invariant: for EVERY admitted timestamp T, count of admissions in [T, T + 60.0] <= 5
        for t in admitted_timestamps:
            in_window = [ts for ts in admitted_timestamps if t <= ts <= t + 60.0]
            assert (
                len(in_window) <= 5
            ), f"Window invariant violated at t={t}: found {len(in_window)} requests in [t, t+60.0]: {in_window}"


class TestAsyncLimiter:
    """Verifies async coroutine queuing and safety."""

    def test_async_acquire_immediate_and_queued(self) -> None:
        async def _run() -> None:
            clock = VirtualClock(200.0)
            limiter = RollingWindowLimiter(
                max_requests=5,
                window_seconds=60.0,
                time_func=clock.time,
                async_sleep_func=clock.async_sleep,
                safety_margin=0.001,
            )

            # 5 immediate admissions
            for _ in range(5):
                wait = await limiter.acquire_async()
                assert wait == 0.0

            assert limiter.window_count == 5

            # 6th request arrives at t=215
            clock.current_time = 215.0
            wait_6 = await limiter.acquire_async()

            # Expected wait: (200 + 60 + 0.001) - 215 = 45.001s
            assert pytest.approx(wait_6, rel=1e-3) == 45.001
            assert len(clock.sleep_calls) == 1
            assert clock.current_time >= 260.0

        asyncio.run(_run())

    def test_async_concurrent_tasks_preserve_invariant(self) -> None:
        """Run 12 concurrent coroutines and assert that limit is never breached."""
        async def _run() -> None:
            # Use short real window for event-loop concurrency verification
            limiter = RollingWindowLimiter(
                max_requests=3,
                window_seconds=0.15,
                safety_margin=0.002,
            )

            timestamps: List[float] = []

            async def worker() -> None:
                await limiter.acquire_async()
                timestamps.append(time.monotonic())

            tasks = [asyncio.create_task(worker()) for _ in range(9)]
            await asyncio.gather(*tasks)

            assert len(timestamps) == 9

            # Verify no rolling window of 0.15s contained > 3 admissions
            for t in timestamps:
                count = sum(1 for ts in timestamps if t <= ts < t + 0.149)
                assert count <= 3, f"Async invariant breached: {count} admissions in [t, t+0.149s]"

        asyncio.run(_run())


class TestConcurrencyAndThreads:
    """Verifies thread-safety under concurrent load."""

    def test_multithreaded_concurrent_requests_preserve_rolling_invariant(self) -> None:
        # 4 requests per 0.20s window
        limiter = RollingWindowLimiter(
            max_requests=4,
            window_seconds=0.20,
            safety_margin=0.002,
        )

        admission_times: List[float] = []
        lock = threading.Lock()

        def client_worker() -> None:
            limiter.acquire()
            with lock:
                admission_times.append(time.monotonic())

        threads = [threading.Thread(target=client_worker) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)
            assert not t.is_alive(), "Worker thread deadlocked or timed out"

        assert len(admission_times) == 12

        # Verify no 0.20s window ever had > 4 admissions
        for t in admission_times:
            count = sum(1 for ts in admission_times if t <= ts < t + 0.198)
            assert count <= 4, f"Thread concurrency invariant breached: {count} admissions in [t, t+0.198s]"


class TestFailureModesAndFailClosed:
    """Verifies fail-closed behavior on timeout or state corruption."""

    def test_timeout_raises_timeout_error_and_fails_closed(self) -> None:
        clock = VirtualClock(10.0)
        limiter = RollingWindowLimiter(
            max_requests=5,
            window_seconds=60.0,
            time_func=clock.time,
            sleep_func=clock.sleep,
        )

        # Saturate at t=10
        for _ in range(5):
            limiter.acquire()

        # Request at t=15 with timeout of 10s (needs 55s)
        clock.current_time = 15.0
        with pytest.raises(RateLimitTimeoutError, match="exceeds timeout"):
            limiter.acquire(timeout=10.0)

        # Queue depth must be restored to 0 after failure
        assert limiter.queue_depth == 0

    def test_async_timeout_fails_closed(self) -> None:
        async def _run() -> None:
            clock = VirtualClock(10.0)
            limiter = RollingWindowLimiter(
                max_requests=5,
                window_seconds=60.0,
                time_func=clock.time,
                async_sleep_func=clock.async_sleep,
            )

            for _ in range(5):
                await limiter.acquire_async()

            clock.current_time = 15.0
            with pytest.raises(RateLimitTimeoutError):
                await limiter.acquire_async(timeout=5.0)

            assert limiter.queue_depth == 0

        asyncio.run(_run())

    def test_reset_clears_history_and_counters(self) -> None:
        limiter = RollingWindowLimiter(max_requests=5, window_seconds=60.0)
        limiter.acquire()
        limiter.acquire()
        assert limiter.window_count == 2
        assert limiter.total_admitted == 2

        limiter.reset()
        assert limiter.window_count == 0
        assert limiter.total_admitted == 0
        assert limiter.queue_depth == 0


class TestSqlitePersistenceAndRollback:
    """Verifies SQLite durability across restarts, transactional concurrency, and rollback defense."""

    def test_persistence_across_process_restarts(self, tmp_path: Any) -> None:
        """Requirement 2: Preserve the global 5 req/60s limit across process restarts."""
        db_file = str(tmp_path / "persistent_limiter.db")
        clock = VirtualClock(100.0)

        # Process 1: Admits 5 requests at t=100.0 and closes
        p1 = RollingWindowLimiter(
            max_requests=5,
            window_seconds=60.0,
            db_path=db_file,
            time_func=clock.time,
            sleep_func=clock.sleep,
        )
        for _ in range(5):
            assert p1.acquire() == 0.0
        assert p1.window_count == 5
        p1.close()

        # Process 2: Starts up 10 seconds later at t=110.0 using the same database file
        clock.current_time = 110.0
        p2 = RollingWindowLimiter(
            max_requests=5,
            window_seconds=60.0,
            db_path=db_file,
            time_func=clock.time,
            sleep_func=clock.sleep,
        )

        # Process 2 must recognize all 5 active admissions from Process 1
        assert p2.window_count == 5

        # Attempt to acquire must wait ~50s until oldest expires at t=160.0
        wait_time = p2.acquire()
        assert pytest.approx(wait_time, rel=1e-3) == 50.001
        assert clock.current_time >= 160.0
        p2.close()

    def test_clock_rollback_detected_and_fails_closed(self, tmp_path: Any) -> None:
        """Requirement 2: Handle clock rollback by failing closed."""
        db_file = str(tmp_path / "rollback_limiter.db")
        clock = VirtualClock(500.0)

        limiter = RollingWindowLimiter(
            max_requests=5,
            window_seconds=60.0,
            db_path=db_file,
            time_func=clock.time,
            sleep_func=clock.sleep,
        )

        # Admit request at t=500.0
        limiter.acquire()

        # System clock is rolled back to t=400.0
        clock.current_time = 400.0

        from gateway.limiter import ClockRollbackError

        with pytest.raises(ClockRollbackError, match="Clock rollback detected"):
            limiter.acquire()

        limiter.close()

    def test_database_corruption_fails_closed(self, tmp_path: Any) -> None:
        """Requirement 2: Database corruption fails closed with RateLimitPersistenceError."""
        db_file = str(tmp_path / "corrupt_limiter.db")

        # Create valid DB first
        limiter = RollingWindowLimiter(db_path=db_file)
        limiter.acquire()
        limiter.close()

        # Corrupt DB file by overwriting with invalid junk bytes
        with open(db_file, "wb") as f:
            f.write(b"NOT A SQLITE DATABASE CORRUPT DATA" * 10)

        from gateway.limiter import RateLimitPersistenceError

        with pytest.raises(RateLimitPersistenceError):
            RollingWindowLimiter(db_path=db_file)


class TestAsyncLockInitialization:
    """Requirement 4: Synchronized lazy initialization of async lock under concurrency."""

    def test_concurrent_initialization_produces_identical_lock_instance(self) -> None:
        limiter = RollingWindowLimiter()
        assert limiter._async_lock is None

        locks: List[Any] = []
        threads: List[threading.Thread] = []

        def worker() -> None:
            # Race to initialize _async_lock
            l = limiter._get_async_lock()
            locks.append(id(l))

        for _ in range(15):
            t = threading.Thread(target=worker)
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(locks) == 15
        # Every single thread must have received the exact same lock instance
        assert len(set(locks)) == 1, "Race condition: multiple asyncio.Lock instances created!"
        assert limiter.get_history() == []
