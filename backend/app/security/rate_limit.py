import time
import threading
from collections import defaultdict

from app.config import settings


class RateLimiter:
    """Simple in-memory sliding-window rate limiter keyed by client IP."""

    def __init__(self, max_requests: int | None = None, window: int | None = None):
        self.max_requests = max_requests or settings.RATE_LIMIT_MAX
        self.window = window or settings.RATE_LIMIT_WINDOW_SECONDS
        self._events: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def allow(self, key: str, max_requests: int | None = None) -> bool:
        limit = max_requests or self.max_requests
        now = time.monotonic()
        with self._lock:
            events = self._events[key]
            cutoff = now - self.window
            self._events[key] = [e for e in events if e > cutoff]
            if len(self._events[key]) >= limit:
                return False
            self._events[key].append(now)
            return True


class KillSwitch:
    """Global emergency stop. When armed, all active operations are blocked."""

    def __init__(self) -> None:
        self._armed = False
        self._lock = threading.Lock()

    def arm(self) -> None:
        with self._lock:
            self._armed = True

    def disarm(self) -> None:
        with self._lock:
            self._armed = False

    @property
    def is_armed(self) -> bool:
        with self._lock:
            return self._armed

    def check(self) -> None:
        """Raise if the kill switch is armed."""
        if self._armed:
            raise RuntimeError("GLOBAL KILL SWITCH ARMING: all active operations are blocked.")


rate_limiter = RateLimiter()
kill_switch = KillSwitch()