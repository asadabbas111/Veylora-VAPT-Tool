import threading

from app.security.rate_limit import RateLimiter


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
            raise RuntimeError("GLOBAL KILL SWITCH ARMED: all active operations are blocked.")


rate_limiter = RateLimiter()
kill_switch = KillSwitch()