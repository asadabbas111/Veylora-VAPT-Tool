"""Unit tests for security primitives: rate limiting, passwords, kill switch, scanner selection."""
import pytest

from app.security.kill_switch import KillSwitch
from app.security.passwords import hash_password, verify_password
from app.security.rate_limit import RateLimiter
from app.scanners.engine import scan_engine


def test_rate_limiter_allows_until_budget():
    rl = RateLimiter(max_requests=3, window=60)
    for _ in range(3):
        assert rl.allow("ip:1") is True
    assert rl.allow("ip:1") is False
    assert rl.allow("ip:2") is True  # different key unaffected


def test_rate_limiter_window_expiry():
    rl = RateLimiter(max_requests=1, window=1)
    assert rl.allow("k") is True
    assert rl.allow("k") is False
    import time

    time.sleep(1.1)
    assert rl.allow("k") is True


def test_password_roundtrip():
    h = hash_password("S3cure!Pass")
    assert h != "S3cure!Pass"
    assert verify_password("S3cure!Pass", h) is True
    assert verify_password("wrong", h) is False


def test_verify_password_rejects_garbage_hash():
    assert verify_password("x", "not-a-bcrypt-hash").__class__ is bool
    assert verify_password("x", "not-a-bcrypt-hash") is False


def test_kill_switch_blocks():
    ks = KillSwitch()
    ks.check()  # no-op when disarmed
    ks.arm()
    with pytest.raises(RuntimeError):
        ks.check()
    assert ks.is_armed is True
    ks.disarm()
    ks.check()


def test_scan_engine_selects_only_available_adapters():
    available = scan_engine.available_adapters()
    assert "simulated-lab" in available  # lab mode bundles the simulator
    for name in available:
        ok, _ = scan_engine.adapters[name].validate_configuration()
        assert ok is True


def test_scan_engine_arm_kill_switch_blocks_scan():
    from app.security.kill_switch import kill_switch as global_ks

    global_ks.arm()
    try:
        with pytest.raises(RuntimeError):
            scan_engine.scan([])
    finally:
        global_ks.disarm()