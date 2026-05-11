import sys
import pathlib
import logging

# ensure project root is on sys.path so tests can import
sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

import pytest
import pow_rsa_xunf


def test_pow_calculate_success_low_difficulty():
    nonce, h, elapsed = pow_rsa_xunf.pow_calculate("unittest", 1, max_nonce=1000000)
    assert isinstance(nonce, int)
    assert h.startswith("0")
    assert elapsed >= 0


def test_pow_calculate_max_nonce_triggers_and_logs(caplog):
    caplog.set_level(logging.WARNING)
    nonce, h, elapsed = pow_rsa_xunf.pow_calculate("unittest", 64, max_nonce=5, progress_interval=1)
    assert nonce is None
    assert elapsed >= 0
    assert any("max_nonce" in record.message or "达到 max_nonce" in record.message for record in caplog.records)


def test_pow_calculate_timeout_logging(monkeypatch, caplog):
    # monkeypatch time so the loop will trigger timeout quickly
    calls = {"n": 0}

    def fake_time():
        calls["n"] += 1
        return float(calls["n"])  # increases each call

    monkeypatch.setattr('pow_rsa_xunf.time.time', fake_time)
    caplog.set_level(logging.WARNING)
    nonce, h, elapsed = pow_rsa_xunf.pow_calculate("unittest", 64, timeout=0.5, progress_interval=1)
    assert nonce is None
    assert any("timeout" in record.message or "达到 timeout" in record.message for record in caplog.records)


def test_pow_calculate_timeout_zero_immediate():
    # timeout=0 should immediately return without doing work
    nonce, h, elapsed = pow_rsa_xunf.pow_calculate("unittest", 1, timeout=0)
    assert nonce is None
    assert h is None
    assert elapsed == 0.0
