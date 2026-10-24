"""Shared test setup. pytest loads this automatically before the tests."""

import pytest

from debugger import registry, spec


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    """Keep tests independent of local spec files, key files and registry settings."""
    monkeypatch.setattr(spec, "_specs", {})
    monkeypatch.setattr(registry, "_store", None)
    for name in ("ONDC_KEYS", "ONDC_REGISTRY", "ONDC_SUBSCRIBER_ID", "ONDC_UNIQUE_KEY_ID", "ONDC_PRIVATE_KEY"):
        monkeypatch.delenv(name, raising=False)  # signature checks off unless a test turns them on
