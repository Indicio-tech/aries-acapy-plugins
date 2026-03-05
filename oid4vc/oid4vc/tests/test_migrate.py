"""Tests for oid4vc/migrate.py."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from acapy_agent.storage.base import BaseStorage
from acapy_agent.utils.testing import create_test_profile

from oid4vc.migrate import (
    _UNVERSIONED,
    _VERSION_RECORD_TYPE,
    _fmt,
    _get_db_version,
    _parse,
    _set_db_version,
    run_migrations,
)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
async def profile():
    yield await create_test_profile()


# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------


class TestVersionHelpers:
    def test_parse_and_fmt_roundtrip(self):
        assert _fmt(_parse("1.2.3")) == "1.2.3"
        assert _parse("0.0.0") == (0, 0, 0)
        assert _parse("0.1.0") == (0, 1, 0)

    def test_unversioned_is_zero(self):
        assert _UNVERSIONED == (0, 0, 0)

    async def test_get_db_version_returns_unversioned_when_no_record(self, profile):
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            assert await _get_db_version(storage) == _UNVERSIONED

    async def test_set_and_get_db_version(self, profile):
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            await _set_db_version(storage, (0, 1, 0))
            assert await _get_db_version(storage) == (0, 1, 0)

    async def test_set_db_version_updates_in_place(self, profile):
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            await _set_db_version(storage, (0, 1, 0))
            await _set_db_version(storage, (0, 2, 0))
            assert await _get_db_version(storage) == (0, 2, 0)
            records = await storage.find_all_records(_VERSION_RECORD_TYPE)
            assert len(records) == 1


# ---------------------------------------------------------------------------
# run_migrations — routing and version bookkeeping
# ---------------------------------------------------------------------------


class TestRunMigrations:
    async def test_no_op_when_no_steps(self, profile):
        """With _STEPS empty, run_migrations is always a no-op."""
        with patch("oid4vc.migrate._pkg_version", return_value="0.1.0"):
            await run_migrations(profile)
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            # No steps → DB version never advances from _UNVERSIONED
            assert await _get_db_version(storage) == _UNVERSIONED

    async def test_no_op_when_versions_match(self, profile):
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            await _set_db_version(storage, _parse("0.1.0"))
        with patch("oid4vc.migrate._pkg_version", return_value="0.1.0"):
            await run_migrations(profile)
        async with profile.session() as session:
            storage = session.inject(BaseStorage)
            assert await _get_db_version(storage) == (0, 1, 0)
