# Copyright (c) 2025 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Unit tests for the Windows GitHub-release updater (no network)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from whydpi.ui import update as upd


def test_parse_version_and_newer() -> None:
    assert upd.parse_version("v1.0.2") == (1, 0, 2)
    assert upd.parse_version("1.0.10") == (1, 0, 10)
    assert upd.is_newer("1.0.3", "1.0.2") is True
    assert upd.is_newer("v1.0.2", "1.0.2") is False
    assert upd.is_newer("1.0.2", "1.0.3") is False


def test_detect_channel_scoop_inno_portable() -> None:
    env = {"ProgramFiles": r"C:\Program Files"}
    assert (
        upd.detect_channel(
            r"C:\Users\x\scoop\apps\whydpi\current\whydpi-tray.exe", env
        )
        == "scoop"
    )
    assert (
        upd.detect_channel(
            r"C:\Program Files\whyDPI\whydpi-tray.exe", env
        )
        == "inno"
    )
    assert upd.detect_channel(r"D:\portable\whydpi-tray.exe", env) == "portable"


def test_select_setup_asset_prefers_versioned_name() -> None:
    assets = [
        {
            "name": "whydpi-tray-1.0.3-win64.zip",
            "browser_download_url": "https://example/zip",
        },
        {
            "name": "whydpi-1.0.3-setup.exe",
            "browser_download_url": "https://example/setup",
        },
        {
            "name": "SHA256SUMS.txt",
            "browser_download_url": "https://example/sums",
        },
    ]
    url, name, sums = upd.select_setup_asset(assets, "1.0.3")
    assert name == "whydpi-1.0.3-setup.exe"
    assert url == "https://example/setup"
    assert sums == "https://example/sums"


def test_parse_sha256sums() -> None:
    text = (
        "aabbcc  whydpi-1.0.3-setup.exe\n"
        "ddeeff *whydpi-tray-1.0.3-win64.zip\n"
    )
    assert (
        upd.parse_sha256sums(text, "whydpi-1.0.3-setup.exe") == "aabbcc"
    )
    assert upd.parse_sha256sums(text, "missing.exe") is None


def _payload(version: str = "1.0.3") -> dict:
    return {
        "tag_name": f"v{version}",
        "html_url": f"https://github.com/byrdltd/whyDPI/releases/tag/v{version}",
        "assets": [
            {
                "name": f"whydpi-{version}-setup.exe",
                "browser_download_url": f"https://example/{version}/setup.exe",
            },
            {
                "name": "SHA256SUMS.txt",
                "browser_download_url": f"https://example/{version}/SHA256SUMS.txt",
            },
        ],
    }


def test_check_for_update_newer_and_cache(tmp_path: Path) -> None:
    cache = tmp_path / "update-check.json"
    hits = {"n": 0}

    def fetcher(url: str) -> bytes:
        hits["n"] += 1
        assert "releases/latest" in url
        return json.dumps(_payload("1.0.3")).encode()

    info = upd.check_for_update(
        "1.0.2", now=1_000.0, fetcher=fetcher, cache_file=cache
    )
    assert info is not None
    assert info.version == "1.0.3"
    assert hits["n"] == 1

    # Fresh cache, same current version: no second fetch.
    again = upd.check_for_update(
        "1.0.2", now=1_000.0 + 60, fetcher=fetcher, cache_file=cache
    )
    assert again is not None
    assert again.version == "1.0.3"
    assert hits["n"] == 1


def test_check_for_update_not_newer(tmp_path: Path) -> None:
    cache = tmp_path / "update-check.json"

    def fetcher(url: str) -> bytes:  # noqa: ARG001
        return json.dumps(_payload("1.0.2")).encode()

    assert (
        upd.check_for_update(
            "1.0.2", now=1.0, fetcher=fetcher, cache_file=cache
        )
        is None
    )


def test_check_for_update_force_refetch(tmp_path: Path) -> None:
    cache = tmp_path / "update-check.json"
    hits = {"n": 0}

    def fetcher(url: str) -> bytes:  # noqa: ARG001
        hits["n"] += 1
        return json.dumps(_payload("1.0.4")).encode()

    upd.check_for_update(
        "1.0.2", now=1.0, fetcher=fetcher, cache_file=cache
    )
    upd.check_for_update(
        "1.0.2", now=2.0, fetcher=fetcher, cache_file=cache, force=True
    )
    assert hits["n"] == 2


def test_check_for_update_network_error(tmp_path: Path) -> None:
    def fetcher(url: str) -> bytes:  # noqa: ARG001
        raise OSError("offline")

    assert (
        upd.check_for_update(
            "1.0.2",
            now=1.0,
            fetcher=fetcher,
            cache_file=tmp_path / "c.json",
        )
        is None
    )


def test_download_setup_verifies_hash(tmp_path: Path) -> None:
    blob = b"installer-bytes"
    digest = __import__("hashlib").sha256(blob).hexdigest()
    info = upd.UpdateInfo(
        version="1.0.3",
        tag="v1.0.3",
        html_url="https://example/rel",
        setup_url="https://example/setup.exe",
        setup_name="whydpi-1.0.3-setup.exe",
        sha256sums_url="https://example/SHA256SUMS.txt",
    )

    def fetcher(url: str) -> bytes:
        if url.endswith("setup.exe"):
            return blob
        return f"{digest}  whydpi-1.0.3-setup.exe\n".encode()

    dest = upd.download_setup(info, tmp_path, fetcher=fetcher)
    assert dest.read_bytes() == blob


def test_download_setup_hash_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WHYDPI_LANG", "en")
    from whydpi.i18n import reset_cache

    reset_cache()
    info = upd.UpdateInfo(
        version="1.0.3",
        tag="v1.0.3",
        html_url="https://example/rel",
        setup_url="https://example/setup.exe",
        setup_name="whydpi-1.0.3-setup.exe",
        sha256sums_url="https://example/SHA256SUMS.txt",
    )

    def fetcher(url: str) -> bytes:
        if url.endswith("setup.exe"):
            return b"nope"
        return (("00" * 32) + "  whydpi-1.0.3-setup.exe\n").encode()

    with pytest.raises(RuntimeError, match="hash mismatch"):
        upd.download_setup(info, tmp_path, fetcher=fetcher)
    assert not (tmp_path / info.setup_name).exists()
