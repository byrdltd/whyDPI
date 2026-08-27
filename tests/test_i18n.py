# Copyright (c) 2026 whyDPI Contributors
# SPDX-License-Identifier: MIT

"""Locale catalogs and lookup."""

from __future__ import annotations

from whydpi.i18n import detect_lang, reset_cache, t
from whydpi.strings import CATALOGS, DEFAULT_LANG, EN, SUPPORTED


def test_catalogs_have_identical_keys() -> None:
    keys = set(EN)
    assert set(CATALOGS[DEFAULT_LANG]) == keys
    for code, table in CATALOGS.items():
        missing = keys - set(table)
        extra = set(table) - keys
        assert not missing, f"{code} missing {sorted(missing)}"
        assert not extra, f"{code} extra {sorted(extra)}"
    assert tuple(sorted(SUPPORTED)) == tuple(sorted(CATALOGS))


def test_t_english_and_turkish(monkeypatch) -> None:
    monkeypatch.setenv("WHYDPI_LANG", "en")
    reset_cache()
    assert t("tray.notify.ready.title") == EN["tray.notify.ready.title"]
    assert "stopped" not in t("tray.notify.ready.body").lower()

    monkeypatch.setenv("WHYDPI_LANG", "tr")
    reset_cache()
    assert t("tray.menu.start") == CATALOGS["tr"]["tray.menu.start"]


def test_t_spanish_german_french_russian(monkeypatch) -> None:
    for code in ("de", "es", "fr", "ru"):
        monkeypatch.setenv("WHYDPI_LANG", code)
        reset_cache()
        assert t("tray.menu.quit") == CATALOGS[code]["tray.menu.quit"]
        assert t("tray.menu.about", version="1.1.0").count("1.1.0") == 1


def test_t_formats_version(monkeypatch) -> None:
    monkeypatch.setenv("WHYDPI_LANG", "en")
    reset_cache()
    assert t("tray.menu.about", version="1.1.0") == "About whyDPI v1.1.0"


def test_detect_lang_from_posix_env() -> None:
    assert detect_lang({"LANG": "tr_TR.UTF-8"}) == "tr"
    assert detect_lang({"LANG": "es_ES.UTF-8"}) == "es"
    assert detect_lang({"LANG": "de_DE.UTF-8"}) == "de"
    assert detect_lang({"LANG": "fr_FR.UTF-8"}) == "fr"
    assert detect_lang({"LANG": "ru_RU.UTF-8"}) == "ru"
    assert detect_lang({"LC_MESSAGES": "en_US.UTF-8"}) == "en"
    assert detect_lang({"LANG": "C"}) == "en"
    assert detect_lang({"WHYDPI_LANG": "es", "LANG": "en_US.UTF-8"}) == "es"


def test_missing_key_falls_back_to_key(monkeypatch) -> None:
    monkeypatch.setenv("WHYDPI_LANG", "en")
    reset_cache()
    assert t("does.not.exist") == "does.not.exist"
