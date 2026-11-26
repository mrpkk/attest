"""Описание в реестре MCP — то, что видят каталоги; /scan должен быть в нём назван.

26.11.2026: каталоги (mcp.so, glama, mcpi.app, midi.mocopo.ai) уже индексируются и ведут на
`/mcp`, но в описании из `server.json` не было бесплатного скана — каталог показывал только
проверку артефактов. Поле ограничено 100 символами, поэтому формулировка проверяется тестом.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _server() -> dict:
    return json.loads((ROOT / "server.json").read_text(encoding="utf-8"))


def test_registry_description_fits_and_names_the_scan():
    desc = _server()["description"]
    assert len(desc) <= 100, f"{len(desc)} символов — реестр отклонит по лимиту"
    low = desc.lower()
    assert "scan" in low and "mcp" in low, desc
    assert "verify" in low, "проверка артефактов — вторая половина продукта, её нельзя потерять"


def test_llms_and_readme_use_the_same_query_phrase():
    llms = (ROOT / "llms.txt").read_text(encoding="utf-8").lower()
    readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
    for doc, name in ((llms, "llms.txt"), (readme, "README.md")):
        assert "mcp server scan" in doc, f"{name}: запрос должен быть назван той же формулировкой"


def test_sitemap_has_scan_and_store():
    from attest.service import _sitemap

    sitemap = _sitemap()
    for page in ("/scan", "/store", "/docs/scan"):
        assert f"<loc>https://attest.rta.lat{page}</loc>" in sitemap, page
