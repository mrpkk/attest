"""S8: две реализации на одних байтах и офлайн-страница.

Гейт: Python и JS дают одинаковый вердикт на каждом векторе; страница работает
без сети и весит меньше 100 КБ.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from attest.receipt import jcs, verify

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "conformance" / "receipt-vectors.json"
PAGE = ROOT / "attest" / "web" / "offline.html"


def load():
    return json.loads(VECTORS.read_text(encoding="utf-8"))


def test_vectors_exist_and_are_readable():
    data = load()
    assert len(data["vectors"]) >= 10
    assert data["public_key"]


@pytest.mark.parametrize("vector", load()["vectors"], ids=lambda v: v["name"])
def test_python_agrees_with_every_vector(vector):
    data = load()
    import base64
    public_key = base64.b64decode(data["public_key"])
    result = verify.verify_receipt(vector["text"].encode(), public_key)
    assert result.ok is vector["expect_ok"], f"{vector['name']}: {result.why()}"


@pytest.mark.skipif(shutil.which("node") is None, reason="node не установлен")
def test_javascript_agrees_with_the_same_vectors():
    """Вторая реализация обязана сойтись на тех же байтах — иначе формат описан неоднозначно."""
    run = ROOT / "conformance" / "run-js.mjs"
    proc = subprocess.run(["node", str(run), str(VECTORS)], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "согласны" in proc.stdout


def test_offline_page_has_no_network_calls():
    html = PAGE.read_text(encoding="utf-8")
    for marker in ("fetch(", "XMLHttpRequest", "import(", "<link rel=\"stylesheet\""):
        assert marker not in html, f"страница не должна содержать {marker}"
    assert "https://" not in html.replace("https://www.w3.org", "")


def test_offline_page_is_small():
    size = PAGE.stat().st_size
    assert size < 100_000, f"{size} байт — предел 100 КБ"


def test_offline_page_contains_the_verifier():
    html = PAGE.read_text(encoding="utf-8")
    assert "NOA-Receipt-v0.1-sig:" in html
    assert "chain.hash does not match the recomputed hash" in html


def test_offline_page_names_the_browser_limitation():
    """Отсутствие Ed25519 в браузере должно быть названо, а не проглочено."""
    html = PAGE.read_text(encoding="utf-8")
    assert "не умеет Ed25519" in html
    assert "это ограничение браузера, а не приговор квитанции" in html


def test_vectors_are_public_domain():
    licence = ROOT / "conformance" / "LICENSE"
    assert licence.exists()
    text = licence.read_text(encoding="utf-8")
    assert "CC0 1.0" in text and "public domain" in text.lower()


def test_docs_page_speaks_three_languages():
    from attest.docs_page import DOCS_HTML
    for marker in ("हिन्दी", "Русский", "non-claims"):
        assert marker in DOCS_HTML, f"в документации нет {marker}"
    assert "verify-offline" in DOCS_HTML


@pytest.mark.skipif(shutil.which("node") is None, reason="node не установлен")
def test_offline_page_actually_executes():
    """Страница проверяется без браузера: модуль исполняется, баннер и вердикты живые.

    Браузерный бэкенд бывает недоступен, а страница обязана работать. Этот прогон
    ловит тихую поломку — когда модуль не доехал и кнопка молчит.
    """
    script = ROOT / "conformance" / "run-page.mjs"
    proc = subprocess.run(["node", str(script)], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "пример: VALID" in proc.stdout
    assert "подделка: NOT VALID" in proc.stdout
