"""IndexNow: сообщить поисковикам об изменении страниц без аккаунта и API-ключа.

Google этот протокол не принимает (у него Search Console), а Bing, Yandex и Seznam — да.
Ключ лежит в корне репозитория файлом `<key>.txt` и отдаётся сервисом; IndexNow проверяет,
что файл доступен по адресу, поэтому подделка чужого домена не проходит.
"""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENDPOINT = "https://api.indexnow.org/indexnow"
HOST = "attest.rta.lat"


def key() -> str:
    """Ключ — имя файла в корне репозитория; содержимое файла равно ключу."""
    for path in ROOT.glob("????????????????????????????????.txt"):
        value = path.read_text(encoding="utf-8").strip()
        if path.stem == value:
            return value
    raise RuntimeError("нет файла ключа IndexNow в корне репозитория")


def payload(urls: list[str]) -> dict:
    k = key()
    return {"host": HOST, "key": k, "keyLocation": f"https://{HOST}/{k}.txt", "urlList": urls}


def send(urls: list[str], timeout: int = 20) -> tuple[int, str]:
    body = json.dumps(payload(urls)).encode("utf-8")
    req = urllib.request.Request(ENDPOINT, data=body, method="POST",
                                 headers={"Content-Type": "application/json; charset=utf-8"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return int(resp.status), resp.read(200).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read(200).decode("utf-8", "replace")
