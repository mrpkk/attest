"""Общие настройки тестов.

Тесты бьют по тому же глобальному счётчику метрик, что и боевой сервис:
20.10.2026 обнаружено, что 298 из 304 «direct» проверок накручены прогонами
тестов. ATTEST_METRICS=0 отключает запись до импорта attest.service.
"""
import os

import pytest

os.environ.setdefault("ATTEST_METRICS", "0")


@pytest.fixture(autouse=True)
def _no_real_email(monkeypatch):
    """Тесты не отправляют настоящую почту.

    POST /start выдаёт ключ и отправляет письмо. В тестах это означало бы
    реальные письма на выдуманные адреса (и пачку писем при каждом прогоне).
    """
    import attest.service as svc
    monkeypatch.setattr(svc, "_send_key_email", lambda to, token, until: "")


@pytest.fixture(autouse=True)
def _isolate_metrics_state(tmp_path, monkeypatch):
    """Ни один тест не пишет в боевой `~/.local/share/attest/metrics.json`.

    23.10.2026: прогон тестов обнулил живые метрики — 780 просмотров и 304
    проверки превратились в 7 проверок и $0.01. Причина не в одном тесте:
    `Metrics()` по умолчанию читает и пишет реальный STATE_PATH, и любой тест,
    забывший подменить путь, затирал продакшн-файл. `ATTEST_METRICS=0` глушит
    только часть путей записи, поэтому полагаться на него нельзя.

    Изоляция — на уровне модуля и для всех тестов сразу: подмена пути безопасна
    и не мешает тестам, которые подменяют STATE_PATH сами (их патч внутри).
    """
    from attest import metrics as metrics_mod
    monkeypatch.setattr(metrics_mod, "STATE_PATH", tmp_path / "metrics.json")
