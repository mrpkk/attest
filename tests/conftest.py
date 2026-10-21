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
