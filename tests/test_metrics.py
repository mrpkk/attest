"""Метрики должны переживать перезапуск.

Регрессия: `save()` вызывался только при показе страницы, поэтому проверки и
платежи жили в памяти и обнулялись при каждом рестарте сервиса. Счётчик
выручки врёт именно в ту сторону, которая выглядит правдоподобно, —
потерянные деньги выглядят как «выручки ещё не было».
"""

from __future__ import annotations

import json
import sys
import threading
import time
from unittest import mock

import pytest

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))

from attest import metrics as metrics_module
from attest.metrics import Metrics, channel_of


@pytest.fixture
def store(tmp_path):
    """Подменяем файл состояния на временный."""
    path = tmp_path / "metrics.json"
    with mock.patch.object(metrics_module, "STATE_PATH", path):
        yield path


def _read(path):
    return json.loads(path.read_text(encoding="utf-8"))


class TestPersisted:
    def test_view_is_persisted(self, store):
        m = Metrics()
        m.view("glama")
        assert _read(store)["views"] == {"glama": 1}

    def test_check_is_persisted(self, store):
        m = Metrics()
        m.check("glama", paid=False)
        assert _read(store)["checks"] == {"glama:free": 1}

    def test_paid_check_is_persisted(self, store):
        m = Metrics()
        m.check("glama", paid=True)
        data = _read(store)
        assert data["checks"] == {"glama:paid": 1}
        assert data["paid"] == {"glama": 1}

    def test_payment_is_persisted(self, store):
        m = Metrics()
        m.payment("smithery", 500_000)
        data = _read(store)
        assert data["revenue_atoms"] == 500_000
        assert data["paid"] == {"smithery": 1}

    def test_revenue_survives_new_instance(self, store):
        """Главное: перезапуск не обнуляет выручку."""
        first = Metrics()
        first.payment("glama", 500_000)
        first.check("glama", paid=True)

        second = Metrics()
        second.load()
        snap = second.snapshot()
        assert snap["revenue_atoms"] == 500_000
        assert snap["successful_paid_actions"] == 1
        assert snap["revenue_usdc"] == "0.500000"

    def test_checks_survive_restart(self, store):
        first = Metrics()
        first.check("direct", paid=False)
        first.check("direct", paid=False)
        first.save()                      # троттлинг: вторая проверка ждёт окна
        second = Metrics()
        second.load()
        assert second.snapshot()["checks_free"] == 2


class TestThrottle:
    def test_burst_of_checks_writes_once(self, store):
        """Пачка проверок не должна писать в диск на каждую."""
        m = Metrics()
        writes = []
        real_save = m.save
        with mock.patch.object(m, "save", side_effect=lambda: (writes.append(1), real_save())[1]):
            for _ in range(50):
                m.check("direct", paid=False)
        assert len(writes) <= 2, f"троттлинг не сработал: {len(writes)} записей"

    def test_payment_bypasses_throttle(self, store):
        """Платёж сохраняется сразу, даже если только что был троттлинг."""
        m = Metrics()
        m.check("direct", paid=False)      # съедает окно троттлинга
        m._last_save = time.time()          # окно только что открыто
        m.payment("glama", 500_000)
        assert _read(store)["revenue_atoms"] == 500_000, \
            "оплата не записалась сразу — потеряем её при рестарте"

    def test_throttle_window_expires(self, store):
        m = Metrics()
        m.check("direct", paid=False)
        m._last_save = time.time() - 999
        m.check("direct", paid=False)
        assert _read(store)["checks"] == {"direct:free": 2}


class TestConcurrent:
    def test_parallel_writes_are_not_lost(self, store):
        """Сервис многопоточный: счётчик обязан совпадать с числом вызовов."""
        m = Metrics()
        def worker():
            for _ in range(25):
                m.check("direct", paid=False)
        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        m.save()                          # сбросить окно троттлинга
        assert m.snapshot()["checks_free"] == 100
        assert _read(store)["checks"]["direct:free"] == 100


class TestChannelOf:
    @pytest.mark.parametrize("query,expected", [
        ("?ref=glama", "glama"),
        ("?ref=smithery", "smithery"),
        ("?ref=storebot", "storebot"),
        ("?a=1&ref=pulsemcp&b=2", "pulsemcp"),
        ("?ref=GLAMA", "glama"),          # регистр не мешает
        ("?ref=  glama  ", "glama"),      # мусор вокруг имени
    ])
    def test_ref_wins(self, query, expected):
        assert channel_of(query, None) == expected

    def test_ref_is_truncated(self, store):
        """Имя канала режется: иначе им забивают память процесса."""
        assert len(channel_of("?ref=" + "x" * 500, None)) == 32

    def test_referer_used_when_no_ref(self):
        assert channel_of("", "https://glama.ai/mcp/servers") == "glama"

    def test_referer_www_stripped(self):
        assert channel_of("", "https://www.glama.ai/x") == "glama"

    def test_unknown_referer_keeps_host(self):
        """Чужой хост полезен сам по себе: видно, откуда пришли."""
        assert channel_of("", "https://news.example.com/a") == "news.example.com"

    def test_direct_when_nothing(self):
        assert channel_of("", None) == "direct"
        assert channel_of("", "") == "direct"

class TestChannelFlood:
    def test_channel_count_is_bounded(self, store):
        """`ref` от клиента не должен раздувать словарь бесконечно."""
        from attest.metrics import MAX_CHANNELS
        m = Metrics()
        for i in range(MAX_CHANNELS * 2):
            m.view(f"ref-{i}")
            m.check(f"ref-{i}", paid=False)
        m.save()
        assert len(m.views) <= MAX_CHANNELS
        assert len(m.checks) <= MAX_CHANNELS

    def test_eviction_uses_recency_not_frequency(self, store):
        """Вытесняется самый давний, а не самый редкий канал.

        Если бы вытеснялся наименее частый, живой канал с малым счётчиком
        исчезал бы раньше заведомого мусора — и метрика замолчала бы
        именно там, где есть трафик.
        """
        from attest.metrics import MAX_CHANNELS
        m = Metrics()
        for i in range(MAX_CHANNELS):
            m.view(f"ref-{i}")        # давно не видно, счётчик 1
        for _ in range(3):
            m.view("живой")           # только что видели
        # Волна короче потолка: «живой» замечен позже ref-*, поэтому он
        # ещё не самый давний и вытеснен быть не должен.
        for i in range(MAX_CHANNELS - 10):
            m.view(f"ref-{i}-новый")

        assert "живой" in m.views, "недавно замеченный канал вытеснен"
        assert "ref-0" not in m.views, "давно не замеченный канал остался"

    def test_count_of_evicted_channel_is_gone(self, store):
        """Вытесненный канал не воскресает со старым счётчиком."""
        from attest.metrics import MAX_CHANNELS
        m = Metrics()
        m.view("давно")
        for i in range(MAX_CHANNELS):
            m.view(f"ref-{i}")
        m.view("давно")
        assert m.views["давно"] == 1


class TestSpentNoncesSurviveRestart:
    """Потраченный nonce платежа не должен воскресать при перезапуске.

    До 17.10.2026 множество жило только в памяти обработчика. Перезапуск
    сервиса его очищал — и подпись, за которую уже заплатили, принималась
    второй раз. Для бесплатного тарифа это терпимо, для платного — прямая
    потеря денег.
    """

    def test_spent_nonce_survives_restart(self, tmp_path):
        from attest.metrics import SpentNonces

        path = tmp_path / "nonces.json"
        first = SpentNonces(path)
        first.add("0xоплачено")
        assert "0xоплачено" in first

        second = SpentNonces(path)      # как после перезапуска
        assert "0xоплачено" in second, (
            "потраченный nonce вернулся к жизни — оплаченный платёж "
            "принимается второй раз")

    def test_fresh_nonce_is_not_in_store(self, tmp_path):
        from attest.metrics import SpentNonces
        store = SpentNonces(tmp_path / "nonces.json")
        assert "0xновый" not in store

    def test_corrupt_file_does_not_break_service(self, tmp_path):
        from attest.metrics import SpentNonces
        path = tmp_path / "nonces.json"
        path.write_text("{не json", encoding="utf-8")
        store = SpentNonces(path)       # не должно бросить
        store.add("0xновый")
        assert "0xновый" in store

    def test_no_path_keeps_old_behaviour(self):
        """Путь не задан — только память. Так работают тесты и встраивание."""
        from attest.metrics import SpentNonces
        store = SpentNonces(None)
        store.add("0xчто-то")
        assert "0xчто-то" in store


class TestRepeatUsage:
    """`repeat_usage_7d` — вернулся ли платящий клиент в пределах недели.

    План (§6.2) ставит эту метрику между «первый платный вызов» и
    «9 USDC за 30 дней»: один платёж — случайный заход, два в неделю —
    клиент. Считаются кошельки из подписанной авторизации; кроме времени
    оплат и счётчика по кошельку не хранится ничего.
    """

    def test_single_payment_is_not_repeat(self, store):
        m = Metrics()
        m.payment("glama", 500_000, payer="0xAAA")
        snap = m.snapshot()
        assert snap["repeat_usage_7d"] == 0
        assert snap["unique_payers"] == 1

    def test_two_payments_in_window_are_repeat(self, store):
        m = Metrics()
        m.payment("glama", 500_000, payer="0xAAA")
        m.payment("glama", 500_000, payer="0xAAA")
        assert m.snapshot()["repeat_usage_7d"] == 1

    def test_two_payments_outside_window_are_not_repeat(self, store):
        now = {"t": 1_000_000.0}
        with mock.patch.object(metrics_module.time, "time", lambda: now["t"]):
            m = Metrics()
            m.payment("glama", 500_000, payer="0xAAA")
            now["t"] += 8 * 86400
            m.payment("glama", 500_000, payer="0xAAA")
        assert m.snapshot()["repeat_usage_7d"] == 0

    def test_different_payers_do_not_make_repeat(self, store):
        m = Metrics()
        m.payment("glama", 500_000, payer="0xAAA")
        m.payment("glama", 500_000, payer="0xBBB")
        snap = m.snapshot()
        assert snap["repeat_usage_7d"] == 0
        assert snap["unique_payers"] == 2

    def test_payment_without_payer_still_counts_money(self, store):
        """Вызовы без кошелька (старые пути) не ломаются: деньги считаются."""
        m = Metrics()
        m.payment("direct", 500_000)
        snap = m.snapshot()
        assert snap["revenue_atoms"] == 500_000
        assert snap["repeat_usage_7d"] == 0
        assert snap["unique_payers"] == 0

    def test_repeat_survives_restart(self, store):
        first = Metrics()
        first.payment("glama", 500_000, payer="0xAAA")
        first.payment("glama", 500_000, payer="0xAAA")
        second = Metrics()
        second.load()
        assert second.snapshot()["repeat_usage_7d"] == 1

    def test_payers_are_bounded(self, store):
        from attest.metrics import MAX_PAYERS
        m = Metrics()
        for i in range(MAX_PAYERS * 2):
            m.payment("direct", 1, payer=f"0x{i:040x}")
        assert len(m.payers) <= MAX_PAYERS


# --- 21.10.2026: «75 проверок» и «75 клиентов по одной» давали одинаковый
# checks_total, и по метрике нельзя было понять, работает воронка или нет.

def test_clients_are_counted_separately(tmp_path, monkeypatch):
    import attest.metrics as m
    monkeypatch.setattr(m, "STATE_PATH", tmp_path / "metrics.json")
    met = m.Metrics()
    met.check("direct", False, client="client-a")
    met.check("direct", False, client="client-a")
    met.check("direct", False, client="client-b")
    met.check("direct", False)  # без клиента — счётчик проверок растёт, клиент нет
    snap = met.snapshot()
    assert snap["checks_total"] == 4
    assert snap["unique_clients"] == 2
    assert snap["checks_per_client"] == {"1": 1, "2-5": 1, "6-20": 0, "20+": 0}


def test_clients_survive_restart(tmp_path, monkeypatch):
    import attest.metrics as m
    monkeypatch.setattr(m, "STATE_PATH", tmp_path / "metrics.json")
    first = m.Metrics()
    for _ in range(7):
        first.check("mcp", False, client="heavy")
    first.save()
    second = m.Metrics()
    second.load()
    snap = second.snapshot()
    assert snap["unique_clients"] == 1
    assert snap["checks_per_client"]["6-20"] == 1


def test_paywall_hits_are_counted(tmp_path, monkeypatch):
    """Сколько клиентов упёрлись в бесплатный лимит — ключевая метрика воронки.

    Без неё «100 проверок и 0 оплат» неотличимо от «никто не дошёл до барьера».
    """
    import attest.metrics as m
    monkeypatch.setattr(m, "STATE_PATH", tmp_path / "metrics.json")
    met = m.Metrics()
    assert met.snapshot()["paywall_hits"] == 0
    met.paywall_hit()
    met.paywall_hit()
    assert met.snapshot()["paywall_hits"] == 2

    met.save()
    again = m.Metrics()
    again.load()
    assert again.snapshot()["paywall_hits"] == 2
