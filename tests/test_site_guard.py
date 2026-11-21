"""Site Guard: проверки состояния и алертов без сети."""
from attest import site_guard as sg


def test_host_of_strips_scheme_and_path():
    assert sg.host_of("https://Example.com/path?x=1") == "example.com"
    assert sg.host_of("http://a.b:8080/x") == "a.b"


def test_alerts_only_on_change():
    prev = {"up": True, "ssl_days": 40, "domain_days": 200}
    now = {"url": "https://x", "up": True, "ssl_days": 40, "domain_days": 200}
    assert sg.evaluate(prev, now) == []


def test_down_and_recovered_alerts():
    down = sg.evaluate({"up": True}, {"url": "https://x", "up": False, "code": 0, "error": "timeout"})
    assert down and "недоступен" in down[0]
    up = sg.evaluate({"up": False}, {"url": "https://x", "up": True, "code": 200})
    assert up and "снова отвечает" in up[0]


def test_ssl_and_domain_thresholds():
    a = sg.evaluate({"ssl_days": 30, "domain_days": 90},
                    {"url": "https://x", "up": True, "ssl_days": 10, "domain_days": 20})
    assert any("SSL" in x for x in a) and any("домен" in x for x in a)


def test_parse_date_variants():
    assert sg._parse_date("2027-01-01T00:00:00Z").year == 2027
    assert sg._parse_date("01.01.2027").year == 2027
    assert sg._parse_date("not-a-date") is None
