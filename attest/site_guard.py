"""Site Guard: uptime, SSL и срок домена; алерты при изменении состояния.

Продукт $49/год. Клиент присылает URL и Telegram chat_id — мы добавляем сайт,
проверяем каждые 5 минут и пишем только при изменении (упал/поднялся, SSL <14 дней,
домен <30 дней), чтобы не спамить.

  python3 -m attest.site_guard add --url https://example.com --chat 123456789
  python3 -m attest.site_guard list
  python3 -m attest.site_guard check [--dry-run]
  python3 -m attest.site_guard test --url https://example.com
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

STATE = Path(os.getenv("SITE_GUARD_STATE", "/home/iamthat/.local/share/attest/site_guard.json"))
TIMEOUT = 15
UA = "Mozilla/5.0 (compatible; SiteGuard/1.0; +https://attest.rta.lat/tools)"


def load() -> list[dict]:
    try:
        data = json.loads(STATE.read_text())
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def save(sites: list[dict]) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(sites, ensure_ascii=False, indent=1))
    tmp.replace(STATE)


def host_of(url: str) -> str:
    return re.sub(r"^https?://", "", url).split("/")[0].split(":")[0].lower()


def check_http(url: str) -> tuple[bool, int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return True, r.status, ""
    except urllib.error.HTTPError as e:
        # 4xx/5xx — сайт ответил, но это уже проблема
        return False, e.code, f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001 — сеть/таймаут/DNS
        return False, 0, type(e).__name__


def ssl_days(host: str) -> int | None:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
        exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return int((exp - datetime.now(timezone.utc)).total_seconds() // 86400)
    except Exception:
        return None


WHOIS_RE = re.compile(
    r"(?:Registry Expiry Date|Registrar Registration Expiration Date|Expiry Date|"
    r"paid-till|expiration date)\s*:\s*([0-9T:\-\. Z]+)", re.I)


def _parse_date(raw: str) -> datetime | None:
    raw = raw.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d", "%d.%m.%Y"):
        try:
            return datetime.strptime(raw[:len(time.strftime(fmt))], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def domain_days(host: str) -> int | None:
    try:
        out = subprocess.run(["whois", host], capture_output=True, text=True, timeout=25).stdout
    except Exception:
        return None
    for m in WHOIS_RE.finditer(out):
        exp = _parse_date(m.group(1))
        if exp:
            return int((exp - datetime.now(timezone.utc)).total_seconds() // 86400)
    return None


def evaluate(prev: dict, now: dict) -> list[str]:
    """Только изменения, не ежедневный шум."""
    alerts = []
    if prev.get("up") is True and not now.get("up"):
        alerts.append(f"🔴 {now['url']} недоступен: {now.get('error') or now.get('code')}")
    elif prev.get("up") is False and now.get("up"):
        alerts.append(f"🟢 {now['url']} снова отвечает ({now.get('code')})")
    ssl_now, ssl_prev = now.get("ssl_days"), prev.get("ssl_days")
    if ssl_now is not None and ssl_now < 14 and (ssl_prev is None or ssl_prev >= 14):
        alerts.append(f"⚠️ {now['url']}: SSL истекает через {ssl_now} дн.")
    dom_now, dom_prev = now.get("domain_days"), prev.get("domain_days")
    if dom_now is not None and dom_now < 30 and (dom_prev is None or dom_prev >= 30):
        alerts.append(f"⚠️ {now['url']}: домен истекает через {dom_now} дн.")
    return alerts


def notify(chat_id: str, text: str) -> bool:
    token = ""
    for line in (Path.home() / ".env").read_text().splitlines():
        if line.startswith("TG_TOKEN="):
            token = line.split("=", 1)[1].strip().strip('"')
    if not token or not chat_id:
        return False
    try:
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status == 200
    except Exception:
        return False


def probe(site: dict) -> dict:
    host = host_of(site["url"])
    up, code, err = check_http(site["url"])
    return {"url": site["url"], "up": up, "code": code, "error": err,
            "ssl_days": ssl_days(host), "domain_days": domain_days(host),
            "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}


def main() -> int:
    ap = argparse.ArgumentParser(description="Site Guard")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add")
    a.add_argument("--url", required=True)
    a.add_argument("--chat", default="")
    a.add_argument("--email", default="")
    sub.add_parser("list")
    r = sub.add_parser("remove")
    r.add_argument("--url", required=True)
    c = sub.add_parser("check")
    c.add_argument("--dry-run", action="store_true")
    t = sub.add_parser("test")
    t.add_argument("--url", required=True)
    args = ap.parse_args()

    if args.cmd == "add":
        sites = load()
        if any(s["url"] == args.url for s in sites):
            print("уже есть")
            return 0
        sites.append({"url": args.url, "chat": args.chat, "email": args.email,
                      "state": {}, "since": datetime.now(timezone.utc).isoformat(timespec="seconds")})
        save(sites)
        print(f"добавлен {args.url}")
        return 0
    if args.cmd == "list":
        for s in load():
            st = s.get("state") or {}
            print(f"{s['url']} · up={st.get('up')} · ssl={st.get('ssl_days')} · domain={st.get('domain_days')}")
        return 0
    if args.cmd == "remove":
        sites = [s for s in load() if s["url"] != args.url]
        save(sites)
        print("удалён")
        return 0
    if args.cmd == "test":
        print(json.dumps(probe({"url": args.url}), ensure_ascii=False, indent=1))
        return 0

    # check
    sites = load()
    changed = 0
    for s in sites:
        now = probe(s)
        alerts = evaluate(s.get("state") or {}, now)
        s["state"] = now
        for text in alerts:
            changed += 1
            print(text)
            if not args.dry_run:
                notify(str(s.get("chat") or ""), text)
    if not args.dry_run:
        save(sites)
    print(f"проверено {len(sites)}, алертов {changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
