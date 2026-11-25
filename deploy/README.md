# Сторож attest

Ставится один раз:
```
cp deploy/attest-watchdog.service deploy/attest-watchdog.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now attest-watchdog.timer
```
Проверка: `systemctl --user list-timers attest-watchdog.timer`, журнал — `journalctl --user -u attest-watchdog.service -n 20`.
Без `ATTEST_SLACK_WEBHOOK` в `~/.env` алерт пишется в журнал и считается **недоставленным** — тишины не изображаем.
