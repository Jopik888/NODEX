# NODEX Windows Alpha 1 — техническая основа

## Что добавлено

- Electron main/preload shell with `contextIsolation`, `sandbox`, `nodeIntegration: false`.
- Local frontend HTTP origin on `127.0.0.1:4173` (secure-context localhost; fixed origin for backend CORS).
- Bootstrap/preflight for bundled Node.js 24.22.2, PostgreSQL 17.11 binaries, Kubo 0.43.1 and backend dependencies; packaged frontend is resolved from the `resources/frontend` payload.
- Windows DPAPI-backed encrypted storage for generated PostgreSQL password and sync-room encryption key via Electron `safeStorage`.
- First-run PostgreSQL data initialization in `%APPDATA%/NODEX`, loopback-only PostgreSQL listener, database creation and existing SQL migrations.
- Kubo repo initialization and loopback-only API/Gateway configuration; Kubo daemon lifecycle.
- Backend start/health check on `127.0.0.1:3001` and service shutdown on app exit. A single-instance lock prevents two NODEX desktop processes from opening the same PostgreSQL/Kubo repositories.
- Electron 45.3.0 + electron-builder 26.18.0 (pinned), NSIS and portable packaging targets. Build preflight fails closed until all pinned runtime assets and lock files are staged. Uninstall is configured not to delete app data.

## Важные ограничения этой стадии

1. В архиве проекта нет runtime-бинарников Node.js, PostgreSQL и Kubo, а также package-lock файлов, поэтому готовый EXE пока не собирается. Их нужно добавить в `assets` по `assets/README-RUNTIME.md` после проверки версий, лицензий и SHA-256.
2. Backend `package.json` не содержит lock-файла. До release необходимо создать и зафиксировать `package-lock.json`, выполнить `npm ci --omit=dev` и проверить нативный `argon2` именно на поставляемом Node.js 24.22.2 runtime.
3. Текущий frontend обращается к Kubo API напрямую по `http://localhost:5001/api/v0` и вызывает `/add`, `/cat`, `/pin/add`, `/pin/rm`, `/repo/gc`. Это приемлемо только для локального Windows-клиента при Kubo bind на loopback. Android LAN proxy — отдельный этап; не публиковать Kubo API в LAN.
4. Frontend содержит ESM/CDN зависимости (Trystero, JSZip, qrcode-generator, html5-qrcode). Для работы без интернета их нужно локализовать и проверить лицензии/версии. На Alpha 1 интернет нужен для этих внешних модулей.
5. SMTP в Alpha 1 не настроен по умолчанию. Backend запускается в development-mode с `DEV_RETURN_VERIFICATION_TOKEN=true` для тестовой регистрации. Не использовать эту конфигурацию как публичный production-сервер.
6. `COOKIE_SECURE=false` допустим только для loopback Alpha 1. LAN-доступ не включать до локального HTTPS, secure cookies и проверки CSRF/CORS.
7. Kubo `/repo/gc` остаётся доступен только локальному процессу/loopback. Не проксировать эту команду в Android.
8. Stop sequence: backend/Kubo child processes terminate; PostgreSQL is stopped with `pg_ctl -m fast`. User data remains in app userData directory.

## Подготовка build-машины

Требуется Windows 10/11 x64, Node.js 24.22.2 и npm.

1. Положить проверенный `node.exe` в `desktop/assets/runtime/`.
2. Положить полную Windows binary distribution PostgreSQL в `desktop/assets/postgres/` (структура `bin`, `lib`, `share`).
3. Положить `ipfs.exe` Kubo в `desktop/assets/ipfs/`.
4. В `secure-disk-backend` выполнить `npm install --omit=dev` на Node.js 24.22.2; сохранить lock-файл в репозитории.
5. В `desktop` выполнить `npm install`.
6. Запуск оболочки: `npm start`.
7. Сборка: `npm run dist:win`.

Сборку необходимо выполнять на Windows. Этот исходный патч не содержит бинарных third-party runtime assets и не является готовым инсталлятором.
