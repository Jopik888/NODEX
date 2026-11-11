# NODEX Windows Alpha 1 — техническая основа

## Что добавлено

- Electron main/preload shell with `contextIsolation`, `sandbox`, `nodeIntegration: false`.
- Local frontend HTTP origin on `127.0.0.1:4173` (secure-context localhost; fixed origin for backend CORS).
- Bootstrap/preflight for bundled Node.js 24.22.3, PostgreSQL 17.11 binaries, Kubo 0.43.1 and backend dependencies; packaged frontend is resolved from the `resources/frontend` payload.
- Windows DPAPI-backed encrypted storage for generated PostgreSQL password and sync-room encryption key via Electron `safeStorage`.
- First-run PostgreSQL data initialization in `%APPDATA%/NODEX`, loopback-only PostgreSQL listener, database creation and existing SQL migrations.
- Kubo repo initialization and loopback-only API/Gateway configuration; Kubo daemon lifecycle.
- Backend start/health check on `127.0.0.1:3001` and service shutdown on app exit. A single-instance lock prevents two NODEX desktop processes from opening the same PostgreSQL/Kubo repositories.
- Electron 45.3.0 + electron-builder 26.18.0 (pinned), NSIS and portable packaging targets. Backend and desktop npm lockfiles are committed; Windows CI validates clean installs, syntax, audits, backend tests and the native Argon2 module. Runtime manifest hashes and integrity states are checked both by Windows build preflight and again when the desktop services start; preflight also checks Authenticode signatures for PostgreSQL EXE/DLL files. Build preflight still fails closed until every runtime binary, archive digest, signature and backend production dependency is staged and verified. Uninstall is configured not to delete app data.

## Важные ограничения этой стадии

1. В архиве проекта пока нет runtime-бинарников Node.js, PostgreSQL и Kubo, поэтому готовый EXE ещё не собирается. `desktop/package-lock.json` и `secure-disk-backend/package-lock.json` уже зафиксированы; CI проверяет установку из lock-файлов. Runtime-бинарники нужно добавить в `assets` по `assets/README-RUNTIME.md` после проверки версий, лицензий и SHA-256.
2. Backend lock-файл уже зафиксирован. До release необходимо выполнить `npm ci --omit=dev` на Windows x64 и проверить нативный `argon2` именно на поставляемом Node.js 24.22.3 runtime; CI дополнительно проверяет загрузку нативного модуля на Node.js 24.22.3.
3. Windows desktop frontend продолжает обращаться к Kubo напрямую по loopback. Для Android добавлен ограниченный backend proxy `/ipfs/api/v0`: только `add`, `cat`, `pin/add`, `pin/rm`; все запросы требуют активную сессию, CSRF и session-bound CSRF. Kubo API/Gateway остаются строго на 127.0.0.1. `repo/gc` никогда не проксируется. Загрузка временно сохраняется через multer diskStorage (лимит 100 MiB) и удаляется после отправки в Kubo.
4. Frontend содержит ESM/CDN зависимости (Trystero, JSZip, qrcode-generator, html5-qrcode). Для работы без интернета их нужно локализовать и проверить лицензии/версии. На Alpha 1 интернет нужен для этих внешних модулей.
5. SMTP в Alpha 1 не настроен по умолчанию. Backend запускается в development-mode с `DEV_RETURN_VERIFICATION_TOKEN=true` для тестовой регистрации. Не использовать эту конфигурацию как публичный production-сервер.
6. `COOKIE_SECURE=false` допустим только для loopback Alpha 1. LAN-доступ намеренно не включён: backend слушает только 127.0.0.1. До его включения требуется согласованная HTTPS-точка входа, доверие Android-клиента к сертификату и проверенная cross-site cookie/CSRF-модель. Текущий backend использует `SameSite=Lax`; одних CORS origins недостаточно для cookie-аутентификации из Android WebView. В этом репозитории отсутствует нативный Android-проект, поэтому настройка WebView cookie policy / certificate trust ещё не выполнена. Не менять HOST на `0.0.0.0` и не открывать Kubo API/Gateway.
7. Kubo `/repo/gc` остаётся доступен только локальному процессу/loopback. Не проксировать эту команду в Android.
8. Startup fails closed if runtime integrity statuses are not all `VERIFIED`, required archive checksums are absent, an executable hash differs, or a pinned runtime version differs. Stop sequence: backend/Kubo child processes terminate; PostgreSQL is stopped with `pg_ctl -m fast`. User data remains in app userData directory.
9. Latest Windows CI passes 71 backend tests and 4 desktop runtime-integrity tests (all passed), backend npm audit reports zero vulnerabilities, and native Argon2 loads. The backend suite includes checks that the IPFS proxy remains loopback-only, authenticated/CSRF-protected before upload parsing, upload-limited, and restricted to the content/pin allowlist. Desktop build dependencies currently report six moderate `minimatch` advisories in the Electron Builder dependency tree; no high/critical advisory is reported. Do not apply `npm audit fix --force` because it proposes a major-version change to Electron Builder; resolve with a compatible upstream release before public distribution.

## Подготовка build-машины

Требуется Windows 10/11 x64, Node.js 24.22.3 и npm.

1. Положить проверенный `node.exe` в `desktop/assets/runtime/`.
2. Положить полную Windows binary distribution PostgreSQL в `desktop/assets/postgres/` (структура `bin`, `lib`, `share`).
3. Положить `ipfs.exe` Kubo в `desktop/assets/ipfs/`.
4. В `secure-disk-backend` выполнить `npm ci --omit=dev` на Node.js 24.22.3; lock-файл уже сохранён в репозитории.
5. В `desktop` выполнить `npm ci`.
6. Запуск оболочки: `npm start`.
7. Сборка: `npm run dist:win`.

Сборку необходимо выполнять на Windows. Этот исходный патч не содержит бинарных third-party runtime assets и не является готовым инсталлятором.
