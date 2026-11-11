# NODEX endpoint configuration (alpha packaging stage 1)

`config.js` centralizes frontend API endpoints. Defaults are unchanged from v0.4.7:

- API: `http://localhost:3001/api/v1`
- IPFS Kubo API: `http://localhost:5001/api/v0`

Override values before the module `app.js` loads by defining `window.NODEX_CONFIG`:

```html
<script>
  window.NODEX_CONFIG = {
    apiBase: 'https://nodex-host.local/api/v1',
    ipfsApi: 'https://nodex-host.local/ipfs/api/v0'
  };
</script>
```

Alternatively set the `nodex-api-base` and `nodex-ipfs-api` meta tags in `index.html`.
The legacy `secure-disk-api-base` meta tag remains supported as an API fallback.

Precedence: `window.NODEX_CONFIG` > meta tags > v0.4.7 localhost defaults.
URLs must be HTTP(S), without embedded credentials, query strings or fragments.

This is endpoint configuration only. It does not yet add a settings screen, persist a selected LAN host, configure backend CORS/cookies/TLS, expose Kubo safely, or make the backend/IPFS reachable over LAN. Do not set the Kubo admin API to `0.0.0.0` for LAN access. The future Windows host should expose a restricted authenticated HTTPS interface instead.
