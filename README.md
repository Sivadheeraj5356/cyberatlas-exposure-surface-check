# Exposure Surface Check

A client-side heuristic QA for internet-mapping results, built with CyberAtlas's problem in mind: mapping exposed infrastructure at internet scale is only useful if the findings get read with a security eye.

Paste discovered services, one per line as `host | port | banner`, and the tool flags potential exposure:

- **DATABASE_PORT_PUBLIC** - a database-looking port reachable in the scan
- **ADMIN_PANEL_NO_AUTH_HINT** - an admin-panel-looking service with no auth hint in its banner
- **DEV_HOST_PUBLIC** - a dev/staging-looking hostname visible in the scan
- **TLS_ISSUE** - expired or self-signed certificate hints
- **LEGACY_PLAINTEXT_SERVICE** - telnet / anonymous-FTP style exposure
- **UNPARSED** - lines that do not match the expected format

Plain HTML, CSS and JavaScript. No build step, no external services.

## Run

Open `index.html` in a browser, paste scan rows, click "Run surface check".

## Test

```
npm test
```

## Limitations

This is a banner-level heuristic screen, not a vulnerability scanner:

- It matches port numbers, hostname prefixes and banner keywords; intent is inferred, never verified. Every finding says "verify".
- A database port may be intentionally public behind its own auth; an admin panel may enforce auth in ways the banner does not show.
- It runs on what you paste - coverage of the real attack surface depends entirely on the input.
- Tests verify the rules match their intended sample patterns; they do not prove real exposures are found.
