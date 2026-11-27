# PhishGuard Local

**100% Local, Zero-Telemetry Real-Time Browser Phishing Detection Extension (`v1.5.0`)**

PhishGuard Local is a **Manifest V3** browser extension (compatible with Google Chrome, Brave, Microsoft Edge, and Mozilla Firefox) that performs multi-layer phishing detection entirely client-side in under `< 50 ms` per page—without sending any browsing data, URLs, or form contents to external servers.

## Key Features

### 1. Multi-Layer Client-Side Detection Engines (6 Diagnostic Categories)

1. **Domain Similarity & IDN Homograph (`extension/src/url_analyzer.js`)**
   - **Offline eTLD+1 Parser**: Accurately separates subdomains from registrable domains across country-code multi-part TLDs (`.co.id`, `.co.uk`, `.com.au`, etc.) and shared hosting suffixes (`.github.io`, `.pages.dev`, `.vercel.app`, `.netlify.app`, `.web.app`, etc.).
   - **RFC 3492 Punycode Decoder**: Decodes `xn--` hostnames locally to expose exact spoofed brand names (e.g., `xn--pypal-4ve.com` → `pаypal.com` spoofing `paypal.com`).
   - **Precision Typosquatting & Combosquatting**: Detects Levenshtein-distance edits, visual confusables (including dual `1→l/i` normalization like `paypa1.com`, `m1crosoft.com`, `g1thub.com`, `g00gle.com`), subdomain/hyphenated brand spoofing, and non-hyphenated combosquatting (`paypallogin.com`, `googleverify.xyz`, `klikbcalogin.top`).
   - **DGA & URL Lure Analysis**: Flags high-entropy randomly generated domains (Shannon entropy), `@` userinfo tricks, raw IP hosts, non-standard ports, and suspicious credential-lure URL paths.

2. **Form Action & Credential Hygiene (`extension/src/dom_analyzer.js`)**
   - **Read-Only Credential Inspection**: Passively inspects `<form>` elements (including **Open Shadow DOM** web components) containing `<input type="password">`, `autocomplete="current-password" | "new-password"`, or credit card inputs (`cc-number`, `cc-csc`, `cvv`) without ever reading `.value` or listening to keystrokes.
   - **False-Positive Elimination**: Automatically recognizes same-site eTLD+1 targets, official sibling ecosystems (`github.com` ↔ `githubusercontent.com`, `google.com` ↔ `gstatic.com`), trusted OAuth/SSO providers (`accounts.google.com`, `login.microsoftonline.com`, `appleid.apple.com`, `*.okta.com`, `*.auth0.com`), and legitimate payment processors (`stripe.com`, `paypal.com`, `midtrans.com`, `xendit.co`).
   - **Modern Harvesting Traps**: Detects plaintext HTTP password/card forms, external credential/card exfiltration, **crypto wallet seed/recovery phrase harvesting**, password forms hosted on disposable free-hosting suffixes, and deceptive mismatched `<a>` links.

3. **Brand & Favicon Integrity (`extension/src/dom_analyzer.js`)**
   - **Browser-in-the-Browser (BitB) Detection**: Flags spoofed address bars (`https://accounts.google.com/...`, `https://login.microsoftonline.com/...`) rendered inside untrusted login modals.
   - **Content & Favicon Impersonation**: Detects untrusted credential pages impersonating major global/regional brands via `<title>`, metadata, `<h1>`/`<h2>` headings, logo `alt` text, urgency/suspension lures, or hotlinked brand favicons.

4. **Iframe & Overlay Security (`extension/src/dom_analyzer.js`)**
   - Uses both inline styles and `getComputedStyle()` to catch suspicious full-screen/high-`z-index` cross-origin overlay iframes, hidden zero-pixel untrusted iframes, and inline `data:`/`blob:`/`javascript:`/`srcdoc` iframe overlays.

5. **Script & Obfuscation Audit (`extension/src/dom_analyzer.js`)**
   - **Credential Exfiltration Webhooks**: Flags inline scripts referencing `api.telegram.org/bot...` or `discord.com/api/webhooks/...` on untrusted pages.
   - **HTML Smuggling Detection**: Catches client-side Base64/Blob `createObjectURL` download smuggling and `data:`/`blob:` download traps for dangerous file types.
   - **Phishing Kit Obfuscation**: Flags `eval`/`Function(atob(...))`, packed eval kits, `fromCharCode` chains, suspicious external script hosts, and right-click blocking on untrusted login pages.

6. **Redirect Chain & Protocol Security (`extension/background.js`, `extension/src/risk_engine.js`)**
   - Collapses same-site/sibling regional hops (e.g., `pinterest.com` → `id.pinterest.com` → `www.pinterest.com`), filters OAuth hops, detects stealth `<meta http-equiv="refresh">` external jumps and suspicious open-redirect query parameters, and applies a **Multi-Signal Cross-Category Correlation** amplifier for coordinated multi-vector attacks.

### 2. Precision Popup Dashboard & Live Monitoring
- **Curated Offline Seed List**: 500+ legitimate global & regional eTLD+1 domains (`extension/src/domains.js`) for near-zero false positives.
- **Dynamic SPA Observer**: Lightweight debounced `MutationObserver` in `content_script.js` catches dynamically injected login modals and iframes after page load.
- **Modern Matte Graphite & Mint UI**: `Poppins` typography, `SAFE` / `WARNING` / `DANGER` / `VERIFIED` verdicts, click-to-inspect 6-row diagnostic telemetry, live DOM counts (`Forms`, `Links`, `Iframes`, `Scripts`), one-click **Re-scan**, local **JSON Report Export**, **Low / Medium / High** detection sensitivity (`40/75`, `25/60`, `15/45`), local whitelist management, Shadow DOM warning banner, and borderless **Gray Hat Person** toolbar icons.

## Project Structure

```text
pishingdetect/
├── extension/
│   ├── manifest.json          # Manifest V3 configuration (v1.5.0)
│   ├── background.js          # Service Worker (redirects, live scans, icons, storage)
│   ├── content_script.js      # Read-only DOM inspector, MutationObserver & warning banner
│   ├── popup.html             # Popup dashboard UI
│   ├── popup.css              # Matte graphite & emerald-mint styling (Poppins)
│   ├── popup.js               # Popup controller (6-check matrix, Re-scan, JSON export)
│   ├── icons/                 # Borderless Gray Hat Person PNG icons (16/32/48/128 px)
│   └── src/
│       ├── domains.js         # Offline eTLD+1 suffixes, siblings, OAuth, 500+ trusted domains
│       ├── url_analyzer.js    # RFC 3492 Punycode, Levenshtein, combosquatting & DGA entropy
│       ├── dom_analyzer.js    # Forms, Shadow DOM, BitB, HTML smuggling, webhooks & iframes
│       └── risk_engine.js     # Weighted risk scoring (0–100), correlation & redirect engine
├── mock-server/
│   └── server.js              # Isolated localhost simulation server
├── scripts/
│   └── generate_icons.js      # Pure Node.js Gray Hat Person PNG icon generator
├── tests/
│   └── run_tests.js           # Automated verification suite (43 tests across 10 suites)
├── .gitignore
└── package.json
```

## Installing the Extension

### Google Chrome / Brave / Microsoft Edge
1. Open `chrome://extensions` (or `brave://extensions` / `edge://extensions`).
2. Enable **Developer mode**.
3. Click **Load unpacked**.
4. Select the `extension/` directory inside this repository.

### Mozilla Firefox
1. Open `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on...**.
3. Select `extension/manifest.json`.

## Local Testing & Verification

### 1. Run the Automated Verification Suite
Runs all **43 automated tests across 10 suites** (phishing URL detection, DOM/form inspection, BitB, HTML smuggling, Telegram/Discord webhooks, RFC 3492 Punycode, `< 5%` false positives across 35 popular safe sites, `< 50 ms` latency, and static privacy compliance checks):

```bash
npm test
```

### 2. Run the Isolated Localhost Simulation Lab
```bash
npm run mock-server
```

Open `http://localhost:8787` in a browser with PhishGuard Local loaded to safely test:
- `/safe` — Safe page
- `/login-http` — Unencrypted HTTP login form
- `/login-external` — External-domain login form
- `/login-raw-ip` — Raw IP login form
- `/deceptive-links` — Mismatched deceptive links
- `/redirect-1` — 4-hop redirect chain

### 3. Regenerate Toolbar Icons
```bash
npm run generate-icons
```

## Privacy & Security Guarantees
- **100% Offline & Client-Side**: All rules, Punycode decoding, and domain lists execute locally with zero remote API calls.
- **Zero Outbound Network Requests**: Verified statically to contain no `fetch`, `XMLHttpRequest`, `WebSocket`, or `sendBeacon` calls.
- **Passive Read-Only DOM**: Verified statically to never read `input.value`, never attach keystroke listeners, and never alter form submissions.
