# PhishGuard Local

**100% Local & Private Real-Time Browser Phishing Detection Extension**

PhishGuard Local is a **Manifest V3** browser extension (compatible with Google Chrome, Brave, Microsoft Edge, and Mozilla Firefox) that analyzes URLs, typosquatting/IDN homograph attacks, login form DOM structure, and redirect chains entirely client-side—without sending any browsing data to external servers.

## Key Features

1. **Homograph & Typosquatting Detection (`extension/src/url_analyzer.js`)**
   - Compares visited domains against a local list of protected brands using **Levenshtein distance** and visual confusable/leetspeak normalization (e.g., `paypa1.com`, `g00gle.com`, `klikbc4.com`).
   - Detects **IDN Homograph** attacks (Punycode `xn--` encoding and non-ASCII / mixed-script Unicode characters).
   - Flags subdomain brand spoofing (`paypal.com.evil.xyz`), URL `@` userinfo tricks, excessive subdomains, and direct raw IP access.

2. **Read-Only Login Form & Link Inspection (`extension/src/dom_analyzer.js`)**
   - Passively inspects `<form>` elements containing `<input type="password">` without ever reading password values (`.value`) or recording keystrokes.
   - Alerts when login forms submit credentials to external domains, raw IP addresses, unsafe URI schemes, or unencrypted HTTP endpoints.
   - Detects deceptive `<a>` links whose visible URL text mismatches the actual `href` destination.

3. **Redirect Chain Monitoring (`extension/background.js` & `extension/src/risk_engine.js`)**
   - Tracks main-frame navigation hops using `chrome.webNavigation` and `chrome.tabs`.
   - Flags unusual multi-hop and cross-domain redirect chains.

4. **Gray Hat Person Emblem, Risk Gauge & Warning Banner (`extension/popup.html`, `extension/content_script.js`)**
   - **Gray Hat Person Logo & Dynamic Toolbar Icons**:
     - **Green (Safe)**: No suspicious indicators detected.
     - **Amber (Caution)**: Moderate anomalies (e.g., HTTP login form or deceptive links).
     - **Red (High Risk)**: Strong phishing indicators (typosquatting, IDN homograph, or external credential submission).
   - **Shadow DOM Warning Banner**: Non-intrusive top-of-page alert with the Gray Hat Person emblem and one-click dismiss.
   - **Modern Popup Dashboard**: Features a radial risk score gauge, analysis latency pill (ms), categorized technical findings, hop-by-hop redirect trail, sensitivity presets (`Low`, `Medium`, `High`), and local **Whitelist** management via `chrome.storage.local`.

## Project Structure

```text
pishingdetect/
├── extension/
│   ├── manifest.json          # Manifest V3 configuration
│   ├── background.js          # Service Worker (navigation, redirects, icons, storage)
│   ├── content_script.js      # Read-only DOM inspector & Shadow DOM warning banner
│   ├── popup.html             # Popup UI (English US + Gray Hat Person logo)
│   ├── popup.css              # Popup styling
│   ├── popup.js               # Popup controller
│   ├── icons/                 # Gray Hat Person status icons (16/32/48/128 px)
│   └── src/
│       ├── domains.js         # Offline protected brand domain list
│       ├── url_analyzer.js    # Levenshtein distance & IDN homograph engine
│       ├── dom_analyzer.js    # Read-only DOM inspection engine
│       └── risk_engine.js     # Risk scoring, sensitivity, whitelist & redirect engine
├── mock-server/
│   └── server.js              # Isolated localhost simulation server
├── scripts/
│   └── generate_icons.js      # Local Gray Hat Person PNG icon generator
├── tests/
│   └── run_tests.js           # Automated verification suite
└── package.json
```

## Installing the Extension

### Google Chrome / Brave / Microsoft Edge
1. Open the extensions page (`chrome://extensions`, `brave://extensions`, or `edge://extensions`).
2. Enable **Developer mode**.
3. Click **Load unpacked**.
4. Select the `extension/` folder inside this repository.

### Mozilla Firefox
1. Open `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on...**.
3. Select `extension/manifest.json`.

## Local Testing

### 1. Run Automated Tests
Verifies phishing detection accuracy, false positive rate (< 5%), analysis latency (< 50 ms), and privacy compliance (zero outbound network calls & zero password `.value` reads):

```bash
npm test
```

### 2. Run the Localhost Simulation Lab
Start the isolated local mock server:

```bash
npm run mock-server
```

Then open `http://localhost:8787` in a browser with PhishGuard Local loaded to test:
- `/safe` — Safe page (Green)
- `/login-http` — Unencrypted HTTP login form (Amber)
- `/login-external` — External-domain login form (Red)
- `/login-raw-ip` — Raw IP login form (Red)
- `/deceptive-links` — Mismatched deceptive links (Amber)
- `/redirect-1` — 4-hop redirect chain (Amber)

## Privacy & Security Guarantees
- **100% Offline & Client-Side**: All detection logic and protected domain references run locally.
- **Zero Outbound Network Requests**: No `fetch`, `XMLHttpRequest`, `WebSocket`, or `sendBeacon` calls anywhere in the extension.
- **Passive Read-Only DOM**: Never reads password input values (`input.value`), never records keystrokes, and never alters form submissions.
