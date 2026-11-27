'use strict';

/**
 * PhishGuard Local - Advanced Read-Only DOM & Content Inspector
 * Passively inspects:
 *  1. Credential & Payment <form> targets (including open Shadow DOM), same-site eTLD+1,
 *     official siblings, OAuth/SSO allowlists, and crypto seed-phrase harvesting
 *  2. Deceptive <a> links (displayed URL vs actual href eTLD+1)
 *  3. Brand Impersonation (title, metadata, headings, logo alt) & Hotlinked Brand Favicons
 *  4. Suspicious Cross-Origin Overlay, Hidden, and data:/blob:/srcdoc <iframe> Elements
 *  5. Client-Side Credential Exfiltration Webhooks (Telegram/Discord), Untrusted Script Hosts,
 *     and Phishing Kit Obfuscation
 *
 * PRIVACY GUARANTEE: NEVER reads input field contents or records keystrokes.
 */
(function (root) {
  const domainData = (typeof module !== 'undefined' && module.exports)
    ? require('./domains.js')
    : root.PhishGuardDomains;
  const urlAnalyzer = (typeof module !== 'undefined' && module.exports)
    ? require('./url_analyzer.js')
    : root.PhishGuardUrlAnalyzer;

  const MAX_LINKS_TO_INSPECT = 200;
  const MAX_IFRAMES_TO_INSPECT = 40;
  const MAX_SCRIPTS_TO_INSPECT = 60;
  const MAX_INLINE_SCRIPT_CHARS = 8192;
  const MAX_SHADOW_ROOTS = 30;

  // High-value brand names mapped to their canonical protected domain for content impersonation checks
  const BRAND_CONTENT_MAP = [
    { pattern: /\bpaypal\b/i, domain: 'paypal.com', label: 'PayPal' },
    { pattern: /\bmicrosoft\b/i, domain: 'microsoft.com', label: 'Microsoft' },
    { pattern: /\boffice\s*365\b/i, domain: 'office.com', label: 'Microsoft Office 365' },
    { pattern: /\b(google\s+account|sign\s+in\s*[-–—]\s*google)\b/i, domain: 'google.com', label: 'Google' },
    { pattern: /\bapple\s+id\b/i, domain: 'apple.com', label: 'Apple' },
    { pattern: /\bicloud\b/i, domain: 'icloud.com', label: 'iCloud' },
    { pattern: /\bamazon\b/i, domain: 'amazon.com', label: 'Amazon' },
    { pattern: /\bklikbca\b/i, domain: 'klikbca.com', label: 'KlikBCA' },
    { pattern: /\bmybca\b/i, domain: 'bca.co.id', label: 'BCA' },
    { pattern: /\bbank\s+mandiri\b/i, domain: 'bankmandiri.co.id', label: 'Bank Mandiri' },
    { pattern: /\bbrimo\b/i, domain: 'bri.co.id', label: 'BRI / BRImo' },
    { pattern: /\bbni\s+mobile\b/i, domain: 'bni.co.id', label: 'BNI' },
    { pattern: /\bfacebook\b/i, domain: 'facebook.com', label: 'Facebook' },
    { pattern: /\binstagram\b/i, domain: 'instagram.com', label: 'Instagram' },
    { pattern: /\bnetflix\b/i, domain: 'netflix.com', label: 'Netflix' },
    { pattern: /\bbinance\b/i, domain: 'binance.com', label: 'Binance' },
    { pattern: /\bcoinbase\b/i, domain: 'coinbase.com', label: 'Coinbase' },
    { pattern: /\bmetamask\b/i, domain: 'metamask.io', label: 'MetaMask' },
    { pattern: /\bgithub\b/i, domain: 'github.com', label: 'GitHub' },
    { pattern: /\bdropbox\b/i, domain: 'dropbox.com', label: 'Dropbox' },
    { pattern: /\bdocusign\b/i, domain: 'docusign.com', label: 'DocuSign' },
    { pattern: /\bsteam\b/i, domain: 'steampowered.com', label: 'Steam' },
    { pattern: /\bdiscord\b/i, domain: 'discord.com', label: 'Discord' },
    { pattern: /\bchase\b/i, domain: 'chase.com', label: 'Chase' },
    { pattern: /\b(dhl|fedex|usps)\b/i, domain: 'dhl.com', label: 'Courier / Delivery' },
    { pattern: /\btokopedia\b/i, domain: 'tokopedia.com', label: 'Tokopedia' },
    { pattern: /\bshopee\b/i, domain: 'shopee.co.id', label: 'Shopee' },
    { pattern: /\bgojek\b/i, domain: 'gojek.com', label: 'Gojek' }
  ];

  const SUSPICIOUS_TLDS = (domainData && domainData.SUSPICIOUS_TLDS) || new Set();
  const FREE_HOSTING_SUFFIXES = (domainData && domainData.FREE_HOSTING_SUFFIXES) || new Set();
  const KNOWN_PAYMENT_PROCESSORS = (domainData && domainData.KNOWN_PAYMENT_PROCESSORS) || new Set();

  const SEED_PHRASE_PATTERN = /\b(seed\s*phrase|recovery\s*phrase|secret\s*recovery|mnemonic|12[\s-]*(word|phrase)|24[\s-]*(word|phrase)|private\s*key)\b/i;
  const BITB_URL_PATTERN = /^https?:\/\/(accounts\.google\.com|login\.microsoftonline\.com|login\.live\.com|appleid\.apple\.com|github\.com\/login|www\.paypal\.com\/signin|www\.facebook\.com\/login|id\.atlassian\.com)/i;
  const DANGEROUS_DOWNLOAD_EXT = /\.(html?|svg|iso|img|zip|rar|7z|exe|msi|lnk|js|jse|vbs|hta|bat|cmd|ps1|scr)$/i;
  const URGENCY_LURE_PATTERN = /\b(account\s+(will\s+be\s+)?(suspended|locked|disabled|terminated|restricted)|verify\s+(your\s+)?(identity|account)\s+within\s+\d+\s*(hours?|mins?|minutes?)|unusual\s+sign[\s-]?in\s+activity|unauthorized\s+access\s+detected|confirm\s+your\s+billing\s+immediately|akun\s+(anda\s+)?(akan\s+)?(diblokir|ditangguhkan)|verifikasi\s+segera)\b/i;

  /**
   * Collect Document + bounded open Shadow Roots (up to depth 2) to inspect web-component login forms.
   */
  function collectInspectableRoots(doc) {
    const roots = [doc];
    if (!doc || typeof doc.querySelectorAll !== 'function') return roots;

    const queue = [{ root: doc, depth: 0 }];
    while (queue.length > 0 && roots.length < MAX_SHADOW_ROOTS) {
      const current = queue.shift();
      if (current.depth >= 2) continue;
      const allEls = current.root.querySelectorAll('*');
      const scanCap = Math.min(allEls.length, 400);
      for (let i = 0; i < scanCap && roots.length < MAX_SHADOW_ROOTS; i++) {
        const el = allEls[i];
        if (el.shadowRoot && el.id !== 'phishguard-local-banner-host') {
          roots.push(el.shadowRoot);
          queue.push({ root: el.shadowRoot, depth: current.depth + 1 });
        }
      }
    }
    return roots;
  }

  function queryAllAcrossRoots(roots, selector) {
    const out = [];
    for (let i = 0; i < roots.length; i++) {
      const found = roots[i].querySelectorAll(selector);
      for (let j = 0; j < found.length; j++) {
        out.push(found[j]);
      }
    }
    return out;
  }

  function elementLooksLikeSeedInput(el) {
    const meta = [
      el.getAttribute('name') || '',
      el.getAttribute('id') || '',
      el.getAttribute('placeholder') || '',
      el.getAttribute('aria-label') || ''
    ].join(' ');
    return SEED_PHRASE_PATTERN.test(meta);
  }

  /**
   * Extract a read-only snapshot from a live browser Document.
   * Strictly avoids reading input field contents.
   */
  function extractDomSnapshot(doc, pageUrl) {
    const roots = collectInspectableRoots(doc);
    const forms = [];
    const formElements = queryAllAcrossRoots(roots, 'form');
    let passwordInputsInForms = 0;

    for (let i = 0; i < formElements.length; i++) {
      const form = formElements[i];
      const pwInputs = form.querySelectorAll('input[type="password"]');
      const credAutoInputs = form.querySelectorAll(
        'input[autocomplete="current-password"], input[autocomplete="new-password"]'
      );
      const ccInputs = form.querySelectorAll(
        'input[autocomplete="cc-number"], input[autocomplete="cc-csc"], input[name*="cardnumber" i], input[name*="cvv" i], input[name*="cvc" i]'
      );
      const hasPassword = pwInputs.length > 0 || credAutoInputs.length > 0;
      const hasCreditCard = ccInputs.length > 0;
      const method = (form.getAttribute('method') || 'GET').toUpperCase();
      const rawAction = form.getAttribute('action') || '';
      const hasJsSubmit = Boolean(form.getAttribute('onsubmit')) || /^javascript:/i.test(rawAction.trim());

      if (hasPassword || hasCreditCard) {
        passwordInputsInForms += pwInputs.length;
        forms.push({
          action: rawAction,
          method,
          hasPassword,
          hasCreditCard,
          hasJsSubmit
        });
      }
    }

    const totalPasswordInputs = queryAllAcrossRoots(roots, 'input[type="password"]').length;
    const hasPasswordInputOutsideForm = totalPasswordInputs > passwordInputsInForms;

    // Seed / recovery phrase harvesting check (passive attribute inspection only)
    let hasSeedPhraseHarvest = false;
    const seedCandidates = queryAllAcrossRoots(roots, 'textarea, input[type="text"], input:not([type])');
    const seedCap = Math.min(seedCandidates.length, 60);
    for (let i = 0; i < seedCap; i++) {
      if (elementLooksLikeSeedInput(seedCandidates[i])) {
        hasSeedPhraseHarvest = true;
        break;
      }
    }

    // Anchor links: URL-text mismatch & HTML smuggling data:/blob: download traps
    const links = [];
    let hasSmugglingDownloadLink = false;
    const anchorElements = doc.querySelectorAll('a[href]');
    const linkLimit = Math.min(anchorElements.length, MAX_LINKS_TO_INSPECT);
    for (let i = 0; i < linkLimit; i++) {
      const a = anchorElements[i];
      const href = (a.getAttribute('href') || '').trim();
      const downloadAttr = a.getAttribute('download');
      if (
        !hasSmugglingDownloadLink &&
        downloadAttr !== null &&
        /^(data|blob):/i.test(href) &&
        (!downloadAttr || DANGEROUS_DOWNLOAD_EXT.test(downloadAttr.trim()))
      ) {
        hasSmugglingDownloadLink = true;
      }

      const text = (a.textContent || '').trim();
      if (!text || text.length > 160) continue;
      if (/^(https?:\/\/|www\.)/i.test(text)) {
        links.push({ text, href });
      }
    }

    // Stealth <meta http-equiv="refresh" content="0;url=..."> redirect check
    let metaRefreshUrl = '';
    const refreshMeta = doc.querySelector('meta[http-equiv="refresh" i][content]');
    if (refreshMeta) {
      const content = refreshMeta.getAttribute('content') || '';
      const match = content.match(/url\s*=\s*['"]?([^'";\s]+)/i);
      if (match && match[1]) {
        metaRefreshUrl = match[1].trim();
      }
    }

    // Browser-in-the-Browser (BitB) fake address bar detection (only when password inputs exist)
    let bitbSpoofedUrl = '';
    if (totalPasswordInputs > 0) {
      const barCandidates = queryAllAcrossRoots(roots, 'div, span, p, header');
      const barCap = Math.min(barCandidates.length, 250);
      for (let i = 0; i < barCap; i++) {
        const el = barCandidates[i];
        if (el.childElementCount > 2) continue;
        const txt = (el.textContent || '').trim();
        if (txt.length >= 18 && txt.length <= 140 && BITB_URL_PATTERN.test(txt)) {
          bitbSpoofedUrl = txt;
          break;
        }
      }
    }

    // Social engineering urgency lure scan (bounded text snippet on pages with password inputs)
    let hasUrgencyLure = false;
    if (totalPasswordInputs > 0 && doc.body) {
      const bodySnippet = (doc.body.textContent || '').slice(0, 3000);
      hasUrgencyLure = URGENCY_LURE_PATTERN.test(bodySnippet);
    }

    // Page title, metadata, headings, logo alts, and favicons for Brand Impersonation checks
    const title = (doc.title || '').trim().slice(0, 200);
    const ogSiteEl = doc.querySelector('meta[property="og:site_name"], meta[name="application-name"]');
    const siteName = ogSiteEl ? (ogSiteEl.getAttribute('content') || '').trim().slice(0, 120) : '';

    const headingTexts = [];
    const headingEls = doc.querySelectorAll('h1, h2');
    for (let i = 0; i < Math.min(headingEls.length, 3); i++) {
      const txt = (headingEls[i].textContent || '').trim().slice(0, 120);
      if (txt) headingTexts.push(txt);
    }

    const logoAlts = [];
    const imgEls = doc.querySelectorAll('img[alt]');
    for (let i = 0; i < Math.min(imgEls.length, 10); i++) {
      const alt = (imgEls[i].getAttribute('alt') || '').trim().slice(0, 80);
      const src = (imgEls[i].getAttribute('src') || '').toLowerCase();
      if (alt && (/logo|brand|icon|header/i.test(alt) || /logo|brand/i.test(src))) {
        logoAlts.push(alt);
      }
    }

    const favicons = [];
    const iconEls = doc.querySelectorAll('link[rel*="icon"][href]');
    for (let i = 0; i < Math.min(iconEls.length, 5); i++) {
      const href = (iconEls[i].getAttribute('href') || '').trim();
      if (href) favicons.push(href);
    }

    // Iframes for clickjacking, hidden-frame, and data:/blob:/srcdoc checks
    const iframes = [];
    const iframeEls = queryAllAcrossRoots(roots, 'iframe');
    const iframeLimit = Math.min(iframeEls.length, MAX_IFRAMES_TO_INSPECT);
    const view = doc.defaultView;
    for (let i = 0; i < iframeLimit; i++) {
      const fr = iframeEls[i];
      const src = (fr.getAttribute('src') || '').trim();
      const hasSrcdoc = fr.hasAttribute('srcdoc');
      const style = (fr.getAttribute('style') || '').toLowerCase();
      const widthAttr = Number(fr.getAttribute('width'));
      const heightAttr = Number(fr.getAttribute('height'));
      let computedHidden = false;
      let computedOverlay = false;

      if (view && typeof view.getComputedStyle === 'function') {
        try {
          const cs = view.getComputedStyle(fr);
          const op = parseFloat(cs.opacity);
          const cw = parseFloat(cs.width);
          const ch = parseFloat(cs.height);
          const zi = parseInt(cs.zIndex, 10);
          computedHidden = cs.visibility === 'hidden' ||
            cs.display === 'none' ||
            (Number.isFinite(op) && op === 0) ||
            (Number.isFinite(cw) && cw <= 2 && Number.isFinite(ch) && ch <= 2);
          computedOverlay = (cs.position === 'fixed' || cs.position === 'absolute') &&
            ((Number.isFinite(zi) && zi >= 1000) || (Number.isFinite(cw) && cw >= (view.innerWidth || 800) * 0.85));
        } catch (_err) {
          // ignore computedStyle failure
        }
      }

      const hidden = computedHidden ||
        Boolean(fr.hasAttribute('hidden')) ||
        /opacity\s*:\s*0(\.0+)?\b/.test(style) ||
        /visibility\s*:\s*hidden/.test(style) ||
        (Number.isFinite(widthAttr) && widthAttr <= 2 && Number.isFinite(heightAttr) && heightAttr <= 2);
      const isOverlay = computedOverlay || (
        /position\s*:\s*(fixed|absolute)/.test(style) &&
        (/z-index\s*:\s*\d{4,}/.test(style) || /width\s*:\s*100(vw|%)/.test(style))
      );
      iframes.push({ src, hasSrcdoc, hidden, isOverlay });
    }

    // Script sources, inline phishing-kit obfuscation, HTML smuggling, and Telegram/Discord exfiltration
    const scripts = [];
    const scriptEls = doc.querySelectorAll('script');
    const scriptLimit = Math.min(scriptEls.length, MAX_SCRIPTS_TO_INSPECT);
    let hasObfuscatedInlineScript = false;
    let hasHtmlSmugglingScript = false;
    let exfilWebhookProvider = null;

    for (let i = 0; i < scriptLimit; i++) {
      const sc = scriptEls[i];
      const src = (sc.getAttribute('src') || '').trim();
      if (src) {
        scripts.push({ src });
      } else {
        const code = (sc.textContent || '').slice(0, MAX_INLINE_SCRIPT_CHARS);
        if (!exfilWebhookProvider) {
          if (/api\.telegram\.org\/bot/i.test(code)) {
            exfilWebhookProvider = 'Telegram Bot API';
          } else if (/discord(?:app)?\.com\/api\/webhooks\//i.test(code)) {
            exfilWebhookProvider = 'Discord Webhook';
          }
        }
        if (
          !hasHtmlSmugglingScript &&
          /\bnew\s+Blob\s*\(/i.test(code) &&
          /\bcreateObjectURL\s*\(/i.test(code) &&
          (/\batob\s*\(/i.test(code) || /\bUint8Array\b/.test(code)) &&
          (/\.download\s*=|msSaveOrOpenBlob/i.test(code))
        ) {
          hasHtmlSmugglingScript = true;
        }
        if (!hasObfuscatedInlineScript) {
          if (
            /\b(eval|Function)\s*\(\s*(atob|unescape|decodeURIComponent)\s*\(/i.test(code) ||
            /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)/i.test(code) ||
            /String\.fromCharCode\s*\((?:\s*\d+\s*,){12,}/i.test(code) ||
            /document\.write\s*\(\s*unescape\s*\(/i.test(code)
          ) {
            hasObfuscatedInlineScript = true;
          }
        }
      }
    }

    // Anti-inspection check (disabling context menu on untrusted login pages)
    const bodyEl = doc.body;
    const blocksContextMenu = Boolean(
      (bodyEl && /return\s+false/i.test(bodyEl.getAttribute('oncontextmenu') || '')) ||
      (doc.documentElement && /return\s+false/i.test(doc.documentElement.getAttribute('oncontextmenu') || ''))
    );

    return {
      pageUrl,
      title,
      siteName,
      headingTexts,
      logoAlts,
      favicons,
      forms,
      totalPasswordInputs,
      hasPasswordInputOutsideForm,
      hasSeedPhraseHarvest,
      hasSmugglingDownloadLink,
      metaRefreshUrl,
      bitbSpoofedUrl,
      hasUrgencyLure,
      links,
      totalLinks: anchorElements.length,
      iframes,
      scripts,
      totalScripts: scriptEls.length,
      hasObfuscatedInlineScript,
      hasHtmlSmugglingScript,
      exfilWebhookProvider,
      blocksContextMenu
    };
  }

  /**
   * Analyze a read-only DOM snapshot across Form/DOM, Brand/Favicon, Iframe, and Script heuristics.
   */
  function analyzeDomSnapshot(snapshot) {
    const findings = [];
    const emptyStats = {
      loginForms: 0,
      inspectedLinks: 0,
      totalLinks: 0,
      sameSiteForms: 0,
      oauthForms: 0,
      iframes: 0,
      scripts: 0,
      totalScripts: 0
    };

    if (!snapshot || !snapshot.pageUrl) {
      return { findings, stats: emptyStats };
    }

    let pageParsed;
    try {
      pageParsed = new URL(snapshot.pageUrl);
    } catch (_err) {
      return { findings, stats: emptyStats };
    }

    const pageHost = pageParsed.hostname.toLowerCase();
    const pageParts = urlAnalyzer.parseDomainParts(pageHost);
    const pageIsLoopback = urlAnalyzer.isLoopbackHost(pageHost);
    const pageIsTrusted = urlAnalyzer.isTrustedDomain(pageHost);
    const pageIsFreeHosting = FREE_HOSTING_SUFFIXES.has(pageParts.tld);
    const forms = snapshot.forms || [];
    const hasAnyPassword = forms.some((f) => f.hasPassword) ||
      Boolean(snapshot.hasPasswordInputOutsideForm) ||
      (snapshot.totalPasswordInputs || 0) > 0;

    let hasFlaggedHttpLogin = false;
    let sameSiteForms = 0;
    let oauthForms = 0;

    // --- 1. Credential & Payment Form Inspection (category: 'dom') ---
    for (let i = 0; i < forms.length; i++) {
      const form = forms[i];
      if (!form.hasPassword && !form.hasCreditCard) continue;

      const method = (form.method || 'GET').toUpperCase();
      const rawAction = (form.action || '').trim();
      const isCredentialSubmission = method === 'POST' || Boolean(form.hasJsSubmit) || Boolean(form.hasPassword);

      if (!isCredentialSubmission && !form.hasCreditCard && method === 'GET' && (pageParsed.protocol === 'https:' || pageIsLoopback)) {
        continue;
      }

      if (/^(javascript|data|vbscript|blob):/i.test(rawAction)) {
        findings.push({
          id: 'FORM_DANGEROUS_SCHEME',
          category: 'dom',
          severity: 'high',
          score: 60,
          title: 'Login Form Uses Unsafe Target Scheme',
          detail: `Credential form on eTLD+1 "${pageParts.registrableDomain}" targets "${rawAction.split(':')[0]}:" scheme (+60).`
        });
        continue;
      }

      let actionUrl;
      try {
        actionUrl = new URL(rawAction || '', pageParsed.href);
      } catch (_err) {
        continue;
      }

      const actionHost = actionUrl.hostname.toLowerCase();
      const actionParts = urlAnalyzer.parseDomainParts(actionHost);
      const isActionRawIp = urlAnalyzer.isIPv4(actionHost) || urlAnalyzer.isIPv6(actionHost);
      const isActionLoopback = urlAnalyzer.isLoopbackHost(actionHost);
      const isSameSite = urlAnalyzer.areSameSiteOrSibling(pageHost, actionHost);
      const isOAuthTarget = !isSameSite && urlAnalyzer.isKnownOAuthProvider(actionUrl.href);
      const isPaymentProcessor = !isSameSite && KNOWN_PAYMENT_PROCESSORS.has(actionParts.registrableDomain);

      if (isSameSite) {
        sameSiteForms++;
      } else if (isOAuthTarget) {
        oauthForms++;
      }

      if (isActionRawIp && (!isActionLoopback || actionHost !== pageHost)) {
        findings.push({
          id: 'FORM_ACTION_RAW_IP',
          category: 'dom',
          severity: 'high',
          score: 75,
          title: 'Login Form Submits to Raw IP Address',
          detail: `Page eTLD+1 "${pageParts.registrableDomain}" submits sensitive form data to raw IP "${actionUrl.origin}${actionUrl.pathname}" (+75).`
        });
      } else if (
        form.hasPassword &&
        !isSameSite &&
        !isOAuthTarget &&
        actionParts.registrableDomain &&
        pageParts.registrableDomain &&
        (method === 'POST' || Boolean(form.hasJsSubmit))
      ) {
        findings.push({
          id: 'FORM_ACTION_EXTERNAL_DOMAIN',
          category: 'dom',
          severity: 'high',
          score: 70,
          title: 'Login Form Submits to External Domain',
          detail: `Page eTLD+1 "${pageParts.registrableDomain}" submits credentials to unrelated eTLD+1 "${actionParts.registrableDomain}" (${actionUrl.origin}, +70).`
        });
      } else if (
        form.hasCreditCard &&
        !isSameSite &&
        !isPaymentProcessor &&
        actionParts.registrableDomain &&
        pageParts.registrableDomain &&
        (method === 'POST' || Boolean(form.hasJsSubmit))
      ) {
        findings.push({
          id: 'PAYMENT_FORM_EXTERNAL_DOMAIN',
          category: 'dom',
          severity: 'high',
          score: 70,
          title: 'Payment Form Submits to Unrecognized Domain',
          detail: `Credit card form on "${pageParts.registrableDomain}" submits to unrecognized external eTLD+1 "${actionParts.registrableDomain}" (+70).`
        });
      }

      if (actionUrl.protocol === 'http:') {
        hasFlaggedHttpLogin = true;
        const isPublicHttp = !isActionLoopback && !pageIsLoopback;
        const score = form.hasCreditCard && isPublicHttp ? 65 : (isPublicHttp ? 60 : 35);
        const severity = isPublicHttp ? 'high' : 'medium';
        findings.push({
          id: form.hasCreditCard && !form.hasPassword ? 'PAYMENT_FORM_INSECURE_HTTP' : 'FORM_ACTION_INSECURE_HTTP',
          category: 'dom',
          severity,
          score,
          title: form.hasCreditCard && !form.hasPassword
            ? 'Unencrypted HTTP Credit Card Form'
            : 'Unencrypted HTTP Login Form',
          detail: `Sensitive form targets plaintext HTTP (${actionUrl.origin}, eTLD+1 "${actionParts.registrableDomain}", +${score}).`
        });
      }
    }

    if (snapshot.hasPasswordInputOutsideForm && pageParsed.protocol === 'http:' && !hasFlaggedHttpLogin) {
      const score = pageIsLoopback ? 35 : 60;
      const severity = pageIsLoopback ? 'medium' : 'high';
      findings.push({
        id: 'PAGE_PASSWORD_INSECURE_HTTP',
        category: 'dom',
        severity,
        score,
        title: 'Password Input on Unencrypted HTTP Page',
        detail: `Page eTLD+1 "${pageParts.registrableDomain}" renders a password input over plaintext HTTP without TLS (+${score}).`
      });
    }

    // Crypto wallet seed/recovery phrase harvesting on untrusted domains
    if (snapshot.hasSeedPhraseHarvest && !pageIsTrusted && !pageIsLoopback) {
      findings.push({
        id: 'CRYPTO_SEED_PHRASE_HARVEST',
        category: 'dom',
        severity: 'high',
        score: 65,
        title: 'Crypto Seed / Recovery Phrase Input on Untrusted Site',
        detail: `Untrusted eTLD+1 "${pageParts.registrableDomain}" requests a wallet seed or recovery phrase (+65).`
      });
    }

    // Password login form hosted on shared free-hosting suffix (pages.dev, vercel.app, web.app, github.io, etc.)
    if (hasAnyPassword && pageIsFreeHosting && !pageIsTrusted) {
      findings.push({
        id: 'FREE_HOSTING_LOGIN_FORM',
        category: 'dom',
        severity: 'medium',
        score: 25,
        title: `Password Form on Shared Free Hosting (.${pageParts.tld})`,
        detail: `Login page is hosted on free public hosting "${pageParts.registrableDomain}", frequently abused for disposable phishing sites (+25).`
      });
    }

    // --- 2. Deceptive <a> Links (category: 'dom') ---
    const links = snapshot.links || [];
    let deceptiveLinkCount = 0;
    let sampleDeceptive = null;

    for (let i = 0; i < links.length; i++) {
      const link = links[i];
      if (!link.text || !link.href) continue;

      let textUrl;
      let hrefUrl;
      try {
        const normalizedText = /^https?:\/\//i.test(link.text) ? link.text : 'https://' + link.text;
        textUrl = new URL(normalizedText);
        hrefUrl = new URL(link.href, pageParsed.href);
      } catch (_err) {
        continue;
      }

      if (hrefUrl.protocol !== 'http:' && hrefUrl.protocol !== 'https:') continue;

      if (!urlAnalyzer.areSameSiteOrSibling(textUrl.hostname, hrefUrl.hostname)) {
        const textParts = urlAnalyzer.parseDomainParts(textUrl.hostname);
        const hrefParts = urlAnalyzer.parseDomainParts(hrefUrl.hostname);
        if (textParts.registrableDomain && hrefParts.registrableDomain) {
          deceptiveLinkCount++;
          if (!sampleDeceptive) {
            sampleDeceptive = {
              displayed: textParts.registrableDomain,
              actual: hrefParts.registrableDomain
            };
          }
        }
      }
    }

    if (deceptiveLinkCount > 0 && sampleDeceptive) {
      findings.push({
        id: 'DECEPTIVE_LINK_MISMATCH',
        category: 'dom',
        severity: 'medium',
        score: 40,
        title: 'Deceptive Mismatched Links Detected',
        detail: `Found ${deceptiveLinkCount} ${deceptiveLinkCount === 1 ? 'link' : 'links'} displaying eTLD+1 "${sampleDeceptive.displayed}" while targeting "${sampleDeceptive.actual}" (+40).`
      });
    }

    // --- 3. Brand Impersonation & Hotlinked Brand Favicon (category: 'brand') ---
    if (!pageIsTrusted && !pageIsLoopback) {
      const brandText = [
        snapshot.title || '',
        snapshot.siteName || '',
        ...((snapshot.headingTexts || []).slice(0, 3)),
        ...((snapshot.logoAlts || []).slice(0, 5))
      ].join(' ');

      if ((hasAnyPassword || snapshot.hasSeedPhraseHarvest) && brandText.trim()) {
        for (const brand of BRAND_CONTENT_MAP) {
          if (
            brand.pattern.test(brandText) &&
            !urlAnalyzer.areSameSiteOrSibling(pageHost, brand.domain)
          ) {
            findings.push({
              id: 'BRAND_IMPERSONATION_CONTENT',
              category: 'brand',
              severity: 'high',
              score: 55,
              title: `Brand Impersonation Detected (${brand.label})`,
              detail: `Credential page claims "${brand.label}" in title/headings/logo while hosted on unrelated eTLD+1 "${pageParts.registrableDomain}" (+55).`
            });
            break;
          }
        }
      }

      // Browser-in-the-Browser (BitB) fake address bar inside untrusted login page
      if (snapshot.bitbSpoofedUrl) {
        try {
          const fakeBarUrl = new URL(snapshot.bitbSpoofedUrl);
          if (!urlAnalyzer.areSameSiteOrSibling(pageHost, fakeBarUrl.hostname)) {
            findings.push({
              id: 'BITB_FAKE_ADDRESS_BAR',
              category: 'brand',
              severity: 'high',
              score: 75,
              title: 'Browser-in-the-Browser (BitB) Fake Address Bar',
              detail: `Untrusted login page "${pageParts.registrableDomain}" renders a spoofed address bar displaying "${fakeBarUrl.hostname}" (+75).`
            });
          }
        } catch (_err) {
          // ignore malformed fake bar URL
        }
      }

      // Social engineering urgency pressure on untrusted login page
      if (hasAnyPassword && snapshot.hasUrgencyLure) {
        findings.push({
          id: 'URGENCY_CREDENTIAL_LURE',
          category: 'brand',
          severity: 'medium',
          score: 20,
          title: 'Urgency / Account-Suspension Lure on Login Page',
          detail: `Untrusted login page "${pageParts.registrableDomain}" uses high-pressure account-suspension or urgent verification wording (+20).`
        });
      }

      const favicons = snapshot.favicons || [];
      for (const fav of favicons) {
        try {
          const favUrl = new URL(fav, pageParsed.href);
          if (favUrl.protocol !== 'http:' && favUrl.protocol !== 'https:') continue;
          const favHost = favUrl.hostname.toLowerCase();
          if (
            !urlAnalyzer.areSameSiteOrSibling(pageHost, favHost) &&
            urlAnalyzer.isTrustedDomain(favHost)
          ) {
            const favParts = urlAnalyzer.parseDomainParts(favHost);
            findings.push({
              id: 'HOTLINKED_BRAND_FAVICON',
              category: 'brand',
              severity: 'high',
              score: 45,
              title: `Hotlinked Brand Favicon (${favParts.registrableDomain})`,
              detail: `Untrusted eTLD+1 "${pageParts.registrableDomain}" hotlinks its favicon from "${favParts.registrableDomain}" — a classic phishing kit indicator (+45).`
            });
            break;
          }
        } catch (_err) {
          // ignore malformed favicon URL
        }
      }
    }

    // --- 4. Iframe & Overlay Security (category: 'iframe') ---
    const iframes = snapshot.iframes || [];
    if (!pageIsTrusted) {
      let flaggedOverlay = false;
      let flaggedHidden = false;
      let flaggedScheme = false;

      for (const fr of iframes) {
        if (!flaggedScheme && ((fr.src && /^(data|blob|javascript):/i.test(fr.src)) || (fr.hasSrcdoc && fr.isOverlay))) {
          flaggedScheme = true;
          findings.push({
            id: 'SUSPICIOUS_IFRAME_SCHEME',
            category: 'iframe',
            severity: 'high',
            score: 45,
            title: 'Inline Data/Blob/Srcdoc Iframe on Untrusted Page',
            detail: `Untrusted eTLD+1 "${pageParts.registrableDomain}" embeds an inline data:/blob:/srcdoc iframe often used to disguise phishing overlays (+45).`
          });
          continue;
        }

        if (!fr.src) continue;
        let frUrl;
        try {
          frUrl = new URL(fr.src, pageParsed.href);
        } catch (_err) {
          continue;
        }
        if (frUrl.protocol !== 'http:' && frUrl.protocol !== 'https:') continue;
        const frHost = frUrl.hostname.toLowerCase();
        const isSameOrTrusted = urlAnalyzer.areSameSiteOrSibling(pageHost, frHost) ||
          urlAnalyzer.isTrustedDomain(frHost) ||
          urlAnalyzer.isKnownOAuthProvider(frUrl.href);

        if (!isSameOrTrusted) {
          const frParts = urlAnalyzer.parseDomainParts(frHost);
          if (fr.isOverlay && !flaggedOverlay) {
            flaggedOverlay = true;
            findings.push({
              id: 'SUSPICIOUS_OVERLAY_IFRAME',
              category: 'iframe',
              severity: 'high',
              score: 40,
              title: 'Suspicious Cross-Origin Overlay Iframe',
              detail: `Full-screen or high-z-index iframe loads untrusted eTLD+1 "${frParts.registrableDomain}" over "${pageParts.registrableDomain}" (+40).`
            });
          } else if (fr.hidden && !flaggedHidden) {
            flaggedHidden = true;
            findings.push({
              id: 'HIDDEN_UNTRUSTED_IFRAME',
              category: 'iframe',
              severity: 'medium',
              score: 25,
              title: 'Hidden Cross-Origin Iframe Detected',
              detail: `Invisible/zero-pixel iframe points to untrusted eTLD+1 "${frParts.registrableDomain}" (+25).`
            });
          }
        }
      }
    }

    // --- 5. Script & Obfuscation Audit (category: 'script') ---
    const scripts = snapshot.scripts || [];
    if (!pageIsTrusted) {
      if (snapshot.exfilWebhookProvider) {
        findings.push({
          id: 'CREDENTIAL_EXFIL_WEBHOOK',
          category: 'script',
          severity: 'high',
          score: 80,
          title: `Client-Side ${snapshot.exfilWebhookProvider} Exfiltration Detected`,
          detail: `Inline script on untrusted eTLD+1 "${pageParts.registrableDomain}" references ${snapshot.exfilWebhookProvider}, a hallmark of phishing credential-stealing kits (+80).`
        });
      }

      if (snapshot.hasHtmlSmugglingScript || snapshot.hasSmugglingDownloadLink) {
        findings.push({
          id: 'HTML_SMUGGLING_DOWNLOAD',
          category: 'script',
          severity: 'high',
          score: 65,
          title: 'HTML Smuggling / Client-Side Payload Drop Detected',
          detail: `Untrusted eTLD+1 "${pageParts.registrableDomain}" uses ${snapshot.hasHtmlSmugglingScript ? 'Base64/Blob createObjectURL download smuggling' : 'a data:/blob: download trap link'} (+65).`
        });
      }

      // Stealth <meta http-equiv="refresh"> redirect to untrusted external domain
      if (snapshot.metaRefreshUrl) {
        try {
          const refUrl = new URL(snapshot.metaRefreshUrl, pageParsed.href);
          if (refUrl.protocol === 'http:' || refUrl.protocol === 'https:') {
            const refHost = refUrl.hostname.toLowerCase();
            const isSafeTarget = urlAnalyzer.areSameSiteOrSibling(pageHost, refHost) ||
              urlAnalyzer.isTrustedDomain(refHost) ||
              urlAnalyzer.isKnownOAuthProvider(refUrl.href);
            if (!isSafeTarget) {
              const refParts = urlAnalyzer.parseDomainParts(refHost);
              const refIsRawIp = (urlAnalyzer.isIPv4(refHost) || urlAnalyzer.isIPv6(refHost)) && !urlAnalyzer.isLoopbackHost(refHost);
              const highRisk = refIsRawIp || SUSPICIOUS_TLDS.has(refParts.tld);
              const score = highRisk ? 45 : 25;
              findings.push({
                id: 'META_REFRESH_EXTERNAL',
                category: 'redirect',
                severity: highRisk ? 'high' : 'medium',
                score,
                title: 'Stealth Meta-Refresh External Redirect',
                detail: `Page uses <meta http-equiv="refresh"> to jump from "${pageParts.registrableDomain}" to untrusted "${refParts.registrableDomain}" (+${score}).`
              });
            }
          }
        } catch (_err) {
          // ignore malformed meta refresh target
        }
      }

      if (hasAnyPassword && snapshot.hasObfuscatedInlineScript) {
        findings.push({
          id: 'OBFUSCATED_PHISHING_SCRIPT',
          category: 'script',
          severity: 'high',
          score: 40,
          title: 'Obfuscated Inline Script on Login Page',
          detail: `Detected eval/atob/fromCharCode script obfuscation on an untrusted login page ("${pageParts.registrableDomain}", +40).`
        });
      }

      if (hasAnyPassword && snapshot.blocksContextMenu) {
        findings.push({
          id: 'ANTI_INSPECTION_LOGIN',
          category: 'script',
          severity: 'medium',
          score: 20,
          title: 'Anti-Inspection Right-Click Block on Login Page',
          detail: `Untrusted login page ("${pageParts.registrableDomain}") disables context menu inspection (+20).`
        });
      }

      if (hasAnyPassword) {
        for (const sc of scripts) {
          if (!sc.src) continue;
          let scUrl;
          try {
            scUrl = new URL(sc.src, pageParsed.href);
          } catch (_err) {
            continue;
          }
          if (scUrl.protocol !== 'http:' && scUrl.protocol !== 'https:') continue;
          const scHost = scUrl.hostname.toLowerCase();
          if (urlAnalyzer.areSameSiteOrSibling(pageHost, scHost) || urlAnalyzer.isTrustedDomain(scHost)) {
            continue;
          }
          const scParts = urlAnalyzer.parseDomainParts(scHost);
          const isRawIp = (urlAnalyzer.isIPv4(scHost) || urlAnalyzer.isIPv6(scHost)) && !urlAnalyzer.isLoopbackHost(scHost);
          const isSuspiciousTld = SUSPICIOUS_TLDS.has(scParts.tld);

          if (isRawIp || isSuspiciousTld) {
            findings.push({
              id: 'UNTRUSTED_SCRIPT_SOURCE',
              category: 'script',
              severity: 'medium',
              score: 35,
              title: 'Suspicious External Script on Login Page',
              detail: `Login page loads external script from ${isRawIp ? `raw IP "${scHost}"` : `high-risk TLD domain "${scParts.registrableDomain}"`} (+35).`
            });
            break;
          }
        }
      }
    }

    return {
      findings,
      stats: {
        loginForms: forms.length,
        inspectedLinks: links.length,
        totalLinks: typeof snapshot.totalLinks === 'number' ? snapshot.totalLinks : links.length,
        sameSiteForms,
        oauthForms,
        iframes: iframes.length,
        scripts: scripts.length,
        totalScripts: typeof snapshot.totalScripts === 'number' ? snapshot.totalScripts : scripts.length
      }
    };
  }

  /**
   * Convenience wrapper for live browser Documents.
   */
  function analyzeDocument(doc, pageUrl) {
    const snapshot = extractDomSnapshot(doc, pageUrl);
    return analyzeDomSnapshot(snapshot);
  }

  const exportsObj = {
    extractDomSnapshot,
    analyzeDomSnapshot,
    analyzeDocument
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportsObj;
  }
  root.PhishGuardDomAnalyzer = exportsObj;
})(typeof globalThis !== 'undefined' ? globalThis : this);
