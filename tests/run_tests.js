'use strict';

/**
 * PhishGuard Local - Automated Verification Suite
 * Verifies all functional detection rules, performance (< 50 ms), false positive rate (< 5%),
 * and strict privacy compliance (zero outbound network requests & zero password .value reads).
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { performance } = require('node:perf_hooks');

const urlAnalyzer = require('../extension/src/url_analyzer.js');
const domAnalyzer = require('../extension/src/dom_analyzer.js');
const riskEngine = require('../extension/src/risk_engine.js');

describe('1. Homograph & Typosquatting Detection', () => {
  it('calculates Levenshtein distance accurately', () => {
    assert.equal(urlAnalyzer.levenshteinDistance('paypal', 'paypa1'), 1);
    assert.equal(urlAnalyzer.levenshteinDistance('google', 'g00gle'), 2);
    assert.equal(urlAnalyzer.levenshteinDistance('microsoft', 'microsoft'), 0);
    assert.equal(urlAnalyzer.levenshteinDistance('kitten', 'sitting'), 3);
  });

  const phishingUrls = [
    { url: 'https://paypa1.com/signin', label: 'Typosquatting paypa1.com' },
    { url: 'https://g00gle.com/login', label: 'Typosquatting g00gle.com' },
    { url: 'https://micr0soft.com/auth', label: 'Typosquatting micr0soft.com' },
    { url: 'https://klikbc4.com/login', label: 'Typosquatting klikbc4.com' },
    { url: 'https://faceb00k.com/', label: 'Typosquatting faceb00k.com' },
    { url: 'https://paypall.com/verify', label: 'Levenshtein-1 paypall.com' },
    { url: 'https://xn--pypal-4ve.com/login', label: 'IDN Punycode homograph' },
    { url: 'https://p\u0430ypal.com/login', label: 'Unicode Cyrillic homograph' },
    { url: 'https://paypal.com.evil-verify.xyz/auth', label: 'Subdomain brand spoofing' },
    { url: 'https://paypal-security.xyz/login', label: 'Hyphenated brand spoofing' },
    { url: 'https://paypal.com@evil-host.example/login', label: 'Userinfo @ trick' },
    { url: 'http://45.33.32.156/login', label: 'Raw IP host' }
  ];

  for (const tc of phishingUrls) {
    it(`detects 100% of phishing URL scenario: ${tc.label}`, () => {
      const urlResult = urlAnalyzer.analyzeUrl(tc.url);
      const report = riskEngine.evaluateRisk({ urlResult });
      assert.equal(report.status, 'danger', `Expected danger for ${tc.url}, got ${report.status} (score=${report.score})`);
      assert.ok(report.findings.length > 0);
    });
  }
});

describe('2. Login Form Target & DOM Link Inspection', () => {
  it('flags login form submitting to an external domain (High Risk)', () => {
    const domResult = domAnalyzer.analyzeDomSnapshot({
      pageUrl: 'https://shop-demo.example/login',
      forms: [{ action: 'https://evil-collector.example/capture', method: 'POST', hasPassword: true }],
      hasPasswordInputOutsideForm: false,
      links: []
    });
    const urlResult = urlAnalyzer.analyzeUrl('https://shop-demo.example/login');
    const report = riskEngine.evaluateRisk({ urlResult, domResult });
    assert.equal(report.status, 'danger');
    assert.equal(report.statusLabel, 'High Risk');
    assert.ok(report.findings.some((f) => f.id === 'FORM_ACTION_EXTERNAL_DOMAIN'));
  });

  it('flags login form submitting to a raw IP address (High Risk)', () => {
    const domResult = domAnalyzer.analyzeDomSnapshot({
      pageUrl: 'http://localhost:8787/login-raw-ip',
      forms: [{ action: 'http://192.168.1.99/steal-cred', method: 'POST', hasPassword: true }],
      hasPasswordInputOutsideForm: false,
      links: []
    });
    const urlResult = urlAnalyzer.analyzeUrl('http://localhost:8787/login-raw-ip');
    const report = riskEngine.evaluateRisk({ urlResult, domResult });
    assert.equal(report.status, 'danger');
    assert.ok(report.findings.some((f) => f.id === 'FORM_ACTION_RAW_IP'));
  });

  it('flags login form over unencrypted HTTP (Caution)', () => {
    const domResult = domAnalyzer.analyzeDomSnapshot({
      pageUrl: 'http://localhost:8787/login-http',
      forms: [{ action: 'http://localhost:8787/submitted', method: 'POST', hasPassword: true }],
      hasPasswordInputOutsideForm: false,
      links: []
    });
    const urlResult = urlAnalyzer.analyzeUrl('http://localhost:8787/login-http');
    const report = riskEngine.evaluateRisk({ urlResult, domResult });
    assert.equal(report.status, 'warning');
    assert.equal(report.statusLabel, 'Caution');
    assert.ok(report.findings.some((f) => f.id === 'FORM_ACTION_INSECURE_HTTP'));
  });

  it('flags deceptive <a> links with mismatched display domain', () => {
    const domResult = domAnalyzer.analyzeDomSnapshot({
      pageUrl: 'http://localhost:8787/deceptive-links',
      forms: [],
      hasPasswordInputOutsideForm: false,
      links: [
        { text: 'https://paypal.com/verify-account', href: 'https://malicious-tracker.example/verify' }
      ]
    });
    const urlResult = urlAnalyzer.analyzeUrl('http://localhost:8787/deceptive-links');
    const report = riskEngine.evaluateRisk({ urlResult, domResult });
    assert.equal(report.status, 'warning');
    assert.ok(report.findings.some((f) => f.id === 'DECEPTIVE_LINK_MISMATCH'));
  });
});

describe('3. Redirect Chain Monitoring', () => {
  it('flags suspicious multi-domain redirect chains', () => {
    const urlResult = urlAnalyzer.analyzeUrl('https://landing-target.example/login');
    const redirectChain = [
      { url: 'https://short.example/abc' },
      { url: 'https://hop-tracker.net/go' },
      { url: 'https://landing-target.example/login' }
    ];
    const report = riskEngine.evaluateRisk({ urlResult, redirectChain });
    assert.equal(report.status, 'danger');
    assert.ok(report.findings.some((f) => f.id === 'REDIRECT_CHAIN_CROSS_DOMAIN_HIGH'));
  });

  it('flags 4-hop redirect chain on localhost simulation', () => {
    const urlResult = urlAnalyzer.analyzeUrl('http://localhost:8787/redirect-landing');
    const redirectChain = [
      { url: 'http://localhost:8787/redirect-1' },
      { url: 'http://localhost:8787/redirect-2' },
      { url: 'http://localhost:8787/redirect-3' },
      { url: 'http://localhost:8787/redirect-landing' }
    ];
    const report = riskEngine.evaluateRisk({ urlResult, redirectChain });
    assert.equal(report.status, 'warning');
    assert.ok(report.findings.some((f) => f.id === 'REDIRECT_CHAIN_EXCESSIVE'));
  });
});

describe('4. Local Whitelist & Sensitivity Thresholds', () => {
  it('respects the user local whitelist', () => {
    const urlResult = urlAnalyzer.analyzeUrl('https://paypa1.com/test');
    const report = riskEngine.evaluateRisk({
      urlResult,
      whitelist: ['paypa1.com']
    });
    assert.equal(report.status, 'safe');
    assert.equal(report.statusLabel, 'Safe (Whitelisted)');
    assert.equal(report.whitelisted, true);
    assert.equal(report.score, 0);
  });

  it('adjusts status according to sensitivity level (low/medium/high)', () => {
    const urlResult = urlAnalyzer.analyzeUrl('http://localhost:8787/login-http');
    const domResult = domAnalyzer.analyzeDomSnapshot({
      pageUrl: 'http://localhost:8787/login-http',
      forms: [{ action: 'http://localhost:8787/submitted', method: 'POST', hasPassword: true }],
      hasPasswordInputOutsideForm: false,
      links: []
    });
    const lowReport = riskEngine.evaluateRisk({ urlResult, domResult, sensitivity: 'low' });
    const medReport = riskEngine.evaluateRisk({ urlResult, domResult, sensitivity: 'medium' });
    const highReport = riskEngine.evaluateRisk({ urlResult, domResult, sensitivity: 'high' });

    assert.equal(lowReport.status, 'safe');
    assert.equal(medReport.status, 'warning');
    assert.equal(highReport.status, 'warning');
  });
});

describe('5. Quality Metrics: False Positive < 5% & Latency < 50 ms', () => {
  const popularSafeSites = [
    'https://www.google.com/search?q=security',
    'https://accounts.google.com/signin',
    'https://mail.google.com/mail/u/0/',
    'https://github.com/login',
    'https://gitlab.com/users/sign_in',
    'https://www.paypal.com/signin',
    'https://www.microsoft.com/en-us',
    'https://login.microsoftonline.com/',
    'https://www.apple.com/',
    'https://www.amazon.com/',
    'https://www.netflix.com/login',
    'https://www.linkedin.com/login',
    'https://www.instagram.com/',
    'https://www.facebook.com/',
    'https://www.bca.co.id/',
    'https://ibank.klikbca.com/',
    'https://www.bankmandiri.co.id/',
    'https://www.bri.co.id/',
    'https://www.bni.co.id/',
    'https://www.tokopedia.com/',
    'https://shopee.co.id/',
    'https://www.gojek.com/',
    'https://www.dana.id/',
    'https://www.wikipedia.org/',
    'https://stackoverflow.com/questions',
    'https://developer.mozilla.org/en-US/docs/Web',
    'https://www.cloudflare.com/',
    'https://www.npmjs.com/',
    'https://www.reddit.com/',
    'https://www.notion.so/',
    'https://vercel.com/',
    'https://stripe.com/docs',
    'https://www.kompas.com/',
    'https://www.detik.com/',
    'https://news.ycombinator.com/'
  ];

  it('maintains a false positive rate below 5% across 35 popular safe sites', () => {
    let falsePositives = 0;
    const flagged = [];

    for (const site of popularSafeSites) {
      const urlResult = urlAnalyzer.analyzeUrl(site);
      const domResult = domAnalyzer.analyzeDomSnapshot({
        pageUrl: site,
        forms: [{ action: '/login', method: 'POST', hasPassword: true }],
        hasPasswordInputOutsideForm: false,
        links: [{ text: site, href: site }]
      });
      const report = riskEngine.evaluateRisk({ urlResult, domResult });
      if (report.status !== 'safe') {
        falsePositives++;
        flagged.push({ site, status: report.status, findings: report.findings });
      }
    }

    const fpRate = (falsePositives / popularSafeSites.length) * 100;
    assert.ok(
      fpRate < 5,
      `False positive rate ${fpRate.toFixed(2)}% >= 5%. Flagged: ${JSON.stringify(flagged)}`
    );
  });

  it('completes URL + DOM analysis well under 50 ms per page', () => {
    const heavyLinks = Array.from({ length: 200 }, (_, i) => ({
      text: `https://example.org/page-${i}`,
      href: `https://example.org/page-${i}`
    }));

    const start = performance.now();
    const iterations = 50;
    for (let i = 0; i < iterations; i++) {
      const urlResult = urlAnalyzer.analyzeUrl('https://paypa1.com/login');
      const domResult = domAnalyzer.analyzeDomSnapshot({
        pageUrl: 'https://paypa1.com/login',
        forms: [{ action: 'https://evil.example/post', method: 'POST', hasPassword: true }],
        hasPasswordInputOutsideForm: false,
        links: heavyLinks
      });
      riskEngine.evaluateRisk({ urlResult, domResult });
    }
    const avgMs = (performance.now() - start) / iterations;
    assert.ok(avgMs < 50, `Average analysis latency ${avgMs.toFixed(2)} ms exceeded the 50 ms limit`);
  });
});

describe('6. Privacy Compliance: Zero Outbound Network & Zero Password Value Reads', () => {
  const extensionDir = path.join(__dirname, '..', 'extension');
  const jsFiles = [
    'background.js',
    'content_script.js',
    'popup.js',
    'src/domains.js',
    'src/url_analyzer.js',
    'src/dom_analyzer.js',
    'src/risk_engine.js'
  ];

  it('contains no outbound network calls (fetch, XMLHttpRequest, WebSocket, sendBeacon)', () => {
    const forbiddenNetworkPatterns = [
      /\bfetch\s*\(/,
      /\bXMLHttpRequest\b/,
      /\bnew\s+WebSocket\b/,
      /\bsendBeacon\s*\(/
    ];

    for (const rel of jsFiles) {
      const content = fs.readFileSync(path.join(extensionDir, rel), 'utf8');
      for (const pattern of forbiddenNetworkPatterns) {
        assert.equal(
          pattern.test(content),
          false,
          `Detected outbound network pattern (${pattern}) in ${rel}`
        );
      }
    }
  });

  it('never reads .value from password inputs or listens to keystrokes in content_script & dom_analyzer', () => {
    const domFiles = ['content_script.js', 'src/dom_analyzer.js'];
    const forbiddenDomPatterns = [
      /\.value\b/,
      /addEventListener\s*\(\s*['"](keydown|keyup|keypress|input)['"]/
    ];

    for (const rel of domFiles) {
      const raw = fs.readFileSync(path.join(extensionDir, rel), 'utf8');
      const content = raw
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/\/\/.*$/gm, '');
      for (const pattern of forbiddenDomPatterns) {
        assert.equal(
          pattern.test(content),
          false,
          `Detected DOM privacy violation (${pattern}) in ${rel}`
        );
      }
    }
  });
});

describe('7. False-Positive Elimination: eTLD+1, Siblings, OAuth/SSO & Trusted Redirects', () => {
  it('parses multi-part TLDs and shared suffixes accurately (.co.id, .co.uk, .github.io)', () => {
    assert.equal(urlAnalyzer.parseDomainParts('gist.github.com').registrableDomain, 'github.com');
    assert.equal(urlAnalyzer.parseDomainParts('id.pinterest.com').registrableDomain, 'pinterest.com');
    assert.equal(urlAnalyzer.parseDomainParts('ibank.bca.co.id').registrableDomain, 'bca.co.id');
    assert.equal(urlAnalyzer.parseDomainParts('myproject.github.io').registrableDomain, 'myproject.github.io');
  });

  it('treats same-site subdomains and official sibling domains as SAFE (0 risk)', () => {
    // gist.github.com -> github.com form submission
    const gistUrl = urlAnalyzer.analyzeUrl('https://gist.github.com/login');
    const gistDom = domAnalyzer.analyzeDomSnapshot({
      pageUrl: 'https://gist.github.com/login',
      forms: [{ action: 'https://github.com/session', method: 'POST', hasPassword: true }],
      hasPasswordInputOutsideForm: false,
      links: [{ text: 'https://github.com/features', href: 'https://raw.githubusercontent.com/org/repo/main/README.md' }]
    });
    const gistReport = riskEngine.evaluateRisk({ urlResult: gistUrl, domResult: gistDom });
    assert.equal(gistReport.status, 'safe');
    assert.equal(gistReport.score, 0);

    // myproject.github.io must NOT falsely match github.com typosquatting
    const pagesUrl = urlAnalyzer.analyzeUrl('https://myproject.github.io/');
    const pagesReport = riskEngine.evaluateRisk({ urlResult: pagesUrl });
    assert.equal(pagesReport.status, 'safe');
    assert.equal(pagesReport.score, 0);
  });

  it('does not flag regional redirects on Pinterest (pinterest.com -> id.pinterest.com -> www.pinterest.com)', () => {
    const urlResult = urlAnalyzer.analyzeUrl('https://www.pinterest.com/');
    const redirectChain = [
      { url: 'https://pinterest.com/' },
      { url: 'https://id.pinterest.com/' },
      { url: 'https://www.pinterest.com/' }
    ];
    const report = riskEngine.evaluateRisk({ urlResult, redirectChain });
    assert.equal(report.status, 'safe');
    assert.equal(report.score, 0);
  });

  it('allows legitimate OAuth / SSO login flows (Google, Microsoft, Apple, GitHub)', () => {
    const pageUrl = 'https://saas-portal.example/signin';
    const urlResult = urlAnalyzer.analyzeUrl(pageUrl);
    const domResult = domAnalyzer.analyzeDomSnapshot({
      pageUrl,
      forms: [
        { action: 'https://accounts.google.com/o/oauth2/v2/auth', method: 'POST', hasPassword: true },
        { action: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize', method: 'POST', hasPassword: true }
      ],
      hasPasswordInputOutsideForm: false,
      links: []
    });
    const report = riskEngine.evaluateRisk({ urlResult, domResult });
    assert.equal(report.status, 'safe');
    assert.equal(report.score, 0);
  });

  it('flags public non-localhost plaintext HTTP password forms as DANGER (>= 60)', () => {
    const pageUrl = 'http://untrusted-portal.example/login';
    const urlResult = urlAnalyzer.analyzeUrl(pageUrl);
    const domResult = domAnalyzer.analyzeDomSnapshot({
      pageUrl,
      forms: [{ action: '/auth', method: 'POST', hasPassword: true }],
      hasPasswordInputOutsideForm: false,
      links: []
    });
    const report = riskEngine.evaluateRisk({ urlResult, domResult });
    assert.equal(report.status, 'danger');
    assert.ok(report.score >= 60);
  });
});

describe('8. Advanced Scanners: Brand/Favicon, Overlay Iframe, Obfuscated Script & Lure URL', () => {
  it('flags brand impersonation & hotlinked brand favicon on untrusted login pages', () => {
    const pageUrl = 'https://secure-billing-portal.example/signin';
    const urlResult = urlAnalyzer.analyzeUrl(pageUrl);
    const domResult = domAnalyzer.analyzeDomSnapshot({
      pageUrl,
      title: 'Log in to your PayPal account',
      siteName: 'PayPal',
      favicons: ['https://www.paypal.com/favicon.ico'],
      forms: [{ action: '/signin', method: 'POST', hasPassword: true }],
      hasPasswordInputOutsideForm: false,
      links: []
    });
    const report = riskEngine.evaluateRisk({ urlResult, domResult });
    assert.equal(report.status, 'danger');
    assert.ok(report.findings.some((f) => f.id === 'BRAND_IMPERSONATION_CONTENT'));
    assert.ok(report.findings.some((f) => f.id === 'HOTLINKED_BRAND_FAVICON'));
  });

  it('does NOT flag a normal blog post mentioning PayPal without a login form', () => {
    const pageUrl = 'https://tech-review-blog.example/paypal-fee-guide';
    const urlResult = urlAnalyzer.analyzeUrl(pageUrl);
    const domResult = domAnalyzer.analyzeDomSnapshot({
      pageUrl,
      title: 'PayPal Fee Guide 2026',
      favicons: ['/favicon.ico'],
      forms: [],
      hasPasswordInputOutsideForm: false,
      links: []
    });
    const report = riskEngine.evaluateRisk({ urlResult, domResult });
    assert.equal(report.status, 'safe');
    assert.equal(report.score, 0);
  });

  it('flags suspicious cross-origin overlay iframes and obfuscated login scripts', () => {
    const pageUrl = 'https://unknown-portal.example/auth';
    const urlResult = urlAnalyzer.analyzeUrl(pageUrl);
    const domResult = domAnalyzer.analyzeDomSnapshot({
      pageUrl,
      forms: [{ action: '/auth', method: 'POST', hasPassword: true }],
      hasPasswordInputOutsideForm: false,
      links: [],
      iframes: [{ src: 'https://evil-kit.xyz/frame', hidden: false, isOverlay: true }],
      scripts: [{ src: 'https://cdn-dropper.xyz/steal.js' }],
      hasObfuscatedInlineScript: true,
      blocksContextMenu: true
    });
    const report = riskEngine.evaluateRisk({ urlResult, domResult });
    assert.equal(report.status, 'danger');
    assert.ok(report.findings.some((f) => f.id === 'SUSPICIOUS_OVERLAY_IFRAME'));
    assert.ok(report.findings.some((f) => f.id === 'OBFUSCATED_PHISHING_SCRIPT'));
    assert.ok(report.findings.some((f) => f.id === 'UNTRUSTED_SCRIPT_SOURCE'));
    assert.ok(report.findings.some((f) => f.id === 'ANTI_INSPECTION_LOGIN'));
  });

  it('flags credential-lure path keywords combined with suspicious TLDs', () => {
    const urlResult = urlAnalyzer.analyzeUrl('https://portal-check.xyz/verify-account?step=1');
    const report = riskEngine.evaluateRisk({ urlResult });
    assert.equal(report.status, 'warning');
    assert.ok(report.findings.some((f) => f.id === 'SUSPICIOUS_LURE_URL'));
  });

  it('catches dual 1->i confusable typosquatting (m1crosoft.com, g1thub.com) and avoids word-boundary false positives', () => {
    for (const bad of ['https://m1crosoft.com/login', 'https://g1thub.com/session']) {
      const urlResult = urlAnalyzer.analyzeUrl(bad);
      const report = riskEngine.evaluateRisk({ urlResult });
      assert.equal(report.status, 'danger', `Expected danger for ${bad}`);
      assert.equal(report.score, 75);
    }

    // Word boundary check: "Steaming Coffee" must NOT falsely match "Steam"
    const domResult = domAnalyzer.analyzeDomSnapshot({
      pageUrl: 'https://coffee-shop.example/login',
      title: 'Steaming Coffee Member Login',
      favicons: [],
      forms: [{ action: '/login', method: 'POST', hasPassword: true }],
      hasPasswordInputOutsideForm: false,
      links: [],
      totalLinks: 42,
      totalScripts: 7
    });
    const urlResult = urlAnalyzer.analyzeUrl('https://coffee-shop.example/login');
    const report = riskEngine.evaluateRisk({ urlResult, domResult });
    assert.equal(report.status, 'safe');
    assert.equal(report.domStats.totalLinks, 42);
    assert.equal(report.domStats.totalScripts, 7);
  });
});

describe('9. Modern Phishing Kit Defense (v1.4.0): Combosquatting, Webhooks, Seed/CC & Free Hosting', () => {
  it('catches non-hyphenated combosquatting domains (paypallogin.com, googleverify.xyz, klikbcalogin.top)', () => {
    const combos = [
      'https://paypallogin.com/auth',
      'https://googleverify.xyz/check',
      'https://klikbcalogin.top/ib',
      'https://securebinance.net/wallet',
      'https://paypallogin.pages.dev/'
    ];
    for (const u of combos) {
      const urlResult = urlAnalyzer.analyzeUrl(u);
      const report = riskEngine.evaluateRisk({ urlResult });
      assert.equal(report.status, 'danger', `Expected danger for combosquat ${u}, got ${report.status} (score=${report.score})`);
      assert.ok(report.findings.some((f) => f.id === 'COMBOSQUATTING_BRAND'));
    }
  });

  it('catches Telegram Bot API and Discord Webhook exfiltration kits immediately as DANGER', () => {
    for (const provider of ['Telegram Bot API', 'Discord Webhook']) {
      const pageUrl = 'https://promo-claim.example/login';
      const urlResult = urlAnalyzer.analyzeUrl(pageUrl);
      const domResult = domAnalyzer.analyzeDomSnapshot({
        pageUrl,
        forms: [{ action: '/submit', method: 'POST', hasPassword: true }],
        hasPasswordInputOutsideForm: false,
        links: [],
        exfilWebhookProvider: provider
      });
      const report = riskEngine.evaluateRisk({ urlResult, domResult });
      assert.equal(report.status, 'danger');
      assert.ok(report.score >= 80);
      assert.ok(report.findings.some((f) => f.id === 'CREDENTIAL_EXFIL_WEBHOOK'));
    }
  });

  it('catches crypto seed-phrase harvesting and unrecognized external credit card forms while allowing Stripe/Midtrans', () => {
    // Untrusted seed phrase harvest -> DANGER
    const seedUrl = 'https://airdrop-connect.example/restore';
    const seedReport = riskEngine.evaluateRisk({
      urlResult: urlAnalyzer.analyzeUrl(seedUrl),
      domResult: domAnalyzer.analyzeDomSnapshot({
        pageUrl: seedUrl,
        title: 'Restore Wallet',
        headingTexts: ['MetaMask Secret Recovery Phrase'],
        forms: [],
        hasPasswordInputOutsideForm: false,
        hasSeedPhraseHarvest: true,
        links: []
      })
    });
    assert.equal(seedReport.status, 'danger');
    assert.ok(seedReport.findings.some((f) => f.id === 'CRYPTO_SEED_PHRASE_HARVEST'));
    assert.ok(seedReport.findings.some((f) => f.id === 'BRAND_IMPERSONATION_CONTENT'));

    // Legitimate checkout submitting CC form to Stripe -> SAFE
    const shopUrl = 'https://boutique-store.example/checkout';
    const safeCheckout = riskEngine.evaluateRisk({
      urlResult: urlAnalyzer.analyzeUrl(shopUrl),
      domResult: domAnalyzer.analyzeDomSnapshot({
        pageUrl: shopUrl,
        forms: [{ action: 'https://api.stripe.com/v1/tokens', method: 'POST', hasPassword: false, hasCreditCard: true }],
        hasPasswordInputOutsideForm: false,
        links: []
      })
    });
    assert.equal(safeCheckout.status, 'safe');
    assert.equal(safeCheckout.score, 0);

    // Malicious CC form submitting to unknown external domain -> DANGER
    const evilCheckout = riskEngine.evaluateRisk({
      urlResult: urlAnalyzer.analyzeUrl(shopUrl),
      domResult: domAnalyzer.analyzeDomSnapshot({
        pageUrl: shopUrl,
        forms: [{ action: 'https://card-collector.example/grab', method: 'POST', hasPassword: false, hasCreditCard: true }],
        hasPasswordInputOutsideForm: false,
        links: []
      })
    });
    assert.equal(evilCheckout.status, 'danger');
    assert.ok(evilCheckout.findings.some((f) => f.id === 'PAYMENT_FORM_EXTERNAL_DOMAIN'));
  });

  it('catches free-hosting login pages, data: iframes, blank-title heading spoofing, and suspicious redirect params', () => {
    const pagesLoginUrl = 'https://acct-portal-82.pages.dev/signin';
    const pagesReport = riskEngine.evaluateRisk({
      urlResult: urlAnalyzer.analyzeUrl(pagesLoginUrl),
      domResult: domAnalyzer.analyzeDomSnapshot({
        pageUrl: pagesLoginUrl,
        title: 'Welcome',
        headingTexts: ['Sign in to Microsoft'],
        forms: [{ action: '/signin', method: 'POST', hasPassword: true }],
        hasPasswordInputOutsideForm: false,
        links: [],
        iframes: [{ src: 'data:text/html;base64,PGZvcm0+', hasSrcdoc: false, hidden: false, isOverlay: true }]
      })
    });
    assert.equal(pagesReport.status, 'danger');
    assert.ok(pagesReport.findings.some((f) => f.id === 'FREE_HOSTING_LOGIN_FORM'));
    assert.ok(pagesReport.findings.some((f) => f.id === 'BRAND_IMPERSONATION_CONTENT'));
    assert.ok(pagesReport.findings.some((f) => f.id === 'SUSPICIOUS_IFRAME_SCHEME'));

    // Suspicious redirect query param pointing to high-risk TLD
    const redirUrl = urlAnalyzer.analyzeUrl('https://tracker-gate.example/go?next=https://evil-kit.xyz/auth');
    const redirReport = riskEngine.evaluateRisk({ urlResult: redirUrl });
    assert.equal(redirReport.status, 'warning');
    assert.ok(redirReport.findings.some((f) => f.id === 'SUSPICIOUS_REDIRECT_PARAM'));
  });
});

describe('10. Next-Level Defense (v1.5.0): RFC 3492 Punycode, BitB, HTML Smuggling, DGA & Correlation', () => {
  it('decodes RFC 3492 Punycode locally and identifies the exact spoofed brand', () => {
    // xn--pypal-4ve.com decodes to pаypal.com (Cyrillic а) -> spoofs paypal.com
    const decoded = urlAnalyzer.decodePunycodeHostname('xn--pypal-4ve.com');
    assert.equal(decoded, 'p\u0430ypal.com');

    const urlResult = urlAnalyzer.analyzeUrl('https://xn--pypal-4ve.com/login');
    const report = riskEngine.evaluateRisk({ urlResult });
    assert.equal(report.status, 'danger');
    assert.equal(report.score, 75);
    assert.ok(report.findings[0].title.includes('paypal.com'));
  });

  it('catches Browser-in-the-Browser (BitB) fake address bar on untrusted login pages', () => {
    const pageUrl = 'https://sso-auth-demo.example/oauth';
    const report = riskEngine.evaluateRisk({
      urlResult: urlAnalyzer.analyzeUrl(pageUrl),
      domResult: domAnalyzer.analyzeDomSnapshot({
        pageUrl,
        forms: [{ action: '/capture', method: 'POST', hasPassword: true }],
        hasPasswordInputOutsideForm: false,
        bitbSpoofedUrl: 'https://accounts.google.com/v3/signin/identifier',
        links: []
      })
    });
    assert.equal(report.status, 'danger');
    assert.ok(report.findings.some((f) => f.id === 'BITB_FAKE_ADDRESS_BAR'));
  });

  it('catches HTML Smuggling scripts and data:/blob: download traps', () => {
    const pageUrl = 'https://invoice-share.example/view';
    const report = riskEngine.evaluateRisk({
      urlResult: urlAnalyzer.analyzeUrl(pageUrl),
      domResult: domAnalyzer.analyzeDomSnapshot({
        pageUrl,
        forms: [],
        hasPasswordInputOutsideForm: false,
        hasHtmlSmugglingScript: true,
        links: []
      })
    });
    assert.equal(report.status, 'danger');
    assert.ok(report.findings.some((f) => f.id === 'HTML_SMUGGLING_DOWNLOAD'));
  });

  it('catches DGA high-entropy domains, meta-refresh stealth redirects, urgency lures, and correlates multi-vector attacks', () => {
    const pageUrl = 'https://x9k4m2p8q7z1v3b5.xyz/login';
    const urlResult = urlAnalyzer.analyzeUrl(pageUrl);
    const domResult = domAnalyzer.analyzeDomSnapshot({
      pageUrl,
      forms: [{ action: '/login', method: 'POST', hasPassword: true }],
      hasPasswordInputOutsideForm: false,
      hasUrgencyLure: true,
      metaRefreshUrl: 'https://drop-stage2.top/go',
      links: []
    });
    const report = riskEngine.evaluateRisk({ urlResult, domResult });
    assert.equal(report.status, 'danger');
    assert.ok(report.findings.some((f) => f.id === 'HIGH_ENTROPY_DGA_DOMAIN'));
    assert.ok(report.findings.some((f) => f.id === 'URGENCY_CREDENTIAL_LURE'));
    assert.ok(report.findings.some((f) => f.id === 'META_REFRESH_EXTERNAL'));
    assert.ok(report.findings.some((f) => f.id === 'MULTI_SIGNAL_CORRELATION'));
  });
});
