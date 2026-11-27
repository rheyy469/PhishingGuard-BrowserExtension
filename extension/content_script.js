'use strict';

/**
 * PhishGuard Local - Content Script (Read-Only DOM Inspector & Visual Warning Banner)
 * Runs passively on loaded pages. NEVER reads password field contents or records keystrokes.
 */
(function () {
  if (window.__phishGuardInjected) return;
  window.__phishGuardInjected = true;

  const BANNER_HOST_ID = 'phishguard-local-banner-host';
  let bannerDismissed = false;

  function removeWarningBanner() {
    const existing = document.getElementById(BANNER_HOST_ID);
    if (existing) existing.remove();
  }

  function createGrayHatIcon() {
    const svgNS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(svgNS, 'svg');
    svg.setAttribute('viewBox', '0 0 48 48');
    svg.setAttribute('width', '26');
    svg.setAttribute('height', '26');
    svg.setAttribute('fill', 'none');
    svg.style.cssText = 'flex-shrink: 0; display: block;';

    const shapes = [
      { tag: 'circle', attrs: { cx: '24', cy: '24', r: '22', fill: '#131514' } },
      { tag: 'path', attrs: { d: 'M10 42C11.5 35.8 16.6 33 24 33C31.4 33 36.5 35.8 38 42C34.3 44.3 29.4 45.5 24 45.5C18.6 45.5 13.7 44.3 10 42Z', fill: '#64748B' } },
      { tag: 'path', attrs: { d: 'M16.8 23.2C16.8 28 19.7 31.8 24 31.8C28.3 31.8 31.2 28 31.2 23.2H16.8Z', fill: '#1E293B', stroke: '#94A3B8', 'stroke-width': '0.9' } },
      { tag: 'path', attrs: { d: 'M14.2 19.5L16.6 10.6C17.1 8.9 18.8 8 20.4 8.6L24 9.9L27.6 8.6C29.2 8 30.9 8.9 31.4 10.6L33.8 19.5H14.2Z', fill: '#CBD5E1' } },
      { tag: 'path', attrs: { d: 'M14.7 17.5H33.3L33.8 19.8H14.2L14.7 17.5Z', fill: '#334155' } },
      { tag: 'path', attrs: { d: 'M6.5 21.4C11.8 19.1 17.7 18.4 24 18.4C30.3 18.4 36.2 19.1 41.5 21.4C36.8 23.1 30.6 23.6 24 23.6C17.4 23.6 11.2 23.1 6.5 21.4Z', fill: '#94A3B8' } }
    ];

    for (const s of shapes) {
      const el = document.createElementNS(svgNS, s.tag);
      for (const [k, v] of Object.entries(s.attrs)) {
        el.setAttribute(k, v);
      }
      svg.appendChild(el);
    }
    return svg;
  }

  function renderWarningBanner(report) {
    removeWarningBanner();
    if (!report || report.ignored || report.whitelisted || bannerDismissed) return;
    if (report.showBanner === false) return;
    if (report.status !== 'warning' && report.status !== 'danger') return;

    const isDanger = report.status === 'danger';
    const bgColor = isDanger ? '#7F1D1D' : '#78350F';
    const accentColor = isDanger ? '#F87171' : '#FBBF24';
    const badgeBg = isDanger ? '#DC2626' : '#D97706';
    const heading = isDanger
      ? 'PhishGuard Local: High Phishing Risk Warning!'
      : 'PhishGuard Local: Security Caution on This Page';

    const topFinding = report.findings && report.findings.length > 0
      ? report.findings[0].title
      : 'Suspicious indicators were detected on this page.';

    const extraCount = report.findings && report.findings.length > 1
      ? ` (+${report.findings.length - 1} more ${report.findings.length - 1 === 1 ? 'finding' : 'findings'} — click the PhishGuard icon for details)`
      : ' — click the PhishGuard toolbar icon for technical details.';

    const host = document.createElement('div');
    host.id = BANNER_HOST_ID;
    host.style.cssText = 'all: initial; position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647; display: block;';

    const shadow = host.attachShadow({ mode: 'closed' });
    const wrapper = document.createElement('div');
    wrapper.style.cssText = [
      'font-family: "Poppins", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      `background: linear-gradient(90deg, ${bgColor}, #0F172A)`,
      'color: #FFFFFF',
      'padding: 10px 16px',
      'display: flex',
      'align-items: center',
      'justify-content: space-between',
      'gap: 12px',
      'box-shadow: 0 6px 20px rgba(0, 0, 0, 0.35)',
      `border-bottom: 2px solid ${accentColor}`,
      'font-size: 13px',
      'line-height: 1.4'
    ].join(';');

    const left = document.createElement('div');
    left.style.cssText = 'display: flex; align-items: center; gap: 10px; flex-wrap: wrap;';

    const logoIcon = createGrayHatIcon();

    const badge = document.createElement('span');
    badge.textContent = isDanger ? `HIGH RISK (${report.score}/100)` : `CAUTION (${report.score}/100)`;
    badge.style.cssText = [
      `background: ${badgeBg}`,
      'color: #FFFFFF',
      'font-weight: 700',
      'font-size: 11px',
      'padding: 3px 9px',
      'border-radius: 999px',
      'letter-spacing: 0.35px',
      'white-space: nowrap'
    ].join(';');

    const textBlock = document.createElement('span');
    const strong = document.createElement('strong');
    strong.textContent = heading + ' ';
    const desc = document.createElement('span');
    desc.textContent = topFinding + extraCount;
    desc.style.color = '#E2E8F0';

    textBlock.appendChild(strong);
    textBlock.appendChild(desc);
    left.appendChild(logoIcon);
    left.appendChild(badge);
    left.appendChild(textBlock);

    const actions = document.createElement('div');
    actions.style.cssText = 'display: flex; align-items: center; gap: 8px; flex-shrink: 0;';

    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.textContent = 'Dismiss';
    closeBtn.style.cssText = [
      'background: rgba(255, 255, 255, 0.14)',
      'color: #FFFFFF',
      'border: 1px solid rgba(255, 255, 255, 0.3)',
      'border-radius: 7px',
      'padding: 5px 11px',
      'font-size: 12px',
      'font-weight: 600',
      'cursor: pointer'
    ].join(';');
    closeBtn.addEventListener('click', () => {
      bannerDismissed = true;
      removeWarningBanner();
    });

    actions.appendChild(closeBtn);
    wrapper.appendChild(left);
    wrapper.appendChild(actions);
    shadow.appendChild(wrapper);

    (document.documentElement || document.body).appendChild(host);
  }

  let mutationTimer = null;
  let lastScanSignature = '';

  function computeQuickDomSignature() {
    const pwCount = document.querySelectorAll('input[type="password"]').length;
    const formCount = document.querySelectorAll('form').length;
    const iframeCount = document.querySelectorAll('iframe').length;
    return `${window.location.href}|${formCount}|${pwCount}|${iframeCount}`;
  }

  function runInspection() {
    lastScanSignature = computeQuickDomSignature();
    const start = performance.now();
    const domResult = globalThis.PhishGuardDomAnalyzer.analyzeDocument(document, window.location.href);
    const durationMs = performance.now() - start;

    try {
      chrome.runtime.sendMessage(
        {
          type: 'DOM_ANALYSIS_REPORT',
          url: window.location.href,
          domResult,
          durationMs
        },
        (response) => {
          if (chrome.runtime.lastError) return;
          if (response && response.ok && response.report) {
            renderWarningBanner(response.report);
          }
        }
      );
    } catch (_err) {
      // Extension context may have been reloaded
    }
  }

  // Lightweight debounced MutationObserver to catch dynamically injected login modals & iframes (SPAs)
  function startDynamicDomObserver() {
    if (typeof MutationObserver !== 'function' || !document.documentElement) return;
    const observer = new MutationObserver((mutations) => {
      let relevant = false;
      for (let i = 0; i < mutations.length; i++) {
        const added = mutations[i].addedNodes;
        for (let j = 0; j < added.length; j++) {
          const node = added[j];
          if (node.nodeType !== 1 || node.id === BANNER_HOST_ID) continue;
          const tag = node.tagName;
          if (
            tag === 'FORM' ||
            tag === 'INPUT' ||
            tag === 'IFRAME' ||
            (node.querySelector && node.querySelector('input[type="password"], form, iframe'))
          ) {
            relevant = true;
            break;
          }
        }
        if (relevant) break;
      }

      if (!relevant) return;
      if (mutationTimer) clearTimeout(mutationTimer);
      mutationTimer = setTimeout(() => {
        const sig = computeQuickDomSignature();
        if (sig !== lastScanSignature) {
          runInspection();
        }
      }, 450);
    });

    observer.observe(document.documentElement, { childList: true, subtree: true });
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (!message || !message.type) return false;
    if (message.type === 'UPDATE_BANNER') {
      bannerDismissed = false;
      renderWarningBanner(message.report);
      sendResponse({ ok: true });
      return true;
    }
    if (message.type === 'RUN_FRESH_SCAN') {
      const start = performance.now();
      const domResult = globalThis.PhishGuardDomAnalyzer.analyzeDocument(document, window.location.href);
      const durationMs = performance.now() - start;
      sendResponse({ ok: true, domResult, durationMs });
      return true;
    }
    return false;
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      runInspection();
      startDynamicDomObserver();
    }, { once: true });
  } else {
    runInspection();
    startDynamicDomObserver();
  }
})();
