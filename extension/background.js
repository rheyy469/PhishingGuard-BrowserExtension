'use strict';

/**
 * PhishGuard Local - Background Service Worker (Manifest V3)
 * Monitors tab navigation, redirect chains, merges URL/DOM/Redirect risk,
 * updates toolbar icon (Green/Yellow/Red), and manages local storage.
 * ZERO outbound network requests. 100% local processing.
 */

if (typeof importScripts === 'function') {
  importScripts('src/domains.js', 'src/url_analyzer.js', 'src/dom_analyzer.js', 'src/risk_engine.js');
}

const DEFAULT_SETTINGS = {
  sensitivity: 'medium', // 'low' | 'medium' | 'high'
  showBanner: true,
  whitelist: [],
  protectedDomains: globalThis.PhishGuardDomains.DEFAULT_PROTECTED_DOMAINS
};

// In-memory per-tab state (ephemeral, cleared on tab close)
const tabReports = new Map();
const tabRedirects = new Map();

const REDIRECT_WINDOW_MS = 3500;
const DOM_CATEGORIES = new Set(['dom', 'brand', 'iframe', 'script']);

async function getSettings() {
  const stored = await chrome.storage.local.get([
    'sensitivity',
    'showBanner',
    'whitelist',
    'protectedDomains'
  ]);
  return {
    sensitivity: stored.sensitivity || DEFAULT_SETTINGS.sensitivity,
    showBanner: typeof stored.showBanner === 'boolean' ? stored.showBanner : DEFAULT_SETTINGS.showBanner,
    whitelist: Array.isArray(stored.whitelist) ? stored.whitelist : [],
    protectedDomains: Array.isArray(stored.protectedDomains) && stored.protectedDomains.length > 0
      ? stored.protectedDomains
      : DEFAULT_SETTINGS.protectedDomains
  };
}

async function ensureDefaultStorage() {
  const stored = await chrome.storage.local.get(['initialized']);
  if (!stored.initialized) {
    await chrome.storage.local.set({
      initialized: true,
      sensitivity: DEFAULT_SETTINGS.sensitivity,
      showBanner: DEFAULT_SETTINGS.showBanner,
      whitelist: DEFAULT_SETTINGS.whitelist,
      protectedDomains: DEFAULT_SETTINGS.protectedDomains
    });
  }
}

function getIconPaths(status) {
  const key = status === 'danger' ? 'danger' : (status === 'warning' ? 'warning' : 'safe');
  return {
    16: `icons/icon-${key}-16.png`,
    32: `icons/icon-${key}-32.png`,
    48: `icons/icon-${key}-48.png`,
    128: `icons/icon-${key}-128.png`
  };
}

async function updateActionIndicator(tabId, report) {
  if (typeof tabId !== 'number' || tabId < 0) return;
  try {
    const status = report ? report.status : 'safe';
    await chrome.action.setIcon({ tabId, path: getIconPaths(status) });

    if (!report || report.ignored) {
      await chrome.action.setBadgeText({ tabId, text: '' });
      await chrome.action.setTitle({ tabId, title: 'PhishGuard Local - Internal Browser Page' });
      return;
    }

    if (status === 'danger') {
      await chrome.action.setBadgeBackgroundColor({ tabId, color: '#DC2626' });
      await chrome.action.setBadgeText({ tabId, text: '!' });
      await chrome.action.setTitle({
        tabId,
        title: `PhishGuard Local - HIGH RISK (Score: ${report.score}/100)`
      });
    } else if (status === 'warning') {
      await chrome.action.setBadgeBackgroundColor({ tabId, color: '#D97706' });
      await chrome.action.setBadgeText({ tabId, text: '?' });
      await chrome.action.setTitle({
        tabId,
        title: `PhishGuard Local - CAUTION (Score: ${report.score}/100)`
      });
    } else {
      await chrome.action.setBadgeBackgroundColor({ tabId, color: '#16A34A' });
      await chrome.action.setBadgeText({ tabId, text: '' });
      await chrome.action.setTitle({
        tabId,
        title: report.whitelisted
          ? 'PhishGuard Local - Safe (Local Whitelist)'
          : 'PhishGuard Local - Safe'
      });
    }
  } catch (_err) {
    // Tab may have been closed before update completed
  }
}

function recordRedirectStep(tabId, url, isRedirectQualifier) {
  if (typeof tabId !== 'number' || tabId < 0 || !url) return;
  if (!/^https?:\/\//i.test(url)) return;

  const now = Date.now();
  const existing = tabRedirects.get(tabId);

  if (
    existing &&
    (isRedirectQualifier || (now - existing.lastTimestamp) <= REDIRECT_WINDOW_MS)
  ) {
    const lastEntry = existing.chain[existing.chain.length - 1];
    if (!lastEntry || lastEntry.url !== url) {
      // Avoid inflating hop counts for trivial in-page hash/query changes on the same host
      try {
        const prevParsed = lastEntry ? new URL(lastEntry.url) : null;
        const currParsed = new URL(url);
        const sameOriginPath = prevParsed &&
          prevParsed.origin === currParsed.origin &&
          prevParsed.pathname === currParsed.pathname;
        if (sameOriginPath) {
          existing.lastTimestamp = now;
          return;
        }
      } catch (_err) {
        // continue recording
      }

      existing.chain.push({ url, timestamp: now });
      if (existing.chain.length > 15) {
        existing.chain.shift();
      }
    }
    existing.lastTimestamp = now;
  } else {
    tabRedirects.set(tabId, {
      chain: [{ url, timestamp: now }],
      lastTimestamp: now
    });
  }
}

function getRedirectChain(tabId) {
  const state = tabRedirects.get(tabId);
  return state ? state.chain : [];
}

async function evaluateTab(tabId, url, domResult, contentDurationMs) {
  const start = performance.now();
  const settings = await getSettings();
  const urlResult = globalThis.PhishGuardUrlAnalyzer.analyzeUrl(url, {
    protectedDomains: settings.protectedDomains
  });

  if (!urlResult.valid || urlResult.ignored) {
    const ignoredReport = {
      ignored: true,
      url,
      hostname: urlResult.hostname || '',
      registrableDomain: urlResult.registrableDomain || '',
      status: 'safe',
      statusLabel: 'Internal Page',
      score: 0,
      whitelisted: false,
      sensitivity: settings.sensitivity,
      findings: [],
      redirectSummary: { hops: 0, uniqueDomains: [] },
      analysisDurationMs: 0,
      timestamp: Date.now()
    };
    tabReports.set(tabId, ignoredReport);
    await updateActionIndicator(tabId, ignoredReport);
    return ignoredReport;
  }

  const redirectChain = getRedirectChain(tabId);
  const bgDurationMs = performance.now() - start;
  const totalDurationMs = typeof contentDurationMs === 'number'
    ? contentDurationMs + bgDurationMs
    : bgDurationMs;

  const report = globalThis.PhishGuardRiskEngine.evaluateRisk({
    urlResult,
    domResult: domResult || { findings: [] },
    redirectChain,
    whitelist: settings.whitelist,
    sensitivity: settings.sensitivity,
    analysisDurationMs: totalDurationMs
  });

  report.showBanner = settings.showBanner;
  tabReports.set(tabId, report);
  await updateActionIndicator(tabId, report);
  return report;
}

// Lifecycle listeners
chrome.runtime.onInstalled.addListener(() => {
  ensureDefaultStorage();
});

// Track main-frame navigations and genuine redirect chains (avoid counting normal user clicks as redirects)
if (chrome.webNavigation) {
  chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId !== 0) return;
    const now = Date.now();
    const existing = tabRedirects.get(details.tabId);
    // Only chain onBeforeNavigate if it happens rapidly within an active redirect window (< 3.5s)
    if (!existing || (now - existing.lastTimestamp) > REDIRECT_WINDOW_MS) {
      tabRedirects.set(details.tabId, {
        chain: [{ url: details.url, timestamp: now }],
        lastTimestamp: now
      });
    } else {
      recordRedirectStep(details.tabId, details.url, true);
    }
  });

  chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId !== 0) return;
    const qualifiers = details.transitionQualifiers || [];
    const isRedirect = qualifiers.includes('server_redirect') || qualifiers.includes('client_redirect');
    const isFreshUserNav = !isRedirect && [
      'typed', 'generated', 'auto_bookmark', 'reload', 'keyword', 'link'
    ].includes(details.transitionType);

    if (isFreshUserNav) {
      tabRedirects.set(details.tabId, {
        chain: [{ url: details.url, timestamp: Date.now() }],
        lastTimestamp: Date.now()
      });
    } else {
      recordRedirectStep(details.tabId, details.url, isRedirect);
    }
    evaluateTab(details.tabId, details.url, null, 0);
  });
}

// Fallback / supplemental tracking via chrome.tabs (handles SPA pushState route changes cleanly)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    // Request a fresh DOM scan on SPA URL change instead of wiping DOM stats to 0
    chrome.tabs.sendMessage(tabId, { type: 'RUN_FRESH_SCAN' })
      .then((live) => {
        if (live && live.ok && live.domResult) {
          return evaluateTab(tabId, changeInfo.url, live.domResult, live.durationMs || 0);
        }
        return evaluateTab(tabId, changeInfo.url, null, 0);
      })
      .catch(() => evaluateTab(tabId, changeInfo.url, null, 0));
  } else if (changeInfo.status === 'complete' && tab && tab.url) {
    if (!tabReports.has(tabId)) {
      evaluateTab(tabId, tab.url, null, 0);
    }
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabReports.delete(tabId);
  tabRedirects.delete(tabId);
});

// Message hub between content_script.js and popup.js
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) return false;

  if (message.type === 'DOM_ANALYSIS_REPORT') {
    const tabId = sender && sender.tab ? sender.tab.id : message.tabId;
    const url = message.url || (sender && sender.tab ? sender.tab.url : '');
    evaluateTab(tabId, url, message.domResult, message.durationMs)
      .then((report) => sendResponse({ ok: true, report }))
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (message.type === 'GET_TAB_REPORT') {
    (async () => {
      const tabId = message.tabId;
      let report = tabReports.get(tabId);
      const needsFreshDom = !report || (
        !report.ignored &&
        report.domStats &&
        report.domStats.totalLinks === undefined &&
        report.domStats.totalScripts === undefined
      );

      // On Service Worker cold start (empty tabReports), fetch a live DOM scan from content_script
      if ((needsFreshDom || !report) && message.url) {
        let liveDom = null;
        let liveDuration = 0;
        if (/^https?:\/\//i.test(message.url)) {
          try {
            const live = await chrome.tabs.sendMessage(tabId, { type: 'RUN_FRESH_SCAN' });
            if (live && live.ok && live.domResult) {
              liveDom = live.domResult;
              liveDuration = live.durationMs || 0;
            }
          } catch (_err) {
            // Content script not injected (e.g., restricted browser store/internal page)
          }
        }
        report = await evaluateTab(tabId, message.url, liveDom, liveDuration);
      }

      const settings = await getSettings();
      sendResponse({ ok: true, report: report || null, settings });
    })().catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (message.type === 'REANALYZE_TAB') {
    (async () => {
      const { tabId, url } = message;
      let freshDomResult = null;
      let contentDurationMs = 0;

      // Request a fresh live DOM scan from the content script if available
      try {
        const live = await chrome.tabs.sendMessage(tabId, { type: 'RUN_FRESH_SCAN' });
        if (live && live.ok && live.domResult) {
          freshDomResult = live.domResult;
          contentDurationMs = live.durationMs || 0;
        }
      } catch (_err) {
        // Fallback to cached DOM findings on internal/uninjected pages
        const existing = tabReports.get(tabId);
        if (existing) {
          const domCategories = new Set(['dom', 'brand', 'iframe', 'script']);
          freshDomResult = {
            findings: (existing.findings || []).filter((f) => domCategories.has(f.category)),
            stats: existing.domStats
          };
        }
      }

      const report = await evaluateTab(tabId, url, freshDomResult, contentDurationMs);
      try {
        await chrome.tabs.sendMessage(tabId, { type: 'UPDATE_BANNER', report });
      } catch (_err) {
        // Content script might not be injected on internal pages
      }
      sendResponse({ ok: true, report });
    })().catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (message.type === 'WHITELIST_TOGGLE') {
    (async () => {
      const domain = String(message.domain || '').toLowerCase().trim();
      const settings = await getSettings();
      const set = new Set(settings.whitelist.map((d) => d.toLowerCase()));
      let whitelisted = false;

      if (domain) {
        if (set.has(domain)) {
          set.delete(domain);
          whitelisted = false;
        } else {
          set.add(domain);
          whitelisted = true;
        }
      }

      const updatedWhitelist = Array.from(set).sort();
      await chrome.storage.local.set({ whitelist: updatedWhitelist });

      let report = null;
      if (typeof message.tabId === 'number' && message.url) {
        const existing = tabReports.get(message.tabId);
        const domCats = new Set(['dom', 'brand', 'iframe', 'script']);
        const cachedDomFindings = existing
          ? { findings: (existing.findings || []).filter((f) => domCats.has(f.category)), stats: existing.domStats }
          : null;
        report = await evaluateTab(message.tabId, message.url, cachedDomFindings, 0);
        try {
          await chrome.tabs.sendMessage(message.tabId, { type: 'UPDATE_BANNER', report });
        } catch (_err) {
          // ignore
        }
      }

      sendResponse({ ok: true, whitelisted, whitelist: updatedWhitelist, report });
    })().catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (message.type === 'UPDATE_SETTINGS') {
    (async () => {
      const patch = {};
      if (message.sensitivity && ['low', 'medium', 'high'].includes(message.sensitivity)) {
        patch.sensitivity = message.sensitivity;
      }
      if (typeof message.showBanner === 'boolean') {
        patch.showBanner = message.showBanner;
      }
      if (Array.isArray(message.protectedDomains)) {
        patch.protectedDomains = message.protectedDomains
          .map((d) => String(d).toLowerCase().trim())
          .filter(Boolean);
      }
      await chrome.storage.local.set(patch);
      const settings = await getSettings();

      let report = null;
      if (typeof message.tabId === 'number' && message.url) {
        const existing = tabReports.get(message.tabId);
        const domCats = new Set(['dom', 'brand', 'iframe', 'script']);
        const cachedDomFindings = existing
          ? { findings: (existing.findings || []).filter((f) => domCats.has(f.category)), stats: existing.domStats }
          : null;
        report = await evaluateTab(message.tabId, message.url, cachedDomFindings, 0);
        try {
          await chrome.tabs.sendMessage(message.tabId, { type: 'UPDATE_BANNER', report });
        } catch (_err) {
          // ignore
        }
      }

      sendResponse({ ok: true, settings, report });
    })().catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  return false;
});
