'use strict';

/**
 * PhishGuard Local - Popup Controller
 * Renders precision verdict telemetry, 6-category interactive heuristic check matrix,
 * live DOM stats, one-click Re-scan & JSON report export, redirect trace,
 * sensitivity controls, and local whitelist management.
 */
(function () {
  const HEURISTIC_CHECKS = [
    { category: 'url', label: 'Domain Similarity & IDN' },
    { category: 'dom', label: 'Form Action & Credentials' },
    { category: 'brand', label: 'Brand & Favicon Integrity' },
    { category: 'iframe', label: 'Iframe & Overlay Security' },
    { category: 'script', label: 'Script & Obfuscation Audit' },
    { category: 'redirect', label: 'Redirect Chain & Protocol' }
  ];

  let activeTab = null;
  let currentReport = null;
  let currentSettings = null;
  let copyResetTimer = null;
  let exportResetTimer = null;

  const els = {
    brandDot: document.getElementById('brandDot'),
    perfPill: document.getElementById('perfPill'),
    statusCard: document.getElementById('statusCard'),
    statusBadge: document.getElementById('statusBadge'),
    domainName: document.getElementById('domainName'),
    scoreValue: document.getElementById('scoreValue'),
    urlPreview: document.getElementById('urlPreview'),
    copyUrlBtn: document.getElementById('copyUrlBtn'),
    copyUrlLabel: document.getElementById('copyUrlLabel'),
    whitelistToggleBtn: document.getElementById('whitelistToggleBtn'),
    whitelistBtnText: document.getElementById('whitelistBtnText'),
    rescanBtn: document.getElementById('rescanBtn'),
    exportReportBtn: document.getElementById('exportReportBtn'),
    exportBtnLabel: document.getElementById('exportBtnLabel'),
    findingsCount: document.getElementById('findingsCount'),
    telemetryStrip: document.getElementById('telemetryStrip'),
    statForms: document.getElementById('statForms'),
    statLinks: document.getElementById('statLinks'),
    statIframes: document.getElementById('statIframes'),
    statScripts: document.getElementById('statScripts'),
    findingsList: document.getElementById('findingsList'),
    redirectSection: document.getElementById('redirectSection'),
    redirectCount: document.getElementById('redirectCount'),
    redirectTrace: document.getElementById('redirectTrace'),
    sensitivityGroup: document.getElementById('sensitivityGroup'),
    showBannerToggle: document.getElementById('showBannerToggle'),
    whitelistCount: document.getElementById('whitelistCount'),
    addWhitelistForm: document.getElementById('addWhitelistForm'),
    whitelistInput: document.getElementById('whitelistInput'),
    whitelistItems: document.getElementById('whitelistItems'),
    footerMeta: document.getElementById('footerMeta')
  };

  function setupTabs() {
    const buttons = document.querySelectorAll('.tab-btn');
    buttons.forEach((btn) => {
      btn.addEventListener('click', () => {
        buttons.forEach((b) => {
          b.classList.remove('active');
          b.setAttribute('aria-selected', 'false');
        });
        document.querySelectorAll('.tab-panel').forEach((p) => p.classList.remove('active'));
        btn.classList.add('active');
        btn.setAttribute('aria-selected', 'true');
        const target = document.getElementById(`tab-${btn.dataset.tab}`);
        if (target) target.classList.add('active');
      });
    });
  }

  function resolveVerdictBadge(report) {
    if (!report) return 'IDLE';
    if (report.ignored) return 'INTERNAL';
    if (report.whitelisted) return 'VERIFIED';
    if (report.status === 'danger') return 'DANGER';
    if (report.status === 'warning') return 'WARNING';
    return 'SAFE';
  }

  function buildPassTelemetryNote(category, report) {
    if (!report || report.ignored) return 'Inspection skipped on internal browser page.';
    const dom = report.registrableDomain || report.hostname || 'page';
    const stats = report.domStats || {};
    const redir = report.redirectSummary || { hops: 0, crossDomainHops: 0 };

    if (category === 'url') {
      return `eTLD+1: ${dom}${report.isTrusted ? ' (Trusted Seed)' : ''} \u2022 0 homographs, 0 typosquats`;
    }
    if (category === 'dom') {
      const forms = stats.loginForms || 0;
      const same = stats.sameSiteForms || 0;
      const oauth = stats.oauthForms || 0;
      const linkCount = stats.totalLinks ?? stats.inspectedLinks ?? 0;
      return `${forms} credential ${forms === 1 ? 'form' : 'forms'} (${same} same-site, ${oauth} OAuth) \u2022 ${linkCount} links scanned`;
    }
    if (category === 'brand') {
      return `Page title, metadata, and favicon are consistent with ${dom}.`;
    }
    if (category === 'iframe') {
      return `${stats.iframes || 0} iframes scanned \u2022 0 untrusted overlays or hidden frames`;
    }
    if (category === 'script') {
      const scriptCount = stats.totalScripts ?? stats.scripts ?? 0;
      return `${scriptCount} scripts scanned \u2022 0 obfuscated kits detected`;
    }
    const proto = (report.protocol || 'https:').replace(':', '').toUpperCase();
    return `${proto} transport \u2022 ${redir.crossDomainHops || 0} cross-domain redirect hops`;
  }

  function renderHeuristicMatrix(findings, report, isUnavailable) {
    els.findingsList.innerHTML = '';

    const byCategory = {
      url: [],
      dom: [],
      brand: [],
      iframe: [],
      script: [],
      redirect: []
    };

    for (const f of findings) {
      const cat = byCategory[f.category] ? f.category : 'url';
      byCategory[cat].push(f);
    }

    for (const check of HEURISTIC_CHECKS) {
      const matches = byCategory[check.category] || [];
      const hasHigh = matches.some((m) => m.severity === 'high');
      const stateClass = isUnavailable
        ? 'state-na'
        : (matches.length === 0 ? 'state-pass' : (hasHigh ? 'state-danger' : 'state-warning'));

      const row = document.createElement('div');
      row.className = `check-row ${stateClass}`;

      const head = document.createElement('div');
      head.className = 'check-row-head';

      const nameEl = document.createElement('span');
      nameEl.className = 'check-name';
      nameEl.textContent = check.label;

      const statusEl = document.createElement('span');
      if (isUnavailable) {
        statusEl.className = 'check-status na';
        statusEl.textContent = 'N/A';
      } else if (matches.length === 0) {
        statusEl.className = 'check-status pass';
        statusEl.textContent = 'Pass';
      } else {
        statusEl.className = `check-status ${hasHigh ? 'fail' : 'warn'}`;
        statusEl.textContent = `${matches.length} ${matches.length === 1 ? 'alert' : 'alerts'}`;
      }

      head.appendChild(nameEl);
      head.appendChild(statusEl);
      row.appendChild(head);

      if (matches.length > 0) {
        const list = document.createElement('div');
        list.className = 'check-findings';

        for (const f of matches) {
          const entry = document.createElement('div');
          entry.className = 'finding-entry';

          const entryHead = document.createElement('div');
          entryHead.className = 'finding-entry-head';

          const titleEl = document.createElement('span');
          titleEl.className = 'finding-entry-title';
          titleEl.textContent = f.title;

          const metaEl = document.createElement('span');
          metaEl.className = 'finding-entry-meta';

          const sevTag = document.createElement('span');
          const sev = f.severity === 'high' ? 'high' : 'medium';
          sevTag.className = `sev-tag ${sev}`;
          sevTag.textContent = sev === 'high' ? 'HIGH' : 'WARN';

          const weightEl = document.createElement('span');
          weightEl.className = 'finding-weight';
          weightEl.textContent = `+${f.score}`;

          metaEl.appendChild(sevTag);
          metaEl.appendChild(weightEl);

          entryHead.appendChild(titleEl);
          entryHead.appendChild(metaEl);

          const detailEl = document.createElement('div');
          detailEl.className = 'finding-entry-detail';
          detailEl.textContent = f.detail;

          entry.appendChild(entryHead);
          entry.appendChild(detailEl);
          list.appendChild(entry);
        }

        row.appendChild(list);
      } else {
        // Click-to-inspect telemetry detail for passing / N/A checks
        const note = document.createElement('div');
        note.className = 'check-telemetry-note';
        note.textContent = buildPassTelemetryNote(check.category, report);
        note.hidden = true;
        row.appendChild(note);

        row.addEventListener('click', () => {
          note.hidden = !note.hidden;
        });
      }

      els.findingsList.appendChild(row);
    }
  }

  function updateFooterMeta(settings) {
    if (!els.footerMeta || !settings) return;
    const sens = settings.sensitivity
      ? settings.sensitivity.charAt(0).toUpperCase() + settings.sensitivity.slice(1)
      : 'Medium';
    const count = Array.isArray(settings.whitelist) ? settings.whitelist.length : 0;
    els.footerMeta.textContent = `${sens} \u2022 ${count} trusted`;
  }

  function renderReport(report) {
    currentReport = report;

    if (!report) {
      els.statusCard.className = 'verdict-hero safe';
      if (els.brandDot) els.brandDot.className = 'status-dot safe';
      els.statusBadge.textContent = 'IDLE';
      els.domainName.textContent = 'No active web page';
      els.urlPreview.textContent = 'Open an http:// or https:// page to inspect.';
      els.urlPreview.title = '';
      if (els.copyUrlBtn) els.copyUrlBtn.hidden = true;
      els.scoreValue.textContent = '0';
      els.perfPill.textContent = '--ms';
      els.whitelistToggleBtn.disabled = true;
      els.whitelistToggleBtn.classList.remove('is-trusted');
      if (els.whitelistBtnText) els.whitelistBtnText.textContent = 'Whitelist unavailable';
      if (els.rescanBtn) els.rescanBtn.disabled = true;
      if (els.exportReportBtn) els.exportReportBtn.disabled = true;
      if (els.telemetryStrip) els.telemetryStrip.hidden = true;
      els.findingsCount.textContent = 'N/A';
      renderHeuristicMatrix([], null, true);
      els.redirectSection.hidden = true;
      return;
    }

    const status = report.status || 'safe';
    const isIgnored = Boolean(report.ignored);
    els.statusCard.className = `verdict-hero ${status}`;
    if (els.brandDot) els.brandDot.className = `status-dot ${status}`;
    els.statusBadge.textContent = resolveVerdictBadge(report);
    els.domainName.textContent = report.hostname || report.registrableDomain || 'Internal Page';
    els.urlPreview.textContent = report.url || '-';
    els.urlPreview.title = report.url || '';
    if (els.copyUrlBtn) els.copyUrlBtn.hidden = !report.url;
    els.scoreValue.textContent = String(report.score ?? 0);

    const ms = typeof report.analysisDurationMs === 'number'
      ? Number(report.analysisDurationMs.toFixed(1))
      : 0;
    els.perfPill.textContent = `${ms}ms`;

    if (els.rescanBtn) els.rescanBtn.disabled = isIgnored;
    if (els.exportReportBtn) els.exportReportBtn.disabled = isIgnored;

    if (isIgnored || !report.registrableDomain) {
      els.whitelistToggleBtn.disabled = true;
      els.whitelistToggleBtn.classList.remove('is-trusted');
      if (els.whitelistBtnText) els.whitelistBtnText.textContent = 'Internal page';
    } else {
      els.whitelistToggleBtn.disabled = false;
      els.whitelistToggleBtn.classList.toggle('is-trusted', Boolean(report.whitelisted));
      if (els.whitelistBtnText) {
        els.whitelistBtnText.textContent = report.whitelisted
          ? `Trusted: ${report.registrableDomain}`
          : `Trust ${report.registrableDomain}`;
      }
    }

    // Live DOM telemetry strip
    const stats = report.domStats || {};
    if (els.telemetryStrip) {
      els.telemetryStrip.hidden = isIgnored;
      if (!isIgnored) {
        els.statForms.textContent = `Forms: ${stats.loginForms || 0}`;
        els.statLinks.textContent = `Links: ${stats.totalLinks ?? stats.inspectedLinks ?? 0}`;
        els.statIframes.textContent = `Iframes: ${stats.iframes || 0}`;
        els.statScripts.textContent = `Scripts: ${stats.totalScripts ?? stats.scripts ?? 0}`;
      }
    }

    // Heuristic Check Matrix & Findings
    const findings = report.findings || [];
    if (isIgnored) {
      els.findingsCount.textContent = 'N/A';
    } else if (findings.length === 0) {
      els.findingsCount.textContent = `${HEURISTIC_CHECKS.length}/${HEURISTIC_CHECKS.length} pass`;
    } else {
      els.findingsCount.textContent = `${findings.length} ${findings.length === 1 ? 'alert' : 'alerts'}`;
    }
    renderHeuristicMatrix(findings, report, isIgnored);

    // Redirect chain summary
    const redir = report.redirectSummary || { hops: 0, uniqueDomains: [] };
    if (redir.hops > 0) {
      els.redirectSection.hidden = false;
      els.redirectCount.textContent = `${redir.hops} ${redir.hops === 1 ? 'hop' : 'hops'}`;
      els.redirectTrace.innerHTML = '';

      if (redir.uniqueDomains.length > 0) {
        redir.uniqueDomains.forEach((dom, index) => {
          const chip = document.createElement('span');
          chip.className = 'hop-chip';
          chip.textContent = dom;
          els.redirectTrace.appendChild(chip);
          if (index < redir.uniqueDomains.length - 1) {
            const arrow = document.createElement('span');
            arrow.className = 'hop-arrow';
            arrow.textContent = '\u2192';
            els.redirectTrace.appendChild(arrow);
          }
        });
      } else {
        els.redirectTrace.textContent = `${redir.hops} redirects detected.`;
      }
    } else {
      els.redirectSection.hidden = true;
    }
  }

  function renderSettings(settings) {
    currentSettings = settings;
    if (!settings) return;

    const segButtons = els.sensitivityGroup.querySelectorAll('.seg-btn');
    segButtons.forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.level === settings.sensitivity);
    });

    els.showBannerToggle.checked = settings.showBanner !== false;

    const list = settings.whitelist || [];
    els.whitelistCount.textContent = String(list.length);
    els.whitelistItems.innerHTML = '';
    updateFooterMeta(settings);

    if (list.length === 0) {
      const li = document.createElement('li');
      li.className = 'empty-row';
      li.textContent = 'No trusted domains added yet.';
      els.whitelistItems.appendChild(li);
      return;
    }

    for (const domain of list) {
      const li = document.createElement('li');
      const span = document.createElement('span');
      span.textContent = domain;

      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'remove-btn';
      btn.textContent = 'Remove';
      btn.addEventListener('click', () => toggleWhitelistDomain(domain));

      li.appendChild(span);
      li.appendChild(btn);
      els.whitelistItems.appendChild(li);
    }
  }

  async function toggleWhitelistDomain(domain) {
    if (!domain) return;
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'WHITELIST_TOGGLE',
        domain,
        tabId: activeTab ? activeTab.id : undefined,
        url: activeTab ? activeTab.url : undefined
      });
      if (response && response.ok) {
        if (currentSettings) {
          currentSettings.whitelist = response.whitelist;
          renderSettings(currentSettings);
        }
        if (response.report) {
          renderReport(response.report);
        }
      }
    } catch (_err) {
      // Service worker unavailable
    }
  }

  async function updateSettings(patch) {
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'UPDATE_SETTINGS',
        ...patch,
        tabId: activeTab ? activeTab.id : undefined,
        url: activeTab ? activeTab.url : undefined
      });
      if (response && response.ok) {
        renderSettings(response.settings);
        if (response.report) {
          renderReport(response.report);
        }
      }
    } catch (_err) {
      // Service worker unavailable
    }
  }

  async function runRescan() {
    if (!activeTab || !els.rescanBtn) return;
    els.rescanBtn.classList.add('spinning');
    els.rescanBtn.disabled = true;
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'REANALYZE_TAB',
        tabId: activeTab.id,
        url: activeTab.url
      });
      if (response && response.ok && response.report) {
        renderReport(response.report);
      }
    } catch (_err) {
      // Service worker unavailable
    } finally {
      setTimeout(() => {
        els.rescanBtn.classList.remove('spinning');
        els.rescanBtn.disabled = Boolean(!currentReport || currentReport.ignored);
      }, 300);
    }
  }

  async function exportReportJson() {
    if (!currentReport || !navigator.clipboard) return;
    const payload = {
      tool: 'PhishGuard Local',
      scannedAt: new Date(currentReport.timestamp || Date.now()).toISOString(),
      url: currentReport.url,
      hostname: currentReport.hostname,
      eTLDPlus1: currentReport.registrableDomain,
      verdict: resolveVerdictBadge(currentReport),
      riskScore: currentReport.score,
      sensitivity: currentReport.sensitivity,
      trustedSeed: Boolean(currentReport.isTrusted),
      whitelisted: Boolean(currentReport.whitelisted),
      analysisDurationMs: currentReport.analysisDurationMs,
      domStats: currentReport.domStats,
      redirectSummary: currentReport.redirectSummary,
      findings: currentReport.findings
    };

    try {
      await navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
      els.exportReportBtn.classList.add('copied');
      if (els.exportBtnLabel) els.exportBtnLabel.textContent = 'Copied';
      if (exportResetTimer) clearTimeout(exportResetTimer);
      exportResetTimer = setTimeout(() => {
        els.exportReportBtn.classList.remove('copied');
        if (els.exportBtnLabel) els.exportBtnLabel.textContent = 'JSON';
      }, 1500);
    } catch (_err) {
      // Clipboard write denied
    }
  }

  async function copyCurrentUrl() {
    if (!currentReport || !currentReport.url || !navigator.clipboard) return;
    try {
      await navigator.clipboard.writeText(currentReport.url);
      els.copyUrlBtn.classList.add('copied');
      if (els.copyUrlLabel) els.copyUrlLabel.textContent = 'Copied';
      if (copyResetTimer) clearTimeout(copyResetTimer);
      copyResetTimer = setTimeout(() => {
        els.copyUrlBtn.classList.remove('copied');
        if (els.copyUrlLabel) els.copyUrlLabel.textContent = 'Copy';
      }, 1400);
    } catch (_err) {
      // Clipboard write denied
    }
  }

  async function init() {
    setupTabs();

    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      activeTab = tabs && tabs[0] ? tabs[0] : null;

      if (activeTab) {
        const response = await chrome.runtime.sendMessage({
          type: 'GET_TAB_REPORT',
          tabId: activeTab.id,
          url: activeTab.url
        });
        if (response && response.ok) {
          renderReport(response.report);
          renderSettings(response.settings);
        } else {
          renderReport(null);
        }
      } else {
        renderReport(null);
      }
    } catch (_err) {
      renderReport(null);
    }

    if (els.copyUrlBtn) {
      els.copyUrlBtn.addEventListener('click', copyCurrentUrl);
    }

    if (els.rescanBtn) {
      els.rescanBtn.addEventListener('click', runRescan);
    }

    if (els.exportReportBtn) {
      els.exportReportBtn.addEventListener('click', exportReportJson);
    }

    els.whitelistToggleBtn.addEventListener('click', () => {
      if (currentReport && currentReport.registrableDomain) {
        toggleWhitelistDomain(currentReport.registrableDomain);
      }
    });

    els.sensitivityGroup.querySelectorAll('.seg-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        updateSettings({ sensitivity: btn.dataset.level });
      });
    });

    els.showBannerToggle.addEventListener('change', () => {
      updateSettings({ showBanner: els.showBannerToggle.checked });
    });

    els.addWhitelistForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const raw = els.whitelistInput.value.trim().toLowerCase()
        .replace(/^https?:\/\//, '')
        .replace(/\/.*$/, '');
      if (!raw) return;
      els.whitelistInput.value = '';
      if (currentSettings && currentSettings.whitelist.includes(raw)) return;
      toggleWhitelistDomain(raw);
    });
  }

  document.addEventListener('DOMContentLoaded', init);
})();
