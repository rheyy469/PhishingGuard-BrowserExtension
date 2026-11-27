'use strict';

/**
 * PhishGuard Local - Weighted Risk Scoring & Redirect Chain Engine
 * Combines URL analysis, DOM inspection, and eTLD+1/OAuth-aware redirect monitoring.
 * Default weighted scoring model (Medium):
 *  - 0–24  : SAFE
 *  - 25–59 : WARNING
 *  - 60–100: DANGER
 */
(function (root) {
  const urlAnalyzer = (typeof module !== 'undefined' && module.exports)
    ? require('./url_analyzer.js')
    : root.PhishGuardUrlAnalyzer;

  const SENSITIVITY_THRESHOLDS = {
    low: { warning: 40, danger: 75 },
    medium: { warning: 25, danger: 60 },
    high: { warning: 15, danger: 45 }
  };

  /**
   * Analyze a redirect chain using eTLD+1 collapsing, sibling grouping,
   * OAuth/SSO filtering, and trusted-landing dampening to eliminate false positives.
   * @param {Array<{url: string, timestamp?: number}>} redirectChain
   * @param {{ landingTrusted?: boolean, landingDomain?: string }} [options]
   */
  function analyzeRedirectChain(redirectChain, options) {
    const opts = options || {};
    const findings = [];
    if (!Array.isArray(redirectChain) || redirectChain.length < 2) {
      return { findings, hops: 0, uniqueDomains: [], crossDomainHops: 0 };
    }

    const totalHops = redirectChain.length - 1;
    const orderedDomains = [];
    const nonOAuthDomains = [];
    let crossDomainHops = 0;
    let prevHost = null;

    for (const step of redirectChain) {
      try {
        const u = new URL(step.url);
        const host = u.hostname.toLowerCase();
        const parts = urlAnalyzer.parseDomainParts(host);
        const dom = parts.registrableDomain || host;

        if (dom && !orderedDomains.includes(dom)) {
          orderedDomains.push(dom);
        }

        const isOAuthHop = urlAnalyzer.isKnownOAuthProvider(u.href);
        if (prevHost && !urlAnalyzer.areSameSiteOrSibling(prevHost, host) && !isOAuthHop) {
          crossDomainHops++;
        }

        if (dom && !isOAuthHop) {
          const alreadyGrouped = nonOAuthDomains.some((existing) =>
            urlAnalyzer.areSameSiteOrSibling(existing, dom)
          );
          if (!alreadyGrouped) {
            nonOAuthDomains.push(dom);
          }
        }

        prevHost = host;
      } catch (_err) {
        // ignore invalid URL entry
      }
    }

    const uniqueExternalCount = nonOAuthDomains.length;
    const lastEntry = redirectChain[redirectChain.length - 1];
    let landingTrusted = Boolean(opts.landingTrusted);
    let landingIsLoopback = false;
    try {
      const lastUrl = new URL(lastEntry.url);
      if (!opts.landingTrusted) {
        landingTrusted = urlAnalyzer.isTrustedDomain(lastUrl.hostname);
      }
      landingIsLoopback = urlAnalyzer.isLoopbackHost(lastUrl.hostname);
    } catch (_err) {
      // ignore
    }

    // Same-site / sibling-only redirects on trusted platforms (e.g. id.pinterest.com -> www.pinterest.com) -> 0 risk
    if (uniqueExternalCount <= 1 && !landingIsLoopback) {
      if (!landingTrusted && totalHops >= 3) {
        findings.push({
          id: 'REDIRECT_CHAIN_EXCESSIVE',
          category: 'redirect',
          severity: 'medium',
          score: 25,
          title: 'Unusual Consecutive Redirect Chain',
          detail: `Detected ${totalHops} consecutive redirects on untrusted eTLD+1 "${orderedDomains[orderedDomains.length - 1] || ''}" (+25).`
        });
      }
      return {
        findings,
        hops: totalHops,
        uniqueDomains: orderedDomains,
        crossDomainHops
      };
    }

    // Reputable/trusted landing domain: 1–2 regional/tracking redirects must NOT push into WARNING
    if (landingTrusted) {
      if (uniqueExternalCount >= 4 && crossDomainHops >= 3) {
        findings.push({
          id: 'REDIRECT_CHAIN_TRUSTED_EXCESSIVE',
          category: 'redirect',
          severity: 'medium',
          score: 15,
          title: 'Multi-Hop Redirect to Trusted Domain',
          detail: `Passed through ${totalHops} hops across ${uniqueExternalCount} eTLD+1 domains (${nonOAuthDomains.join(' -> ')}) before landing on trusted domain (+15).`
        });
      }
      return {
        findings,
        hops: totalHops,
        uniqueDomains: orderedDomains,
        crossDomainHops
      };
    }

    // Untrusted / unknown landing domain (or localhost simulation)
    if (uniqueExternalCount >= 3 || (totalHops >= 3 && uniqueExternalCount >= 2)) {
      findings.push({
        id: 'REDIRECT_CHAIN_CROSS_DOMAIN_HIGH',
        category: 'redirect',
        severity: 'high',
        score: 55,
        title: 'Suspicious Cross-Domain Redirect Chain',
        detail: `Passed through ${totalHops} redirects across ${uniqueExternalCount} unrelated eTLD+1 domains (${nonOAuthDomains.join(' -> ')}, +55).`
      });
    } else if (totalHops >= 2 && uniqueExternalCount >= 2) {
      findings.push({
        id: 'REDIRECT_CHAIN_CROSS_DOMAIN',
        category: 'redirect',
        severity: 'medium',
        score: 30,
        title: 'Consecutive Cross-Domain Redirects',
        detail: `Detected ${totalHops} redirects across different eTLD+1 domains (${nonOAuthDomains.join(' -> ')}, +30).`
      });
    } else if (totalHops >= 3) {
      findings.push({
        id: 'REDIRECT_CHAIN_EXCESSIVE',
        category: 'redirect',
        severity: 'medium',
        score: 30,
        title: 'Unusual Consecutive Redirect Chain',
        detail: `Detected ${totalHops} consecutive redirects before the final page loaded (+30).`
      });
    }

    return {
      findings,
      hops: totalHops,
      uniqueDomains: orderedDomains,
      crossDomainHops
    };
  }

  /**
   * Check whether a hostname or registrableDomain is in the user's local whitelist.
   */
  function isWhitelisted(hostname, registrableDomain, whitelist) {
    if (!Array.isArray(whitelist) || whitelist.length === 0) return false;
    const h = (hostname || '').toLowerCase();
    const r = (registrableDomain || '').toLowerCase();
    return whitelist.some((entry) => {
      const clean = String(entry || '').toLowerCase().trim();
      return clean && (clean === h || clean === r || h.endsWith('.' + clean));
    });
  }

  /**
   * Deduplicate findings by id+detail and compute aggregate weighted risk score (0–100) and status.
   */
  function evaluateRisk(params) {
    const {
      urlResult,
      domResult,
      redirectChain = [],
      whitelist = [],
      sensitivity = 'medium',
      analysisDurationMs = 0
    } = params || {};

    const hostname = (urlResult && urlResult.hostname) || '';
    const registrableDomain = (urlResult && urlResult.registrableDomain) || '';
    const isTrusted = Boolean(urlResult && urlResult.isTrusted);

    const redirectResult = analyzeRedirectChain(redirectChain, {
      landingTrusted: isTrusted,
      landingDomain: registrableDomain
    });

    const allFindings = [
      ...((urlResult && urlResult.findings) || []),
      ...((domResult && domResult.findings) || []),
      ...redirectResult.findings
    ];

    // Deduplicate identical findings
    const seen = new Set();
    const findings = [];
    for (const f of allFindings) {
      const key = `${f.id}:${f.detail}`;
      if (!seen.has(key)) {
        seen.add(key);
        findings.push(f);
      }
    }

    const whitelisted = isWhitelisted(hostname, registrableDomain, whitelist);

    // Multi-Signal Cross-Category Correlation Amplifier (for untrusted sites with 2+ distinct attack surfaces)
    if (!isTrusted && !whitelisted) {
      const triggeredCategories = new Set(findings.map((f) => f.category).filter(Boolean));
      const baseScore = findings.reduce((sum, f) => sum + (f.score || 0), 0);
      if (triggeredCategories.size >= 2 && baseScore >= 35) {
        findings.push({
          id: 'MULTI_SIGNAL_CORRELATION',
          category: 'url',
          severity: 'high',
          score: 15,
          title: 'Multi-Vector Phishing Signals Correlated',
          detail: `Detected coordinated anomalies across ${triggeredCategories.size} independent layers (${Array.from(triggeredCategories).join(', ')}) on untrusted eTLD+1 "${registrableDomain}" (+15).`
        });
      }
    }

    const rawScore = findings.reduce((sum, f) => sum + (f.score || 0), 0);
    const score = Math.min(100, rawScore);

    const thresholds = SENSITIVITY_THRESHOLDS[sensitivity] || SENSITIVITY_THRESHOLDS.medium;
    const hasHighFinding = findings.some((f) => f.severity === 'high');

    let status = 'safe';
    if (!whitelisted) {
      if (score >= thresholds.danger || (hasHighFinding && score >= 55)) {
        status = 'danger';
      } else if (score >= thresholds.warning) {
        status = 'warning';
      }
    }

    const statusLabelMap = {
      safe: 'Safe',
      warning: 'Caution',
      danger: 'High Risk'
    };

    const domStats = (domResult && domResult.stats) || {
      loginForms: 0,
      inspectedLinks: 0,
      sameSiteForms: 0,
      oauthForms: 0,
      iframes: 0,
      scripts: 0
    };

    return {
      url: (urlResult && urlResult.url) || '',
      hostname,
      registrableDomain,
      protocol: (urlResult && urlResult.protocol) || '',
      isTrusted,
      status,
      statusLabel: whitelisted ? 'Safe (Whitelisted)' : statusLabelMap[status],
      score: whitelisted ? 0 : score,
      rawScore: score,
      whitelisted,
      sensitivity,
      findings,
      domStats,
      redirectSummary: {
        hops: redirectResult.hops,
        crossDomainHops: redirectResult.crossDomainHops,
        uniqueDomains: redirectResult.uniqueDomains
      },
      analysisDurationMs: Number(analysisDurationMs.toFixed(2)),
      timestamp: Date.now()
    };
  }

  const exportsObj = {
    SENSITIVITY_THRESHOLDS,
    analyzeRedirectChain,
    isWhitelisted,
    evaluateRisk
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportsObj;
  }
  root.PhishGuardRiskEngine = exportsObj;
})(typeof globalThis !== 'undefined' ? globalThis : this);
