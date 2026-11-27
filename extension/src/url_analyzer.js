'use strict';

/**
 * PhishGuard Local - Offline eTLD+1 Parser, Sibling/OAuth Resolver & Typosquatting Engine
 * 100% client-side, zero network requests, deterministic < 5ms execution.
 */
(function (root) {
  const domainData = (typeof module !== 'undefined' && module.exports)
    ? require('./domains.js')
    : root.PhishGuardDomains;

  const MULTI_PART_TLDS = domainData.MULTI_PART_TLDS;
  const FREE_HOSTING_SUFFIXES = domainData.FREE_HOSTING_SUFFIXES || new Set();
  const SUSPICIOUS_TLDS = domainData.SUSPICIOUS_TLDS;
  const DEFAULT_PROTECTED_DOMAINS = domainData.DEFAULT_PROTECTED_DOMAINS;
  const TOP_TRUSTED_DOMAINS = domainData.TOP_TRUSTED_DOMAINS || new Set(DEFAULT_PROTECTED_DOMAINS);
  const SIBLING_GROUP_INDEX = domainData.SIBLING_GROUP_INDEX || new Map();
  const KNOWN_OAUTH_HOSTS = domainData.KNOWN_OAUTH_HOSTS || new Set();
  const KNOWN_OAUTH_DOMAINS = domainData.KNOWN_OAUTH_DOMAINS || new Set();

  // Common lure affixes concatenated onto brand names in combosquatting (e.g., paypallogin.com)
  const COMBO_LURE_TOKENS = [
    'login', 'signin', 'logon', 'auth', 'verify', 'verification', 'secure', 'security',
    'account', 'update', 'support', 'wallet', 'portal', 'billing', 'recover', 'recovery',
    'service', 'online', 'banking', 'confirm', 'official', 'helpdesk', 'alert', 'claim'
  ];

  // Confusable character map (leetspeak + common Cyrillic/Greek lookalikes -> Latin)
  const CONFUSABLE_MAP = {
    '0': 'o',
    '1': 'l',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '6': 'g',
    '7': 't',
    '8': 'b',
    '@': 'a',
    '$': 's',
    // Cyrillic lookalikes
    '\u0430': 'a', // а
    '\u0435': 'e', // е
    '\u043e': 'o', // о
    '\u0440': 'p', // р
    '\u0441': 'c', // с
    '\u0443': 'y', // у
    '\u0445': 'x', // х
    '\u0456': 'i', // і
    '\u0458': 'j', // ј
    '\u04bb': 'h', // һ
    '\u0501': 'd', // ԁ
    // Greek lookalikes
    '\u03b1': 'a', // α
    '\u03bf': 'o', // ο
    '\u03c1': 'p', // ρ
    '\u03b5': 'e', // ε
    '\u03b9': 'i'  // ι
  };

  /**
   * Classic Levenshtein distance using O(min(m, n)) memory.
   */
  function levenshteinDistance(a, b) {
    if (a === b) return 0;
    if (!a.length) return b.length;
    if (!b.length) return a.length;

    if (a.length > b.length) {
      const tmp = a;
      a = b;
      b = tmp;
    }

    const m = a.length;
    const n = b.length;
    let prev = new Array(m + 1);
    let curr = new Array(m + 1);

    for (let i = 0; i <= m; i++) prev[i] = i;

    for (let j = 1; j <= n; j++) {
      curr[0] = j;
      const bj = b.charCodeAt(j - 1);
      for (let i = 1; i <= m; i++) {
        const cost = a.charCodeAt(i - 1) === bj ? 0 : 1;
        const del = prev[i] + 1;
        const ins = curr[i - 1] + 1;
        const sub = prev[i - 1] + cost;
        curr[i] = del < ins ? (del < sub ? del : sub) : (ins < sub ? ins : sub);
      }
      const swap = prev;
      prev = curr;
      curr = swap;
    }

    return prev[m];
  }

  /**
   * Normalize visual confusables (e.g., paypa1 -> paypal, g00gle -> google, rn -> m).
   */
  function normalizeConfusables(str) {
    let out = '';
    const lower = str.toLowerCase();
    for (let i = 0; i < lower.length; i++) {
      const ch = lower[i];
      out += CONFUSABLE_MAP[ch] || ch;
    }
    return out.replace(/rn/g, 'm').replace(/vv/g, 'w');
  }

  function isIPv4(hostname) {
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return false;
    return hostname.split('.').every((part) => {
      const n = Number(part);
      return n >= 0 && n <= 255;
    });
  }

  function isIPv6(hostname) {
    return hostname.startsWith('[') && hostname.endsWith(']') && hostname.includes(':');
  }

  function isLoopbackHost(hostname) {
    const h = (hostname || '').toLowerCase();
    return h === 'localhost' || h === '127.0.0.1' || h === '[::1]' || h === '::1' || h.endsWith('.localhost');
  }

  /**
   * Offline Registrable Domain (eTLD+1) parser.
   * Handles multi-part public suffixes (.co.id, .co.uk, .com.au, .github.io, etc.).
   */
  function parseDomainParts(hostname) {
    const clean = (hostname || '').toLowerCase().replace(/\.$/, '');
    if (!clean || isIPv4(clean) || isIPv6(clean) || !clean.includes('.')) {
      return {
        hostname: clean,
        registrableDomain: clean,
        sld: clean,
        tld: '',
        subdomains: []
      };
    }

    const labels = clean.split('.');
    let tldCount = 1;
    if (labels.length >= 3) {
      const lastTwo = labels.slice(-2).join('.');
      if (MULTI_PART_TLDS.has(lastTwo)) {
        tldCount = 2;
      }
    }

    const registrableLabels = labels.slice(-(tldCount + 1));
    const registrableDomain = registrableLabels.join('.');
    const sld = registrableLabels[0];
    const tld = registrableLabels.slice(1).join('.');
    const subdomains = labels.slice(0, labels.length - (tldCount + 1));

    return {
      hostname: clean,
      registrableDomain,
      sld,
      tld,
      subdomains
    };
  }

  /**
   * Returns true if hostname or its eTLD+1 is in the curated offline TOP_TRUSTED_DOMAINS seed list.
   */
  function isTrustedDomain(hostnameOrDomain) {
    if (!hostnameOrDomain) return false;
    const clean = String(hostnameOrDomain).toLowerCase().trim();
    if (TOP_TRUSTED_DOMAINS.has(clean)) return true;
    const parts = parseDomainParts(clean);
    return Boolean(parts.registrableDomain && TOP_TRUSTED_DOMAINS.has(parts.registrableDomain));
  }

  /**
   * Returns true if two hosts share the same eTLD+1 (Same-Site) or belong to the same
   * official sibling ecosystem (e.g., github.com <-> githubusercontent.com, google.com <-> gstatic.com).
   */
  function areSameSiteOrSibling(hostA, hostB) {
    if (!hostA || !hostB) return false;
    const a = parseDomainParts(hostA);
    const b = parseDomainParts(hostB);
    if (!a.registrableDomain || !b.registrableDomain) return false;
    if (a.registrableDomain === b.registrableDomain) return true;

    const groupA = SIBLING_GROUP_INDEX.get(a.registrableDomain);
    if (groupA !== undefined && groupA === SIBLING_GROUP_INDEX.get(b.registrableDomain)) {
      return true;
    }
    return false;
  }

  /**
   * Returns true if a URL or hostname belongs to a known legitimate OAuth / SSO identity provider.
   */
  function isKnownOAuthProvider(urlOrHost) {
    if (!urlOrHost) return false;
    let host = '';
    try {
      const parsed = /^https?:\/\//i.test(urlOrHost)
        ? new URL(urlOrHost)
        : new URL('https://' + urlOrHost);
      host = parsed.hostname.toLowerCase();
    } catch (_err) {
      host = String(urlOrHost).toLowerCase().trim();
    }
    if (!host) return false;
    if (KNOWN_OAUTH_HOSTS.has(host)) return true;

    const parts = parseDomainParts(host);
    if (parts.registrableDomain && KNOWN_OAUTH_DOMAINS.has(parts.registrableDomain)) {
      return true;
    }
    return false;
  }

  /**
   * Pure offline RFC 3492 Punycode label decoder (decodes xn-- labels to Unicode).
   */
  function decodePunycodeLabel(label) {
    const clean = (label || '').toLowerCase();
    if (!clean.startsWith('xn--')) return clean;
    const input = clean.slice(4);
    const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
    let n = 128, bias = 72, i = 0;
    const output = [];

    const basicEnd = input.lastIndexOf('-');
    let idx = 0;
    if (basicEnd > 0) {
      for (let j = 0; j < basicEnd; j++) {
        output.push(input.charCodeAt(j));
      }
      idx = basicEnd + 1;
    }

    const digitOf = (cp) => {
      if (cp >= 48 && cp <= 57) return cp - 22;      // 0-9 -> 26-35
      if (cp >= 65 && cp <= 90) return cp - 65;      // A-Z -> 0-25
      if (cp >= 97 && cp <= 122) return cp - 97;     // a-z -> 0-25
      return base;
    };

    const adapt = (delta, numPoints, firstTime) => {
      delta = firstTime ? Math.floor(delta / damp) : (delta >> 1);
      delta += Math.floor(delta / numPoints);
      let k = 0;
      while (delta > (((base - tMin) * tMax) >> 1)) {
        delta = Math.floor(delta / (base - tMin));
        k += base;
      }
      return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
    };

    while (idx < input.length) {
      const oldi = i;
      let w = 1;
      for (let k = base; ; k += base) {
        if (idx >= input.length) return clean; // malformed punycode fallback
        const digit = digitOf(input.charCodeAt(idx++));
        if (digit >= base) return clean;
        i += digit * w;
        const t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);
        if (digit < t) break;
        w *= (base - t);
      }
      const outLen = output.length + 1;
      bias = adapt(i - oldi, outLen, oldi === 0);
      n += Math.floor(i / outLen);
      i %= outLen;
      if (n > 0x10FFFF) return clean;
      output.splice(i++, 0, n);
    }

    try {
      return String.fromCodePoint(...output);
    } catch (_err) {
      return clean;
    }
  }

  function decodePunycodeHostname(hostname) {
    return (hostname || '').toLowerCase().split('.').map(decodePunycodeLabel).join('.');
  }

  /**
   * Compute Shannon entropy (bits/char) of a string to detect random DGA hostnames.
   */
  function shannonEntropy(str) {
    if (!str || str.length === 0) return 0;
    const freq = Object.create(null);
    for (let i = 0; i < str.length; i++) {
      const ch = str[i];
      freq[ch] = (freq[ch] || 0) + 1;
    }
    let entropy = 0;
    const len = str.length;
    for (const ch in freq) {
      const p = freq[ch] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  /**
   * Detect Punycode (xn--) or non-ASCII Unicode characters in hostname (IDN Homograph Attack),
   * decoding Punycode locally (RFC 3492) to expose exact spoofed brand names.
   */
  function detectIdnHomograph(hostname, protectedDomains) {
    const labels = (hostname || '').toLowerCase().split('.');
    const hasPunycode = labels.some((l) => l.startsWith('xn--'));
    const hasNonAscii = /[^\x00-\x7F]/.test(hostname || '');

    if (!hasPunycode && !hasNonAscii) {
      return null;
    }

    const decodedHost = hasPunycode ? decodePunycodeHostname(hostname) : hostname.toLowerCase();
    const hasLatin = /[a-zA-Z]/.test(decodedHost);
    const hasCyrillic = /[\u0400-\u04FF]/.test(decodedHost);
    const hasGreek = /[\u0370-\u03FF]/.test(decodedHost);
    const mixedScript = hasLatin && (hasCyrillic || hasGreek);

    // Check if decoded Unicode visually spoofs a protected brand after confusable normalization
    const decodedParts = parseDomainParts(decodedHost);
    const normDecodedSld = normalizeConfusables(decodedParts.sld);
    const list = (protectedDomains && protectedDomains.length > 0)
      ? protectedDomains
      : DEFAULT_PROTECTED_DOMAINS;

    let spoofedBrand = null;
    for (const rawTarget of list) {
      const tParts = parseDomainParts(rawTarget);
      if (tParts.sld && tParts.sld.length >= 4 && normDecodedSld === tParts.sld) {
        spoofedBrand = tParts.registrableDomain;
        break;
      }
    }

    if (spoofedBrand) {
      return {
        id: 'IDN_HOMOGRAPH',
        category: 'url',
        severity: 'high',
        score: 75,
        title: `IDN Homograph Spoofing ${spoofedBrand}`,
        detail: `Host "${hostname}" decodes to "${decodedHost}" and visually impersonates official domain "${spoofedBrand}" (+75).`
      };
    }

    return {
      id: 'IDN_HOMOGRAPH',
      category: 'url',
      severity: 'high',
      score: 65,
      title: 'IDN / Punycode Homograph Detected',
      detail: hasPunycode
        ? `Host "${hostname}" decodes via Punycode to "${decodedHost}"${mixedScript ? ' (mixed Latin & Cyrillic/Greek scripts)' : ''} (+65).`
        : `Host "${hostname}" contains non-ASCII Unicode characters${mixedScript ? ' (mixed Latin & Cyrillic/Greek scripts)' : ''} (+65).`
    };
  }

  /**
   * Detect typosquatting strictly on the eTLD+1 (never comparing raw subdomains).
   * Exact matches in TOP_TRUSTED_DOMAINS immediately return 0 risk.
   */
  function detectTyposquatting(domainParts, protectedDomains) {
    const { hostname, registrableDomain, sld, tld, subdomains } = domainParts;
    if (!registrableDomain || !tld || isLoopbackHost(hostname) || isIPv4(hostname) || isIPv6(hostname)) {
      return [];
    }

    // Exact match in curated TOP_TRUSTED_DOMAINS -> immediately SAFE (0 risk)
    if (TOP_TRUSTED_DOMAINS.has(registrableDomain) || TOP_TRUSTED_DOMAINS.has(hostname)) {
      return [];
    }

    const list = (protectedDomains && protectedDomains.length > 0)
      ? protectedDomains
      : DEFAULT_PROTECTED_DOMAINS;

    const parsedTargets = [];
    for (const rawTarget of list) {
      const t = rawTarget.toLowerCase().trim();
      if (!t) continue;
      if (hostname === t || registrableDomain === t || areSameSiteOrSibling(hostname, t)) {
        return []; // Exact official domain or official sibling -> Safe
      }
      parsedTargets.push(parseDomainParts(t));
    }

    const findings = [];
    const normalizedSld = normalizeConfusables(sld);
    const normalizedSldI = normalizeConfusables(sld.replace(/1/g, 'i'));
    const isSuspiciousTld = SUSPICIOUS_TLDS.has(tld);
    const hasConfusableChars = normalizedSld !== sld || normalizedSldI !== sld;

    // 1. eTLD+1 SLD similarity check (exclusively on eTLD+1)
    let bestMatch = null;
    for (const target of parsedTargets) {
      const targetSld = target.sld;
      if (!targetSld || targetSld.length < 4) continue;

      // Exact same SLD with different TLD (e.g., paypal.xyz or bca.top)
      if (sld === targetSld && registrableDomain !== target.registrableDomain) {
        if (isSuspiciousTld || targetSld.length >= 6) {
          bestMatch = {
            target: target.registrableDomain,
            distance: 0,
            reason: 'same_sld_different_tld',
            score: isSuspiciousTld ? 65 : 40,
            severity: isSuspiciousTld ? 'high' : 'medium'
          };
          break;
        }
        continue;
      }

      // Visual confusable exact match (e.g., paypa1 -> paypal, g00gle -> google, m1crosoft -> microsoft, g1thub -> github)
      if ((normalizedSld === targetSld || normalizedSldI === targetSld) && sld !== targetSld) {
        bestMatch = {
          target: target.registrableDomain,
          distance: levenshteinDistance(sld, targetSld),
          reason: 'confusable_substitution',
          score: 75,
          severity: 'high'
        };
        break;
      }

      // Levenshtein distance 1 or 2: brand SLD >= 6 chars (or >= 5 chars when paired with suspicious TLD / confusables)
      if (targetSld.length < 5 || sld.length < 5) continue;
      if (Math.abs(sld.length - targetSld.length) > 2) continue;

      const rawDist = levenshteinDistance(sld, targetSld);
      const normDist = Math.min(
        levenshteinDistance(normalizedSld, targetSld),
        levenshteinDistance(normalizedSldI, targetSld)
      );
      const effDist = Math.min(rawDist, normDist);

      const isSingleEdit = effDist === 1 && (
        targetSld.length >= 6 ||
        (targetSld.length === 5 && (hasConfusableChars || isSuspiciousTld))
      );
      const isDoubleEdit = effDist === 2 && targetSld.length >= 7 && (
        normDist <= 1 ||
        isSuspiciousTld
      );

      if (isSingleEdit || isDoubleEdit) {
        const candidate = {
          target: target.registrableDomain,
          distance: rawDist,
          reason: 'levenshtein',
          score: effDist === 1 ? 70 : 60,
          severity: 'high'
        };
        if (!bestMatch || candidate.distance < bestMatch.distance) {
          bestMatch = candidate;
        }
      }
    }

    if (bestMatch) {
      if (bestMatch.reason === 'same_sld_different_tld') {
        findings.push({
          id: 'BRAND_TLD_IMPERSONATION',
          category: 'url',
          severity: bestMatch.severity,
          score: bestMatch.score,
          title: `Brand Lookalike eTLD+1 (${bestMatch.target})`,
          detail: `eTLD+1 "${registrableDomain}" mirrors "${bestMatch.target}" on a different TLD (.${tld}) (+${bestMatch.score}).`
        });
      } else {
        findings.push({
          id: 'TYPOSQUATTING',
          category: 'url',
          severity: bestMatch.severity,
          score: bestMatch.score,
          title: `Typosquatting Match Against ${bestMatch.target}`,
          detail: `eTLD+1 "${registrableDomain}" closely spoofs "${bestMatch.target}" (Levenshtein distance: ${bestMatch.distance}, +${bestMatch.score}).`
        });
      }
    }

    // 2. Brand spoofing inside subdomain or hyphenated eTLD+1 (only on non-trusted domains)
    const fullSubdomain = subdomains.join('.');
    if (fullSubdomain || sld.includes('-')) {
      for (const target of parsedTargets) {
        if (target.sld.length < 5) continue;
        const brand = target.sld;
        const subHasBrand = fullSubdomain && (
          fullSubdomain.includes(target.registrableDomain) ||
          subdomains.some((sub) => normalizeConfusables(sub) === brand || sub.includes(brand + '-') || sub.includes('-' + brand))
        );
        const hyphenatedSldHasBrand = sld.includes('-') && (
          sld.split('-').some((part) => normalizeConfusables(part) === brand)
        );

        if (subHasBrand) {
          findings.push({
            id: 'SUBDOMAIN_BRAND_SPOOFING',
            category: 'url',
            severity: 'high',
            score: 65,
            title: `Brand Spoofing in Subdomain (${target.registrableDomain})`,
            detail: `Subdomain "${fullSubdomain}" references "${brand}", while actual eTLD+1 is "${registrableDomain}" (+65).`
          });
          break;
        }

        if (hyphenatedSldHasBrand && !bestMatch) {
          findings.push({
            id: 'HYPHENATED_BRAND_SPOOFING',
            category: 'url',
            severity: 'high',
            score: 60,
            title: `Unofficial Brand Domain (${target.registrableDomain})`,
            detail: `eTLD+1 "${registrableDomain}" embeds "${brand}" with a hyphen and is not "${target.registrableDomain}" (+60).`
          });
          break;
        }
      }
    }

    // 3. Combosquatting without hyphens (e.g., paypallogin.com, googleverify.xyz, klikbcalogin.top)
    if (!bestMatch && !findings.length && sld.length >= 8) {
      const candidates = [normalizedSld, normalizedSldI];
      let comboHit = null;
      for (const target of parsedTargets) {
        const brand = target.sld;
        if (!brand || brand.length < 5) continue;
        for (const norm of candidates) {
          if (norm.startsWith(brand) && norm.length > brand.length) {
            const suffix = norm.slice(brand.length).replace(/^-+/, '');
            if (COMBO_LURE_TOKENS.some((tok) => suffix === tok || suffix.startsWith(tok))) {
              comboHit = { target: target.registrableDomain, brand, token: suffix };
              break;
            }
          } else if (norm.endsWith(brand) && norm.length > brand.length) {
            const prefix = norm.slice(0, norm.length - brand.length).replace(/-+$/, '');
            if (COMBO_LURE_TOKENS.some((tok) => prefix === tok || prefix.endsWith(tok))) {
              comboHit = { target: target.registrableDomain, brand, token: prefix };
              break;
            }
          }
        }
        if (comboHit) break;
      }

      if (comboHit) {
        findings.push({
          id: 'COMBOSQUATTING_BRAND',
          category: 'url',
          severity: 'high',
          score: 65,
          title: `Brand Combosquatting Detected (${comboHit.target})`,
          detail: `eTLD+1 "${registrableDomain}" concatenates "${comboHit.brand}" with lure term "${comboHit.token}" and is not "${comboHit.target}" (+65).`
        });
      }
    }

    return findings;
  }

  /**
   * Main URL analysis entry point.
   */
  function analyzeUrl(rawUrl, options) {
    const opts = options || {};
    const protectedDomains = opts.protectedDomains || DEFAULT_PROTECTED_DOMAINS;
    const findings = [];

    let parsed;
    try {
      parsed = new URL(rawUrl);
    } catch (_err) {
      return {
        valid: false,
        url: rawUrl,
        hostname: '',
        registrableDomain: '',
        protocol: '',
        isTrusted: false,
        findings: []
      };
    }

    // Ignore internal browser pages (chrome://, about:, edge://, moz-extension://)
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return {
        valid: true,
        ignored: true,
        url: rawUrl,
        hostname: parsed.hostname,
        registrableDomain: parsed.hostname,
        protocol: parsed.protocol,
        isTrusted: false,
        findings: []
      };
    }

    const rawHostMatch = rawUrl.match(/^[a-zA-Z]+:\/\/(?:[^/@]*@)?([^/:?#]+)/);
    const rawHostname = rawHostMatch ? rawHostMatch[1].toLowerCase() : parsed.hostname.toLowerCase();
    const hostname = parsed.hostname.toLowerCase();
    const domainParts = parseDomainParts(hostname);
    const trusted = isTrustedDomain(hostname);
    const loopback = isLoopbackHost(hostname);

    // 1. Userinfo "@" trick (e.g., https://paypal.com@evil.com)
    if (parsed.username || parsed.password) {
      findings.push({
        id: 'URL_USERINFO_TRICK',
        category: 'url',
        severity: 'high',
        score: 65,
        title: 'Embedded "@" Credentials in URL',
        detail: `URL contains "@" userinfo before host "${hostname}" (eTLD+1: "${domainParts.registrableDomain}", +65).`
      });
    }

    // 2. Raw IP address host (non-loopback)
    if ((isIPv4(hostname) || isIPv6(hostname)) && !loopback) {
      findings.push({
        id: 'RAW_IP_HOST',
        category: 'url',
        severity: 'high',
        score: 60,
        title: 'Direct Access via Raw IP Address',
        detail: `Page is served directly from raw IP "${hostname}" instead of a domain name (+60).`
      });
    }

    // 3. IDN / Punycode Homograph detection (with RFC 3492 decoding & brand check)
    const idnFinding = detectIdnHomograph(rawHostname, protectedDomains) || detectIdnHomograph(hostname, protectedDomains);
    if (idnFinding) {
      findings.push(idnFinding);
    }

    // 4. Typosquatting & Brand Spoofing (exclusively on eTLD+1; trusted seed = 0 risk)
    const typoFindings = detectTyposquatting(domainParts, protectedDomains);
    for (const f of typoFindings) {
      findings.push(f);
    }

    // 5. Excessive subdomains (>= 4 levels on non-trusted, non-loopback domain)
    if (domainParts.subdomains.length >= 4 && !loopback && !trusted) {
      findings.push({
        id: 'EXCESSIVE_SUBDOMAINS',
        category: 'url',
        severity: 'medium',
        score: 25,
        title: 'Excessive Subdomain Depth',
        detail: `Host "${hostname}" has ${domainParts.subdomains.length} subdomain levels above eTLD+1 "${domainParts.registrableDomain}" (+25).`
      });
    }

    // 6. Non-standard port on unknown external host
    if (parsed.port && parsed.port !== '80' && parsed.port !== '443' && !loopback && !trusted) {
      findings.push({
        id: 'NON_STANDARD_PORT',
        category: 'url',
        severity: 'medium',
        score: 15,
        title: 'Non-Standard Port on Unknown Domain',
        detail: `Untrusted eTLD+1 "${domainParts.registrableDomain}" is accessed on non-standard port :${parsed.port} (+15).`
      });
    }

    // 7. Suspicious credential-lure path + suspicious TLD or long obfuscated URL on untrusted host
    if (!trusted && !loopback) {
      const pathAndQuery = (parsed.pathname + parsed.search).toLowerCase();
      const hasLureKeyword = /(verify[-_]?account|confirm[-_]?identity|update[-_]?billing|secure[-_]?login|webscr|signin[-_]?recover|wallet[-_]?connect)/i.test(pathAndQuery);
      const isSuspiciousTld = SUSPICIOUS_TLDS.has(domainParts.tld);
      if (hasLureKeyword && (isSuspiciousTld || parsed.href.length > 140)) {
        findings.push({
          id: 'SUSPICIOUS_LURE_URL',
          category: 'url',
          severity: 'medium',
          score: 25,
          title: 'Suspicious Credential-Lure URL Pattern',
          detail: `Untrusted eTLD+1 "${domainParts.registrableDomain}" combines credential-lure path keywords with ${isSuspiciousTld ? `high-risk TLD .${domainParts.tld}` : 'an unusually long URL'} (+25).`
        });
      }

      // 8. High-Entropy / DGA (Domain Generation Algorithm) check on untrusted domains
      const sldClean = domainParts.sld.replace(/-/g, '');
      const digitCount = (sldClean.match(/\d/g) || []).length;
      const vowelCount = (sldClean.match(/[aeiou]/g) || []).length;
      const entropy = shannonEntropy(sldClean);
      const isHighRiskHost = SUSPICIOUS_TLDS.has(domainParts.tld) || FREE_HOSTING_SUFFIXES.has(domainParts.tld);
      if (
        sldClean.length >= 14 &&
        entropy >= 3.7 &&
        (digitCount >= 4 || (vowelCount / sldClean.length) < 0.15) &&
        (isHighRiskHost || digitCount >= 5)
      ) {
        findings.push({
          id: 'HIGH_ENTROPY_DGA_DOMAIN',
          category: 'url',
          severity: 'medium',
          score: 25,
          title: 'High-Entropy / Randomly Generated Domain (DGA)',
          detail: `Untrusted eTLD+1 "${domainParts.registrableDomain}" has high Shannon entropy (${entropy.toFixed(2)} bits/char), typical of disposable phishing infrastructure (+25).`
        });
      }

      // 9. Suspicious open-redirect query parameter pointing to a raw IP or high-risk TLD
      const redirectParamKeys = ['redirect', 'redirect_uri', 'next', 'url', 'goto', 'return', 'dest', 'continue'];
      for (const key of redirectParamKeys) {
        const paramVal = parsed.searchParams.get(key);
        if (!paramVal || !/^https?:\/\//i.test(paramVal)) continue;
        try {
          const targetUrl = new URL(paramVal);
          const targetHost = targetUrl.hostname.toLowerCase();
          if (areSameSiteOrSibling(hostname, targetHost) || isTrustedDomain(targetHost) || isKnownOAuthProvider(targetUrl.href)) {
            continue;
          }
          const targetParts = parseDomainParts(targetHost);
          const targetRawIp = (isIPv4(targetHost) || isIPv6(targetHost)) && !isLoopbackHost(targetHost);
          if (targetRawIp || SUSPICIOUS_TLDS.has(targetParts.tld)) {
            findings.push({
              id: 'SUSPICIOUS_REDIRECT_PARAM',
              category: 'redirect',
              severity: 'medium',
              score: 30,
              title: 'Suspicious External Redirect Parameter in URL',
              detail: `Query parameter "${key}" redirects toward untrusted ${targetRawIp ? `raw IP "${targetHost}"` : `high-risk domain "${targetParts.registrableDomain}"`} (+30).`
            });
            break;
          }
        } catch (_err) {
          // ignore malformed redirect param
        }
      }
    }

    return {
      valid: true,
      ignored: false,
      url: parsed.href,
      hostname,
      registrableDomain: domainParts.registrableDomain,
      tld: domainParts.tld,
      isFreeHosting: FREE_HOSTING_SUFFIXES.has(domainParts.tld),
      protocol: parsed.protocol,
      isLoopback: loopback,
      isTrusted: trusted,
      findings
    };
  }

  const exportsObj = {
    levenshteinDistance,
    normalizeConfusables,
    decodePunycodeLabel,
    decodePunycodeHostname,
    shannonEntropy,
    parseDomainParts,
    isTrustedDomain,
    areSameSiteOrSibling,
    isKnownOAuthProvider,
    isIPv4,
    isIPv6,
    isLoopbackHost,
    detectIdnHomograph,
    detectTyposquatting,
    analyzeUrl
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportsObj;
  }
  root.PhishGuardUrlAnalyzer = exportsObj;
})(typeof globalThis !== 'undefined' ? globalThis : this);
