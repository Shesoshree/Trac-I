// Scam Detective Content Script: Real-time link scanner for web pages & Gmail
(function() {
  const HOMOGLYPHS = {
    '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u0456': 'i',
    '\u043e': 'o', '\u0440': 'p', '\u0455': 's', '\u0445': 'x', '\u0443': 'y'
  };

  const SUSPICIOUS_TLDS = ['.xyz', '.top', '.click', '.cam', '.buzz', '.country', '.work'];

  function inspectLink(aTag) {
    if (aTag.dataset.scamChecked) return;
    aTag.dataset.scamChecked = "true";

    const href = aTag.href || "";
    if (!href.startsWith("http://") && !href.startsWith("https://")) return;

    let parsed;
    try {
      parsed = new URL(href);
    } catch(e) {
      return;
    }

    const host = parsed.hostname;
    const text = aTag.textContent.trim();

    let threatReason = null;

    // 1. Homoglyph check
    if (host.startsWith("xn--") || host.includes(".xn--")) {
      threatReason = "Punycode (IDN) disguised domain";
    } else {
      for (let ch of host) {
        if (HOMOGLYPHS[ch]) {
          threatReason = `Cyrillic homoglyph '${ch}' disguised as Latin '${HOMOGLYPHS[ch]}'`;
          break;
        }
      }
    }

    // 2. Visual anchor text mismatch
    if (!threatReason && (text.startsWith("http://") || text.startsWith("https://") || text.includes(".com") || text.includes(".gov") || text.includes(".mil"))) {
      try {
        const textUrl = new URL(text.includes("://") ? text : `https://${text}`);
        if (textUrl.hostname && textUrl.hostname !== host) {
          threatReason = `Anchor text deceives: displays '${textUrl.hostname}' but routes to '${host}'`;
        }
      } catch(e) {}
    }

    // 3. Raw IP Host
    if (!threatReason && /^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
      threatReason = "Raw IP address link bypassing DNS";
    }

    // 4. Suspicious TLD
    if (!threatReason && SUSPICIOUS_TLDS.some(tld => host.endsWith(tld))) {
      threatReason = `Zero-reputation high-risk TLD (${host})`;
    }

    if (threatReason) {
      injectWarningBadge(aTag, threatReason);
    }
  }

  function injectWarningBadge(aTag, reason) {
    const badge = document.createElement("span");
    badge.className = "scam-detective-badge";
    badge.innerHTML = `&#9888; <strong>Phish Alert</strong>`;
    badge.title = `Scam Detective Warning:\n${reason}`;
    badge.style.cssText = `
      display: inline-flex;
      align-items: center;
      gap: 4px;
      margin-left: 6px;
      padding: 2px 6px;
      background-color: #ef4444;
      color: #ffffff;
      font-size: 11px;
      font-weight: bold;
      border-radius: 4px;
      cursor: help;
      vertical-align: middle;
      font-family: Arial, sans-serif;
      text-decoration: none;
      box-shadow: 0 1px 3px rgba(0,0,0,0.3);
    `;

    aTag.style.outline = "2px dashed #ef4444";
    aTag.style.outlineOffset = "2px";
    aTag.parentNode.insertBefore(badge, aTag.nextSibling);
  }

  function scanPageLinks() {
    const links = document.querySelectorAll("a[href]");
    links.forEach(inspectLink);
  }

  // Initial scan
  scanPageLinks();

  // Re-scan when dynamic content (like opening an email in Gmail) loads
  const observer = new MutationObserver(() => {
    scanPageLinks();
  });
  observer.observe(document.body, { childList: true, subtree: true });
})();
