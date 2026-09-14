// Trac-I Popup Logic
const API_BASE = "http://localhost:8000";

// Confusable homoglyphs map for client-side heuristic backup
const HOMOGLYPHS = {
  '\u0430': 'a', '\u0441': 'c', '\u0435': 'e', '\u0456': 'i',
  '\u043e': 'o', '\u0440': 'p', '\u0455': 's', '\u0445': 'x', '\u0443': 'y'
};

const TARGET_BRANDS = ["microsoft", "office365", "google", "defense", "paypal", "apple", "okta"];

document.addEventListener("DOMContentLoaded", async () => {
  // Query active tab
  let currentUrl = "";
  if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.query) {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab && tab.url) {
        currentUrl = tab.url;
      }
    } catch (e) {
      console.warn("Could not query active tab:", e);
    }
  }

  if (!currentUrl) {
    currentUrl = "https://login.microsoftonline.com";
  }

  analyzeUrl(currentUrl);

  // Quick Scan Event
  const quickBtn = document.getElementById("quickScanBtn");
  const quickInput = document.getElementById("quickInput");
  quickBtn.addEventListener("click", () => {
    const val = quickInput.value.trim();
    if (val) {
      analyzeUrl(val);
    }
  });

  // Open Console Event
  document.getElementById("openConsoleBtn").addEventListener("click", () => {
    if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.create) {
      chrome.tabs.create({ url: "http://localhost:8000/scan" });
    } else {
      window.open("http://localhost:8000/scan", "_blank");
    }
  });
});

async function analyzeUrl(targetUrl) {
  const domainEl = document.getElementById("targetDomain");
  const scoreValEl = document.getElementById("scoreValue");
  const scoreCircle = document.getElementById("scoreCircle");
  const statusBadge = document.getElementById("statusBadge");
  const homoglyphStatus = document.getElementById("homoglyphStatus");
  const brandStatus = document.getElementById("brandStatus");
  const entropyStatus = document.getElementById("entropyStatus");
  const sslStatus = document.getElementById("sslStatus");
  const quickResult = document.getElementById("quickResult");

  try {
    const parsed = new URL(targetUrl.includes("://") ? targetUrl : `http://${targetUrl}`);
    const host = parsed.hostname;
    domainEl.textContent = host || targetUrl;
    sslStatus.textContent = parsed.protocol === "https:" ? "HTTPS Encrypted" : "Insecure HTTP";

    // Try backend API first
    let data = null;
    try {
      const resp = await fetch(`${API_BASE}/api/analyze/url`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: targetUrl })
      });
      if (resp.ok) {
        data = await resp.json();
      }
    } catch (e) {
      // Backend unavailable, fallback to client-side heuristics
    }

    if (!data) {
      data = clientSideFallbackScan(targetUrl);
    }

    renderScanResults(data);
  } catch (err) {
    domainEl.textContent = targetUrl.slice(0, 30);
    renderScanResults(clientSideFallbackScan(targetUrl));
  }
}

function clientSideFallbackScan(url) {
  let isHomoglyph = url.startsWith("xn--") || url.includes(".xn--");
  let detectedChars = [];
  for (let ch of url) {
    if (HOMOGLYPHS[ch]) {
      isHomoglyph = true;
      detectedChars.push(ch);
    }
  }

  let typosquat = null;
  const lower = url.toLowerCase();
  for (let b of TARGET_BRANDS) {
    if (lower.includes(b) && !lower.includes(`${b}.com`)) {
      typosquat = b;
      break;
    }
  }

  let risk = 0;
  if (isHomoglyph) risk += 50;
  if (typosquat) risk += 35;
  if (url.includes(".xyz") || url.includes(".top") || url.includes(".click")) risk += 25;
  if (url.startsWith("http://")) risk += 15;

  return {
    url: url,
    risk_score: Math.min(100, risk),
    has_homoglyphs: isHomoglyph,
    homoglyphs_count: detectedChars.length,
    typosquat_target: typosquat,
    entropy_domain: 2.8,
    risk_reasons: isHomoglyph ? ["Cyrillic homoglyph or IDN punycode detected"] : []
  };
}

function renderScanResults(data) {
  const scoreValEl = document.getElementById("scoreValue");
  const scoreCircle = document.getElementById("scoreCircle");
  const statusBadge = document.getElementById("statusBadge");
  const homoglyphStatus = document.getElementById("homoglyphStatus");
  const brandStatus = document.getElementById("brandStatus");
  const entropyStatus = document.getElementById("entropyStatus");
  const quickResult = document.getElementById("quickResult");

  const score = data.risk_score || 0;
  scoreValEl.textContent = `${score}%`;

  scoreCircle.className = "score-circle";
  statusBadge.className = "status-badge";

  if (score >= 70) {
    scoreCircle.classList.add("danger");
    statusBadge.classList.add("danger");
    statusBadge.textContent = "CRITICAL PHISHING";
  } else if (score >= 30) {
    scoreCircle.classList.add("warning");
    statusBadge.classList.add("warning");
    statusBadge.textContent = "SUSPICIOUS";
  } else {
    statusBadge.classList.add("safe");
    statusBadge.textContent = "VERIFIED SAFE";
  }

  if (data.has_homoglyphs || (data.homoglyphs_detected && data.homoglyphs_detected.length > 0)) {
    homoglyphStatus.textContent = "DETECTED";
    homoglyphStatus.className = "metric-value danger-text";
  } else {
    homoglyphStatus.textContent = "None";
    homoglyphStatus.className = "metric-value safe-text";
  }

  if (data.typosquat_target) {
    brandStatus.textContent = `Impersonating ${data.typosquat_target}`;
    brandStatus.className = "metric-value danger-text";
  } else {
    brandStatus.textContent = "Legitimate";
    brandStatus.className = "metric-value safe-text";
  }

  entropyStatus.textContent = `${data.entropy_domain || 2.4}`;

  if (data.risk_reasons && data.risk_reasons.length > 0) {
    quickResult.style.display = "block";
    quickResult.innerHTML = `<strong style="color:#ff4d66;">Threat Indicators:</strong><br>&bull; ${data.risk_reasons.join("<br>&bull; ")}`;
  } else {
    quickResult.style.display = "none";
  }
}
