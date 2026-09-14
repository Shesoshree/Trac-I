// Trac-I Phishing Triage Console Logic
let currentScenarioId = "apt_hr_policy_update";
let currentAnalysisData = null;

// Escape attacker-controlled text before injecting into innerHTML (DOM XSS guard).
function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Announce dynamic status changes to screen readers via the hidden live region.
function announce(message) {
  const region = document.getElementById("analysisStatus");
  if (region) {
    region.textContent = "";
    setTimeout(() => { region.textContent = message; }, 50);
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  initTabs();
  initModals();
  await loadScenarios();
  setupEventListeners();
  loadScanHistory();
});

// Tab Navigation
function initTabs() {
  const tabBtns = document.querySelectorAll(".tab-btn");
  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => {
        b.classList.remove("active");
        b.setAttribute("aria-selected", "false");
        b.setAttribute("tabindex", "-1");
      });
      btn.classList.add("active");
      btn.setAttribute("aria-selected", "true");
      btn.setAttribute("tabindex", "0");

      const targetId = btn.getAttribute("data-tab");
      document.querySelectorAll(".tab-content").forEach(tc => {
        tc.style.display = "none";
        tc.setAttribute("aria-hidden", "true");
      });
      const targetContent = document.getElementById(targetId);
      if (targetContent) {
        targetContent.style.display = "block";
        targetContent.setAttribute("aria-hidden", "false");
      }
    });

    // Keyboard arrow navigation between tabs (roving tabindex)
    btn.addEventListener("keydown", (e) => {
      if (e.key !== "ArrowRight" && e.key !== "ArrowLeft" && e.key !== "Home" && e.key !== "End") return;
      e.preventDefault();
      const list = Array.from(tabBtns);
      const idx = list.indexOf(btn);
      let nextIdx = idx;
      if (e.key === "ArrowRight") nextIdx = (idx + 1) % list.length;
      else if (e.key === "ArrowLeft") nextIdx = (idx - 1 + list.length) % list.length;
      else if (e.key === "Home") nextIdx = 0;
      else if (e.key === "End") nextIdx = list.length - 1;
      list[nextIdx].click();
      list[nextIdx].focus();
    });
  });
}

// Scenarios Loader
async function loadScenarios() {
  const container = document.getElementById("scenarioPills");
  if (!container) return;

  try {
    const resp = await fetch("/api/scenarios");
    const scenarios = await resp.json();

    container.innerHTML = "";

    const customEml = sessionStorage.getItem("custom_triage_eml");
    const customTitle = sessionStorage.getItem("custom_triage_title") || "Personalized Defense Scenario";
    const urlParams = new URLSearchParams(window.location.search);
    const isCustomMode = urlParams.get("mode") === "custom" && customEml;

    if (customEml) {
      const customPill = document.createElement("button");
      customPill.className = `scenario-pill ${isCustomMode ? 'active' : ''}`;
      customPill.style.border = '1px solid #ff1a35';
      customPill.style.color = '#ff1a35';
      customPill.setAttribute("role", "radio");
      customPill.setAttribute("aria-checked", isCustomMode ? "true" : "false");
      customPill.innerHTML = `&#9888; ${escapeHtml(customTitle)}`;
      customPill.addEventListener("click", () => {
        selectCustomScenario(customEml, customTitle, customPill);
      });
      container.appendChild(customPill);
    }

    scenarios.forEach((s, idx) => {
      const pill = document.createElement("button");
      pill.className = `scenario-pill ${(!isCustomMode && idx === 0) ? 'active' : ''}`;
      pill.setAttribute("role", "radio");
      pill.setAttribute("aria-checked", (!isCustomMode && idx === 0) ? "true" : "false");
      pill.textContent = s.title;
      pill.addEventListener("click", () => selectScenario(s.id, pill));
      container.appendChild(pill);
    });

    if (isCustomMode) {
      const customPillEl = container.querySelector(".scenario-pill");
      if (customPillEl) selectCustomScenario(customEml, customTitle, customPillEl);
    } else if (scenarios.length > 0) {
      selectScenario(scenarios[0].id, container.querySelector(".scenario-pill"));
    }
  } catch (err) {
    console.error("Error loading scenarios:", err);
  }
}

function selectCustomScenario(rawEml, title, pillElement) {
  currentScenarioId = "custom_dynamic";

  if (pillElement) {
    document.querySelectorAll(".scenario-pill").forEach(p => {
      p.classList.remove("active");
      p.setAttribute("aria-checked", "false");
    });
    pillElement.classList.add("active");
    pillElement.setAttribute("aria-checked", "true");
  }

  const rawInput = document.getElementById("rawEmlInput");
  const metaSummary = document.getElementById("scenarioMetaSummary");

  if (rawInput) rawInput.value = rawEml;
  if (metaSummary) {
    metaSummary.innerHTML = `
      <strong>${title}</strong><br>
      <span style="color:#ff1a35;">Origin:</span> Personalized Defense Threat Studio<br>
      <span style="color:#a3a3a3;">Summary:</span> Dynamic adversary lure generated to test organization defenses.
    `;
  }

  runEmailAnalysis(rawEml);
}

async function selectScenario(scenarioId, pillElement) {
  currentScenarioId = scenarioId;

  // Update pills UI
  if (pillElement) {
    document.querySelectorAll(".scenario-pill").forEach(p => {
      p.classList.remove("active");
      p.setAttribute("aria-checked", "false");
    });
    pillElement.classList.add("active");
    pillElement.setAttribute("aria-checked", "true");
  }

  try {
    const resp = await fetch(`/api/scenarios/${scenarioId}`);
    const data = await resp.json();

    const rawInput = document.getElementById("rawEmlInput");
    const metaSummary = document.getElementById("scenarioMetaSummary");

    if (rawInput) rawInput.value = data.raw_eml;
    if (metaSummary) {
      metaSummary.innerHTML = `
        <strong>${data.title}</strong><br>
        <span style="color:#ff1a35;">Target:</span> ${data.target}<br>
        <span style="color:#a3a3a3;">Summary:</span> ${data.summary}
      `;
    }

    // Auto trigger analysis
    runEmailAnalysis(data.raw_eml);
  } catch (err) {
    console.error("Error fetching scenario:", err);
  }
}

function setupEventListeners() {
  // Run Email Analysis button
  const analyzeEmailBtn = document.getElementById("analyzeEmailBtn");
  if (analyzeEmailBtn) {
    analyzeEmailBtn.addEventListener("click", () => {
      const raw = document.getElementById("rawEmlInput").value.trim();
      if (!raw) {
        alert("Please paste raw email headers & body or pick a scenario above.");
        return;
      }
      runEmailAnalysis(raw);
    });
  }

  // URL Deep Dive button
  const analyzeUrlBtn = document.getElementById("analyzeUrlBtn");
  if (analyzeUrlBtn) {
    analyzeUrlBtn.addEventListener("click", async () => {
      const url = document.getElementById("singleUrlInput").value.trim();
      if (!url) return;
      analyzeUrlBtn.disabled = true;
      analyzeUrlBtn.setAttribute("aria-busy", "true");
      analyzeUrlBtn.textContent = "Analyzing...";
      announce("Inspecting URL heuristics");

      try {
        const resp = await fetch("/api/analyze/url", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url })
        });
        const data = await resp.json();
        renderUrlDeepDiveResults(data);
        loadScanHistory();
        announce(`URL analysis complete. Risk score ${data.risk_score} percent`);
      } catch (e) {
        alert("URL inspection failed.");
      } finally {
        analyzeUrlBtn.disabled = false;
        analyzeUrlBtn.removeAttribute("aria-busy");
        analyzeUrlBtn.textContent = "Inspect Link Heuristics";
      }
    });
  }

  // Text/BEC button
  const analyzeTextBtn = document.getElementById("analyzeTextBtn");
  if (analyzeTextBtn) {
    analyzeTextBtn.addEventListener("click", async () => {
      const text = document.getElementById("rawTextInput").value.trim();
      if (!text) return;
      analyzeTextBtn.disabled = true;
      analyzeTextBtn.setAttribute("aria-busy", "true");
      analyzeTextBtn.textContent = "Analyzing...";
      announce("Analyzing urgency and BEC triggers");

      try {
        const resp = await fetch("/api/analyze/text", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text })
        });
        const data = await resp.json();
        renderTextAnalysisResults(data, text);
        loadScanHistory();
      } catch (e) {
        alert("Text analysis failed.");
      } finally {
        analyzeTextBtn.disabled = false;
        analyzeTextBtn.removeAttribute("aria-busy");
        analyzeTextBtn.textContent = "Analyze Urgency & BEC Triggers";
      }
    });
  }

  // File Upload
  const fileInput = document.getElementById("emlFileInput");
  if (fileInput) {
    fileInput.addEventListener("change", (e) => {
      const file = e.target.files[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = (event) => {
        const content = event.target.result;
        document.getElementById("rawEmlInput").value = content;
        runEmailAnalysis(content);
      };
      reader.readAsText(file);
    });
  }

  // Export SOC Ticket Top Button
  const exportBtn = document.getElementById("exportTicketTopBtn");
  if (exportBtn) {
    exportBtn.addEventListener("click", () => {
      openIncidentTicketModal(currentScenarioId);
    });
  }

  // History Refresh & Clear Buttons
  const refreshBtn = document.getElementById("refreshHistoryBtn");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => loadScanHistory());
  }

  const clearBtn = document.getElementById("clearHistoryBtn");
  if (clearBtn) {
    clearBtn.addEventListener("click", async () => {
      if (!confirm("Are you sure you want to clear persistent SOC triage audit history?")) return;
      try {
        await fetch("/api/history", { method: "DELETE" });
        loadScanHistory();
      } catch (e) {
        alert("Failed to clear history.");
      }
    });
  }
}

// Master Email Analysis Execution
async function runEmailAnalysis(rawEml) {
  const btn = document.getElementById("analyzeEmailBtn");
  if (btn) {
    btn.disabled = true;
    btn.setAttribute("aria-busy", "true");
    btn.textContent = "Executing AI Pipeline...";
  }
  announce("AI detection in progress");

  try {
    const resp = await fetch("/api/analyze/email", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw_eml: rawEml })
    });

    if (!resp.ok) throw new Error("Analysis failed");
    const data = await resp.json();
    currentAnalysisData = data;

    renderFullTriageReport(data);
    loadScanHistory();
    announce(`Analysis complete. Threat probability ${Math.round((data.prediction?.probability ?? 0) * 100)} percent`);
  } catch (err) {
    alert("Error executing detection engine. Ensure FastAPI server is running.");
    console.error(err);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.removeAttribute("aria-busy");
      btn.textContent = "Run AI Detection";
    }
  }
}

// Render Master Triage Report
function renderFullTriageReport(data) {
  const pred = data.prediction;
  const features = data.features;
  const headers = features.headers;
  const urls = features.urls;
  const nlp = features.nlp;
  const dom = features.dom;

  // 1. Dial and Threat Probability
  const dialScore = document.getElementById("dialScore");
  const dialCircle = document.getElementById("dialCircle");
  const severityBadge = document.getElementById("severityBadge");
  const categoryTitle = document.getElementById("categoryTitle");
  const socActionText = document.getElementById("socActionText");
  const modelConfidence = document.getElementById("modelConfidence");
  const confidenceBadge = document.getElementById("confidencePercentage");

  const score = pred.threat_score;
  const isHighRisk = score >= 25;
  const isDark = document.documentElement.getAttribute("data-theme") !== "light";
  const themeAccentColor = isHighRisk ? "#ff1a35" : (isDark ? "#ffffff" : "#0f172a");
  const themeBgColor = isHighRisk ? "rgba(255, 26, 53, 0.2)" : (isDark ? "rgba(255, 255, 255, 0.1)" : "rgba(15, 23, 42, 0.08)");

  dialScore.textContent = `${score}%`;
  const dialCircle = document.getElementById("dialCircle");
  if (dialCircle) dialCircle.setAttribute("aria-valuenow", String(Math.round(score)));
  dialCircle.style.borderColor = themeAccentColor;
  dialCircle.style.color = themeAccentColor;
  dialCircle.style.boxShadow = isHighRisk ? "0 0 25px rgba(255, 26, 53, 0.4)" : (isDark ? "0 0 20px rgba(255, 255, 255, 0.2)" : "0 2px 10px rgba(0,0,0,0.08)");

  severityBadge.textContent = pred.severity;
  severityBadge.style.background = themeBgColor;
  severityBadge.style.color = themeAccentColor;
  severityBadge.style.border = `1px solid ${isHighRisk ? '#ff1a3566' : 'var(--border-color)'}`;

  categoryTitle.textContent = pred.category;
  categoryTitle.style.color = "var(--text-main)";
  socActionText.innerHTML = `<strong style="color:var(--text-main);">SOC Action:</strong> ${pred.soc_action}`;
  modelConfidence.textContent = `RF: ${pred.rf_confidence}% | GBM: ${pred.gb_confidence}%`;

  if (confidenceBadge) {
    const confVal = pred.confidence_percentage !== undefined ? pred.confidence_percentage : Math.round((pred.rf_confidence + pred.gb_confidence) / 2);
    confidenceBadge.textContent = `CONFIDENCE: ${confVal}%`;
    confidenceBadge.style.background = themeBgColor;
    confidenceBadge.style.color = themeAccentColor;
    confidenceBadge.style.border = `1px solid ${isHighRisk ? '#ff1a3566' : 'var(--border-color)'}`;
  }

  // 2. Header Authentication Matrix
  renderHeaderMatrix(headers);

  // 3. URLs Intelligence Matrix
  renderUrlsList(urls);

  // 4. NLP Urgency & DOM Heatmap
  renderNlpHeatmap(nlp, dom, features.plain_text_snippet);

  // 5. Explainable AI (XAI) Attribution
  renderXaiAttribution(pred.feature_contributions);
}

function renderHeaderMatrix(headers) {
  const spfEl = document.getElementById("spfStatusBadge");
  const dkimEl = document.getElementById("dkimStatusBadge");
  const dmarcEl = document.getElementById("dmarcStatusBadge");
  const riskBadge = document.getElementById("headerRiskBadge");
  const mismatchesList = document.getElementById("headerMismatchesList");

  const spfStatus = headers.spf.status.toUpperCase();
  const dkimStatus = headers.dkim.status.toUpperCase();
  const dmarcStatus = headers.dmarc.status.toUpperCase();

  spfEl.textContent = spfStatus;
  spfEl.style.color = spfStatus === "PASS" ? "var(--text-main)" : "#ff1a35";

  dkimEl.textContent = dkimStatus;
  dkimEl.style.color = dkimStatus === "PASS" ? "var(--text-main)" : "#ff1a35";

  dmarcEl.textContent = dmarcStatus;
  dmarcEl.style.color = dmarcStatus === "PASS" ? "var(--text-main)" : "#ff1a35";

  riskBadge.textContent = `Risk Score: ${headers.header_risk_score}/100`;
  riskBadge.style.color = headers.header_risk_score >= 30 ? "#ff1a35" : "var(--text-main)";

  mismatchesList.innerHTML = "";
  if (headers.header_flags && headers.header_flags.length > 0) {
    headers.header_flags.forEach(flag => {
      const item = document.createElement("div");
      item.className = "red-flag-item";
      item.innerHTML = `&#9888; ${escapeHtml(flag)}`;
      mismatchesList.appendChild(item);
    });
  } else {
    const safeItem = document.createElement("div");
    safeItem.className = "safe-flag-item";
    safeItem.innerHTML = `&#10004; Verified SPF/DKIM/DMARC records with aligned sender domains.`;
    mismatchesList.appendChild(safeItem);
  }
}

function renderUrlsList(urlData) {
  const countBadge = document.getElementById("urlCountBadge");
  const container = document.getElementById("urlIntelligenceList");
  countBadge.textContent = `${urlData.total_urls_found} URL(s) Detected`;
  countBadge.style.color = urlData.total_urls_found > 0 ? "#ff1a35" : "var(--text-main)";

  container.innerHTML = "";
  if (!urlData.urls || urlData.urls.length === 0) {
    container.innerHTML = "<p style='font-size:13px; color:var(--text-muted);'>No embedded URLs found in email body.</p>";
    return;
  }

  urlData.urls.forEach(u => {
    const isThreat = u.risk_score >= 40;
    const card = document.createElement("div");
    card.style.cssText = `
      background: var(--bg-input);
      border: 1px solid ${isThreat ? '#ff1a35' : 'var(--border-color)'};
      border-radius: 6px;
      padding: 12px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    `;

    // Homoglyph display (escape char/resembles from hostname analysis)
    let homoglyphDetail = "None";
    if (u.homoglyphs_detected && u.homoglyphs_detected.length > 0) {
      homoglyphDetail = u.homoglyphs_detected.map(h =>
        `<span style="background:rgba(255,26,53,0.2); color:#ff4d66; border:1px solid rgba(255,26,53,0.4); padding:2px 4px; border-radius:3px; font-weight:bold;">
          ${escapeHtml(h.char)} (${escapeHtml(h.unicode)} resembling '${escapeHtml(h.resembles)}')
        </span>`
      ).join(" ");
    }

    const isDark = document.documentElement.getAttribute("data-theme") !== "light";
    const normalText = isDark ? "#ffffff" : "#0f172a";
    card.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
        <div style="font-family:monospace; font-size:13px; font-weight:bold; color:${isThreat ? '#ff1a35' : normalText};">
          ${escapeHtml(u.url)}
        </div>
        <div style="display:flex; gap:6px; align-items:center;">
          <span style="font-size:11px; font-weight:bold; background:${isThreat ? 'rgba(255,26,53,0.2)' : 'var(--safe-bg)'}; color:${isThreat ? '#ff1a35' : normalText}; border:1px solid ${isThreat ? '#ff1a3566' : 'var(--border-color)'}; padding:3px 8px; border-radius:4px;">
            ${escapeHtml(u.risk_score)}% Risk
          </span>
          <button class="btn btn-outline btn-sm sandbox-btn" data-url="${escapeHtml(encodeURIComponent(u.url))}">
            Safe Sandbox
          </button>
        </div>
      </div>

      <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(170px, 1fr)); gap:8px; font-size:11.5px;">
        <div><span style="color:var(--text-muted);">Punycode:</span> <strong style="color:var(--text-main);">${escapeHtml(u.is_punycode ? u.decoded_punycode : 'Standard ASCII')}</strong></div>
        <div><span style="color:var(--text-muted);">Homoglyphs:</span> <strong>${homoglyphDetail}</strong></div>
        <div><span style="color:var(--text-muted);">Brand Target:</span> <strong style="color:${u.typosquat_target ? '#ff1a35' : 'var(--text-main)'};">${escapeHtml(u.typosquat_target || 'None')}</strong></div>
        <div><span style="color:var(--text-muted);">Shannon Entropy:</span> <strong style="color:var(--text-main);">${escapeHtml(u.entropy_domain)}</strong></div>
      </div>

      ${u.risk_reasons && u.risk_reasons.length > 0 ? `
        <div style="font-size:11px; color:#ff4d66; border-top:1px dashed var(--border-color); padding-top:6px;">
          <strong>Threat Flags:</strong> ${escapeHtml(u.risk_reasons.join(" \u2022 "))}
        </div>
      ` : ''}
    `;

    container.appendChild(card);
  });

  // Attach sandbox click listeners
  container.querySelectorAll(".sandbox-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const url = decodeURIComponent(btn.getAttribute("data-url"));
      openSandboxModal(url);
    });
  });
}

function renderNlpHeatmap(nlp, dom, textSnippet) {
  const summaryBar = document.getElementById("nlpSummaryBar");
  const bodySnippet = document.getElementById("nlpBodySnippet");

  const counts = nlp.counts || {};
  summaryBar.innerHTML = `
    <div style="background:var(--bg-input); border:1px solid var(--border-color); padding:6px 12px; border-radius:4px; font-size:12px;">
      <span style="color:var(--text-muted);">Urgency Triggers:</span>
      <strong style="color:${counts.urgency > 0 ? '#ff1a35' : 'var(--text-main)'};">${counts.urgency || 0}</strong>
    </div>
    <div style="background:var(--bg-input); border:1px solid var(--border-color); padding:6px 12px; border-radius:4px; font-size:12px;">
      <span style="color:var(--text-muted);">Fear / Disciplinary:</span>
      <strong style="color:${counts.fear > 0 ? '#ff1a35' : 'var(--text-main)'};">${counts.fear || 0}</strong>
    </div>
    <div style="background:var(--bg-input); border:1px solid var(--border-color); padding:6px 12px; border-radius:4px; font-size:12px;">
      <span style="color:var(--text-muted);">Credential Solicitation:</span>
      <strong style="color:${counts.credential > 0 ? '#ff1a35' : 'var(--text-main)'};">${counts.credential > 0 ? 'YES' : 'NONE'}</strong>
    </div>
    <div style="background:var(--bg-input); border:1px solid var(--border-color); padding:6px 12px; border-radius:4px; font-size:12px;">
      <span style="color:var(--text-muted);">Anti-Spam Hidden Text:</span>
      <strong style="color:${dom.hidden_elements_count > 0 ? '#ff1a35' : 'var(--text-main)'};">${dom.hidden_elements_count || 0}</strong>
    </div>
  `;

  // Highlight keywords in text (escape first to neutralize any attacker HTML)
  let rawText = textSnippet || "No text content.";
  let highlighted = escapeHtml(rawText);

  if (nlp.matched_triggers) {
    // Collect all (start, end, class) spans from the classifier over the RAW text,
    // then re-wrap the ESCAPED text at those offsets with the clickable/highlight span.
    const spans = [];
    for (const [cat, matches] of Object.entries(nlp.matched_triggers)) {
      const cls = cat === "urgency" ? "highlight-urgency" : (cat === "fear_consequence" ? "highlight-fear" : "highlight-credential");
      (matches || []).forEach(m => {
        if (typeof m.start === "number" && typeof m.end === "number" && m.end > m.start) {
          spans.push({ s: m.start, e: m.end, cls });
        }
      });
    }

    if (spans.length > 0) {
      spans.sort((a, b) => a.s - b.s || (b.e - b.s) - (a.e - a.s));
      const merged = [];
      for (const sp of spans) {
        const last = merged[merged.length - 1];
        if (last && sp.s < last.e) continue; // skip overlapping/nested
        merged.push(sp);
      }

      let out = "";
      let cursor = 0;
      for (const sp of merged) {
        const safeStart = Math.max(0, Math.min(sp.s, rawText.length));
        const safeEnd = Math.max(safeStart, Math.min(sp.e, rawText.length));
        out += escapeHtml(rawText.slice(cursor, safeStart));
        out += `<span class="${sp.cls}">${escapeHtml(rawText.slice(safeStart, safeEnd))}</span>`;
        cursor = safeEnd;
      }
      out += escapeHtml(rawText.slice(cursor));
      highlighted = out;
    }
  }

  bodySnippet.innerHTML = highlighted;
}

function renderXaiAttribution(contributions) {
  const container = document.getElementById("xaiAttributionList");
  container.innerHTML = "";

  if (!contributions || contributions.length === 0) {
    container.innerHTML = "<p style='font-size:13px; color:var(--text-muted);'>No elevated risk contributions flagged.</p>";
    return;
  }

  contributions.forEach(c => {
    const item = document.createElement("div");
    item.className = "xai-bar-wrap";

    item.innerHTML = `
      <div class="xai-bar-label">
        <span style="font-weight:600; color:${c.is_critical ? '#ff4d66' : 'var(--text-main)'};">
          ${c.title}
        </span>
        <strong style="color:${c.is_critical ? '#ff1a35' : '#ffffff'}; font-family:monospace;">
          +${c.impact_percentage}%
        </strong>
      </div>
      <div class="xai-bar-track">
        <div class="xai-bar-fill" style="width:${Math.min(100, c.impact_percentage * 2.2)}%;"></div>
      </div>
    `;

    container.appendChild(item);
  });
}

function renderUrlDeepDiveResults(data) {
  renderUrlsList({
    total_urls_found: 1,
    urls: [data]
  });
  
  // Set threat dial from actual URL risk score
  const dialScore = document.getElementById("dialScore");
  const dialCircle = document.getElementById("dialCircle");
  dialScore.textContent = `${data.risk_score}%`;
  if (dialCircle) dialCircle.setAttribute("aria-valuenow", String(Math.round(data.risk_score ?? 0)));
  const isHigh = data.risk_score >= 25;
  dialCircle.style.borderColor = isHigh ? "#ff1a35" : "#ffffff";
  dialCircle.style.color = isHigh ? "#ff1a35" : "#ffffff";
  dialCircle.style.boxShadow = isHigh ? "0 0 25px rgba(255, 26, 53, 0.4)" : "0 0 15px rgba(255, 255, 255, 0.2)";

  const confBadge = document.getElementById("confidencePercentage");
  if (confBadge) {
    // Confidence is derived from how many URL indicators agree: more flags = higher confidence
    const reasonsCount = (data.risk_reasons || []).length;
    const confVal = Math.min(98, 60 + reasonsCount * 8);
    confBadge.textContent = `CONFIDENCE: ${confVal}%`;
  }

  const severityBadge = document.getElementById("severityBadge");
  const categoryTitle = document.getElementById("categoryTitle");
  const socActionText = document.getElementById("socActionText");
  const isDark = document.documentElement.getAttribute("data-theme") !== "light";
  const accentColor = isHigh ? "#ff1a35" : (isDark ? "#ffffff" : "#0f172a");
  const bgAccent = isHigh ? "rgba(255, 26, 53, 0.2)" : (isDark ? "rgba(255, 255, 255, 0.1)" : "rgba(15, 23, 42, 0.08)");

  if (severityBadge) {
    const sev = data.risk_score >= 60 ? "CRITICAL" : (data.risk_score >= 40 ? "HIGH" : (data.risk_score >= 20 ? "MEDIUM" : "LOW"));
    severityBadge.textContent = sev;
    severityBadge.style.background = bgAccent;
    severityBadge.style.color = accentColor;
  }
  if (categoryTitle) {
    const reasons = (data.risk_reasons || []).slice(0, 2).join("; ") || "No critical flags detected.";
    categoryTitle.textContent = reasons;
  }
  if (socActionText) {
    socActionText.innerHTML = `<strong style="color:var(--text-main);">Domain Age:</strong> ${escapeHtml(data.domain_creation_date || "Unknown")} &bull; <strong style="color:var(--text-main);">Registrar:</strong> ${escapeHtml(data.domain_registrar || "Unknown")}`;
  }
}

function renderTextAnalysisResults(data, rawText) {
  renderNlpHeatmap(data.nlp, { hidden_elements_count: 0 }, rawText);
  const pred = data.prediction;
  const isHigh = pred.threat_score >= 25;
  const accentColor = isHigh ? "#ff1a35" : "#ffffff";
  const bgAccent = isHigh ? "rgba(255, 26, 53, 0.2)" : "rgba(255, 255, 255, 0.1)";

  document.getElementById("dialScore").textContent = `${pred.threat_score}%`;
  document.getElementById("dialCircle").style.borderColor = accentColor;
  document.getElementById("dialCircle").style.color = accentColor;
  document.getElementById("severityBadge").textContent = pred.severity;
  document.getElementById("severityBadge").style.background = bgAccent;
  document.getElementById("severityBadge").style.color = accentColor;
  document.getElementById("categoryTitle").textContent = pred.category;
  document.getElementById("socActionText").innerHTML = `<strong style="color:#ffffff;">SOC Action:</strong> ${pred.soc_action}`;

  const confBadge = document.getElementById("confidencePercentage");
  if (confBadge) {
    const confVal = pred.confidence_percentage !== undefined ? pred.confidence_percentage : Math.round((pred.rf_confidence + pred.gb_confidence) / 2);
    confBadge.textContent = `CONFIDENCE: ${confVal}%`;
  }

  renderXaiAttribution(pred.feature_contributions);
}

// Modal Controllers
function openModal(modalEl) {
  if (!modalEl) return;
  modalEl.classList.add("active");
  modalEl.setAttribute("aria-hidden", "false");
  const firstFocusable = modalEl.querySelector("button, input, textarea, a[href], [tabindex]:not([tabindex='-1'])");
  if (firstFocusable) firstFocusable.focus();
}

function closeModal(modalEl, restoreTarget) {
  if (!modalEl) return;
  modalEl.classList.remove("active");
  modalEl.setAttribute("aria-hidden", "true");
  if (restoreTarget && typeof restoreTarget.focus === "function") {
    restoreTarget.focus();
  }
}

function trapFocus(modalEl, e) {
  if (!modalEl.classList.contains("active")) return;
  if (e.key !== "Tab") return;
  const focusables = modalEl.querySelectorAll("button, input, textarea, a[href], [tabindex]:not([tabindex='-1'])");
  if (focusables.length === 0) return;
  const first = focusables[0];
  const last = focusables[focusables.length - 1];
  if (e.shiftKey && document.activeElement === first) {
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && document.activeElement === last) {
    e.preventDefault();
    first.focus();
  }
}

function initModals() {
  const sbModal = document.getElementById("sandboxModal");
  const closeSbBtn = document.getElementById("closeSandboxBtn");
  if (sbModal) sbModal.setAttribute("aria-hidden", "true");
  if (closeSbBtn) {
    closeSbBtn.addEventListener("click", () => closeModal(sbModal, document.activeElement));
  }

  const ticketModal = document.getElementById("ticketModal");
  const closeTicketBtn = document.getElementById("closeTicketBtn");
  const copyTicketBtn = document.getElementById("copyTicketBtn");
  const downloadTicketBtn = document.getElementById("downloadTicketBtn");
  if (ticketModal) ticketModal.setAttribute("aria-hidden", "true");

  if (closeTicketBtn) {
    closeTicketBtn.addEventListener("click", () => closeModal(ticketModal, document.activeElement));
  }

  if (copyTicketBtn) {
    copyTicketBtn.addEventListener("click", () => {
      const text = document.getElementById("ticketMarkdownText").value;
      navigator.clipboard.writeText(text).then(() => {
        copyTicketBtn.textContent = "Copied to Clipboard!";
        setTimeout(() => copyTicketBtn.textContent = "Copy Markdown", 2000);
      });
    });
  }

  if (downloadTicketBtn) {
    downloadTicketBtn.addEventListener("click", () => {
      const text = document.getElementById("ticketMarkdownText").value;
      const blob = new Blob([text], { type: "text/markdown" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `SOC-TICKET-${currentScenarioId.toUpperCase()}.md`;
      a.click();
    });
  }

  // Close modals when clicking on dark overlay backdrop
  [sbModal, ticketModal].forEach(modalEl => {
    if (modalEl) {
      modalEl.addEventListener("click", (e) => {
        if (e.target === modalEl) {
          closeModal(modalEl, document.activeElement);
        }
      });
      modalEl.addEventListener("keydown", (e) => trapFocus(modalEl, e));
    }
  });

  // Escape key closes active modals
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (sbModal && sbModal.classList.contains("active")) closeModal(sbModal, document.activeElement);
      if (ticketModal && ticketModal.classList.contains("active")) closeModal(ticketModal, document.activeElement);
    }
  });
}

async function openSandboxModal(targetUrl) {
  const modal = document.getElementById("sandboxModal");
  const sbUrl = document.getElementById("sbUrl");
  const sbDomainAge = document.getElementById("sbDomainAge");
  const sbSsl = document.getElementById("sbSsl");
  const sbFormAction = document.getElementById("sbFormAction");
  const iframe = document.getElementById("sandboxIframe");

  if (sbUrl) sbUrl.textContent = targetUrl;
  if (sbDomainAge) sbDomainAge.textContent = "Inspecting RDAP/WHOIS registry...";
  if (sbSsl) sbSsl.textContent = "Validating TLS Certificate...";
  if (sbFormAction) sbFormAction.textContent = "Analyzing DOM targets...";

  if (iframe) {
    iframe.srcdoc = `
      <!DOCTYPE html>
      <html>
      <head><meta charset="utf-8"></head>
      <body style="background:#020617;color:#94a3b8;font-family:system-ui,-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">
        <div style="text-align:center;padding:20px;">
          <div style="font-size:15px;font-weight:700;color:#f8fafc;margin-bottom:8px;">[TRAC-I AIR-GAPPED VIRTUAL PREVIEW SANDBOX]</div>
          <div style="font-size:12px;color:#38bdf8;">Enforcing strict SSRF & sandbox isolation... Crawling wireframe...</div>
        </div>
      </body>
      </html>
    `;
  }
  openModal(modal);

  try {
    const resp = await fetch("/api/analyze/sandbox", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: targetUrl })
    });
    const data = await resp.json();

    if (sbUrl) sbUrl.textContent = data.target_url || targetUrl;
    if (sbDomainAge) sbDomainAge.textContent = data.domain_age || "Unknown";
    if (sbSsl) sbSsl.textContent = data.ssl_issuer || "No SSL";
    if (sbFormAction) sbFormAction.textContent = data.form_action || "None detected";

    if (iframe) {
      iframe.srcdoc = data.sandboxed_html || "<p style='color:#fff;padding:20px;'>No rendered wireframe returned.</p>";
    }
  } catch (err) {
    if (iframe) {
      iframe.srcdoc = `
        <!DOCTYPE html>
        <html>
        <body style="background:#020617;color:#ef4444;font-family:system-ui,sans-serif;padding:30px;">
          <h4 style="margin-top:0;">Virtual Sandbox Inspection Failed</h4>
          <p style="font-size:12px;color:#94a3b8;">Unable to crawl or render target: ${targetUrl}</p>
        </body>
        </html>
      `;
    }
  }
}

async function openIncidentTicketModal(scenarioId) {
  const modal = document.getElementById("ticketModal");
  const textarea = document.getElementById("ticketMarkdownText");

  textarea.value = "Generating official Defense Contractor SOC Incident Ticket...";
  openModal(modal);

  try {
    const resp = await fetch(`/api/export/incident/${scenarioId}`);
    const data = await resp.json();
    textarea.value = data.markdown_ticket;
  } catch (err) {
    textarea.value = "Failed to export incident ticket.";
  }
}

// Persistent Scan History Loader
async function loadScanHistory() {
  const container = document.getElementById("historyTableContainer");
  const countBadge = document.getElementById("historyCountBadge");
  if (!container) return;

  try {
    const resp = await fetch("/api/history?limit=25");
    if (!resp.ok) throw new Error("Failed to fetch history");
    const data = await resp.json();
    const scans = Array.isArray(data) ? data : (data.scans || []);

    if (countBadge) {
      countBadge.textContent = `${scans.length} Scans`;
    }

    if (scans.length === 0) {
      container.innerHTML = `
        <div style="text-align: center; padding: 24px; color: var(--text-muted); font-size: 13px;">
          No scan records recorded yet in SQLite database. Run an email or URL analysis above.
        </div>
      `;
      return;
    }

    const rowsHtml = scans.map(item => {
      const isCrit = item.threat_score >= 70;
      const isHigh = item.threat_score >= 40 && !isCrit;
      const isMed = item.threat_score >= 25 && !isHigh && !isCrit;
      const badgeColor = isCrit ? "#ff1a35" : (isHigh ? "#f97316" : (isMed ? "#eab308" : "#22c55e"));
      const badgeBg = isCrit ? "rgba(255, 26, 53, 0.15)" : (isHigh ? "rgba(249, 115, 22, 0.15)" : (isMed ? "rgba(234, 179, 8, 0.15)" : "rgba(34, 197, 94, 0.15)"));
      const timeStr = item.created_at ? new Date(item.created_at).toLocaleTimeString() : "--:--";
      const targetDisplay = (item.target_name || "Unknown target").replace(/</g, "&lt;").replace(/>/g, "&gt;");
      const flagsDisplay = (item.summary || "None").replace(/</g, "&lt;").replace(/>/g, "&gt;");

      return `
        <tr style="border-bottom: 1px solid var(--border-color); font-size: 12px;">
          <td style="padding: 10px 12px; font-family: monospace; color: var(--text-muted); white-space: nowrap;">${timeStr}</td>
          <td style="padding: 10px 12px;">
            <span style="font-size: 10px; font-weight: 700; text-transform: uppercase; background: var(--bg-input); padding: 2px 6px; border-radius: 3px; border: 1px solid var(--border-color); color: var(--text-main);">
              ${item.scan_type}
            </span>
          </td>
          <td style="padding: 10px 12px; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text-main);" title="${targetDisplay}">
            ${targetDisplay}
          </td>
          <td style="padding: 10px 12px; white-space: nowrap;">
            <span style="font-weight: 800; color: ${badgeColor}; font-family: monospace;">${item.threat_score}%</span>
            <span style="display: inline-block; margin-left: 6px; font-size: 10px; font-weight: 700; padding: 1px 6px; border-radius: 3px; background: ${badgeBg}; color: ${badgeColor}; border: 1px solid ${badgeColor}44;">
              ${item.severity}
            </span>
          </td>
          <td style="padding: 10px 12px; font-family: monospace; color: var(--text-main); font-size: 11px; white-space: nowrap;">
            ${item.confidence_score !== undefined ? item.confidence_score : (item.confidence_percentage || '--')}%
          </td>
          <td style="padding: 10px 12px; font-size: 11px; color: var(--text-muted); max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${flagsDisplay}">
            ${flagsDisplay}
          </td>
        </tr>
      `;
    }).join("");

    container.innerHTML = `
      <table style="width: 100%; border-collapse: collapse; text-align: left;">
        <thead>
          <tr style="border-bottom: 1px solid var(--border-color); font-size: 11px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.05em; background: var(--bg-input);">
            <th style="padding: 8px 12px;">Time</th>
            <th style="padding: 8px 12px;">Type</th>
            <th style="padding: 8px 12px;">Target / Subject</th>
            <th style="padding: 8px 12px;">Threat Score</th>
            <th style="padding: 8px 12px;">Confidence</th>
            <th style="padding: 8px 12px;">Primary Threat Flags</th>
          </tr>
        </thead>
        <tbody>
          ${rowsHtml}
        </tbody>
      </table>
    `;
  } catch (err) {
    console.error("Error loading scan history:", err);
    container.innerHTML = `
      <div style="text-align: center; padding: 20px; color: #ef4444; font-size: 12px;">
        Failed to fetch audit records from SQLite history database.
      </div>
    `;
  }
}

// Re-render prediction elements on theme change
window.addEventListener("themechange", () => {
  if (currentAnalysisData) {
    renderFullTriageReport(currentAnalysisData);
  }
});

