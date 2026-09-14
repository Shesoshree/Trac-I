// Scam Detective Phishing Triage Console Logic
let currentScenarioId = "apt_hr_policy_update";
let currentAnalysisData = null;

document.addEventListener("DOMContentLoaded", async () => {
  initTabs();
  initModals();
  await loadScenarios();
  setupEventListeners();
});

// Tab Navigation
function initTabs() {
  const tabBtns = document.querySelectorAll(".tab-btn");
  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");

      const targetId = btn.getAttribute("data-tab");
      document.querySelectorAll(".tab-content").forEach(tc => tc.style.display = "none");
      const targetContent = document.getElementById(targetId);
      if (targetContent) targetContent.style.display = "block";
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
      customPill.style.border = '1px solid #38bdf8';
      customPill.style.color = '#38bdf8';
      customPill.innerHTML = `&#9888; ${customTitle}`;
      customPill.addEventListener("click", () => {
        selectCustomScenario(customEml, customTitle, customPill);
      });
      container.appendChild(customPill);
    }

    scenarios.forEach((s, idx) => {
      const pill = document.createElement("button");
      pill.className = `scenario-pill ${(!isCustomMode && idx === 0) ? 'active' : ''}`;
      pill.textContent = s.title;
      pill.addEventListener("click", () => selectScenario(s.id, pill));
      container.appendChild(pill);
    });

    // Automatically load either the custom scenario or the first preloaded scenario
    if (isCustomMode) {
      selectCustomScenario(customEml, customTitle);
    } else if (scenarios.length > 0) {
      await selectScenario(scenarios[0].id);
    }
  } catch (err) {
    console.error("Failed to load scenarios:", err);
  }
}

function selectCustomScenario(rawEml, title, pillElement = null) {
  currentScenarioId = "custom_spear_phish";

  if (pillElement) {
    document.querySelectorAll(".scenario-pill").forEach(p => p.classList.remove("active"));
    pillElement.classList.add("active");
  }

  const rawInput = document.getElementById("rawEmlInput");
  const metaSummary = document.getElementById("scenarioMetaSummary");

  if (rawInput) rawInput.value = rawEml;
  if (metaSummary) {
    metaSummary.innerHTML = `
      <strong>${title}</strong><br>
      <span style="color:#38bdf8;">Origin:</span> Personalized Defense Threat Studio<br>
      <span style="color:#cbd5e1;">Target Profile:</span> Cleared personnel targeted with customized homoglyphs, GCC High lure, or urgent compliance coercion.
    `;
  }

  // Auto trigger analysis
  runEmailAnalysis(rawEml);
}

async function selectScenario(scenarioId, pillElement = null) {
  currentScenarioId = scenarioId;

  // Update pills UI
  if (pillElement) {
    document.querySelectorAll(".scenario-pill").forEach(p => p.classList.remove("active"));
    pillElement.classList.add("active");
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
        <span style="color:#38bdf8;">Target:</span> ${data.target}<br>
        <span style="color:#cbd5e1;">Summary:</span> ${data.summary}
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
      analyzeUrlBtn.textContent = "Analyzing...";

      try {
        const resp = await fetch("/api/analyze/url", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url })
        });
        const data = await resp.json();
        renderUrlDeepDiveResults(data);
      } catch (e) {
        alert("URL inspection failed.");
      } finally {
        analyzeUrlBtn.disabled = false;
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
      analyzeTextBtn.textContent = "Analyzing...";

      try {
        const resp = await fetch("/api/analyze/text", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text })
        });
        const data = await resp.json();
        renderTextAnalysisResults(data, text);
      } catch (e) {
        alert("Text analysis failed.");
      } finally {
        analyzeTextBtn.disabled = false;
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
}

// Master Email Analysis Execution
async function runEmailAnalysis(rawEml) {
  const btn = document.getElementById("analyzeEmailBtn");
  if (btn) {
    btn.disabled = true;
    btn.textContent = "Executing AI Pipeline...";
  }

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
  } catch (err) {
    alert("Error executing detection engine. Ensure FastAPI server is running.");
    console.error(err);
  } finally {
    if (btn) {
      btn.disabled = false;
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

  const score = pred.threat_score;
  dialScore.textContent = `${score}%`;
  dialCircle.style.borderColor = pred.badge_color;
  dialCircle.style.color = pred.badge_color;

  severityBadge.textContent = pred.severity;
  severityBadge.style.background = `${pred.badge_color}33`;
  severityBadge.style.color = pred.badge_color;

  categoryTitle.textContent = pred.category;
  socActionText.innerHTML = `<strong>SOC Action:</strong> ${pred.soc_action}`;
  modelConfidence.textContent = `RF: ${pred.rf_confidence}% | GBM: ${pred.gb_confidence}%`;

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
  spfEl.style.color = spfStatus === "PASS" ? "#10b981" : (spfStatus === "NONE" ? "#f59e0b" : "#ef4444");

  dkimEl.textContent = dkimStatus;
  dkimEl.style.color = dkimStatus === "PASS" ? "#10b981" : (dkimStatus === "NONE" ? "#f59e0b" : "#ef4444");

  dmarcEl.textContent = dmarcStatus;
  dmarcEl.style.color = dmarcStatus === "PASS" ? "#10b981" : (dmarcStatus === "NONE" ? "#f59e0b" : "#ef4444");

  riskBadge.textContent = `Risk Score: ${headers.header_risk_score}/100`;

  mismatchesList.innerHTML = "";
  if (headers.header_flags && headers.header_flags.length > 0) {
    headers.header_flags.forEach(flag => {
      const item = document.createElement("div");
      item.className = "red-flag-item";
      item.innerHTML = `&#9888; ${flag}`;
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
      border: 1px solid ${isThreat ? '#ef4444' : 'var(--border-color)'};
      border-radius: 6px;
      padding: 12px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    `;

    // Homoglyph display
    let homoglyphDetail = "None";
    if (u.homoglyphs_detected && u.homoglyphs_detected.length > 0) {
      homoglyphDetail = u.homoglyphs_detected.map(h => 
        `<span style="background:#ef444433; color:#f87171; padding:2px 4px; border-radius:3px; font-weight:bold;">
          ${h.char} (${h.unicode} resembling '${h.resembles}')
        </span>`
      ).join(" ");
    }

    card.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
        <div style="font-family:monospace; font-size:13px; font-weight:bold; color:${isThreat ? '#f87171' : '#34d399'};">
          ${u.url}
        </div>
        <div style="display:flex; gap:6px; align-items:center;">
          <span style="font-size:11px; font-weight:bold; background:${isThreat ? '#ef444433' : '#10b98133'}; color:${isThreat ? '#ef4444' : '#10b981'}; padding:3px 8px; border-radius:4px;">
            ${u.risk_score}% Risk
          </span>
          <button class="btn btn-outline btn-sm sandbox-btn" data-url="${encodeURIComponent(u.url)}">
            Safe Sandbox
          </button>
        </div>
      </div>

      <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(170px, 1fr)); gap:8px; font-size:11.5px;">
        <div><span style="color:var(--text-muted);">Punycode:</span> <strong>${u.is_punycode ? u.decoded_punycode : 'Standard ASCII'}</strong></div>
        <div><span style="color:var(--text-muted);">Homoglyphs:</span> <strong>${homoglyphDetail}</strong></div>
        <div><span style="color:var(--text-muted);">Brand Target:</span> <strong style="color:${u.typosquat_target ? '#f87171' : 'inherit'};">${u.typosquat_target || 'None'}</strong></div>
        <div><span style="color:var(--text-muted);">Shannon Entropy:</span> <strong>${u.entropy_domain}</strong></div>
      </div>

      ${u.risk_reasons && u.risk_reasons.length > 0 ? `
        <div style="font-size:11px; color:#f87171; border-top:1px dashed #334155; padding-top:6px;">
          <strong>Threat Flags:</strong> ${u.risk_reasons.join(" &bull; ")}
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
    <div style="background:var(--bg-input); padding:6px 12px; border-radius:4px; font-size:12px;">
      <span style="color:var(--text-muted);">Urgency Triggers:</span>
      <strong style="color:${counts.urgency > 0 ? '#f59e0b' : '#10b981'};">${counts.urgency || 0}</strong>
    </div>
    <div style="background:var(--bg-input); padding:6px 12px; border-radius:4px; font-size:12px;">
      <span style="color:var(--text-muted);">Fear / Disciplinary:</span>
      <strong style="color:${counts.fear > 0 ? '#ef4444' : '#10b981'};">${counts.fear || 0}</strong>
    </div>
    <div style="background:var(--bg-input); padding:6px 12px; border-radius:4px; font-size:12px;">
      <span style="color:var(--text-muted);">Credential Solicitation:</span>
      <strong style="color:${counts.credential > 0 ? '#a855f7' : '#10b981'};">${counts.credential > 0 ? 'YES' : 'NONE'}</strong>
    </div>
    <div style="background:var(--bg-input); padding:6px 12px; border-radius:4px; font-size:12px;">
      <span style="color:var(--text-muted);">Anti-Spam Hidden Text:</span>
      <strong style="color:${dom.hidden_elements_count > 0 ? '#ef4444' : '#10b981'};">${dom.hidden_elements_count || 0}</strong>
    </div>
  `;

  // Highlight keywords in text
  let highlighted = textSnippet || "No text content.";
  if (nlp.matched_triggers) {
    for (const [cat, matches] of Object.entries(nlp.matched_triggers)) {
      matches.forEach(m => {
        const regex = new RegExp(`(${m.phrase})`, "gi");
        const cls = cat === "urgency" ? "highlight-urgency" : (cat === "fear_consequence" ? "highlight-fear" : "highlight-credential");
        highlighted = highlighted.replace(regex, `<span class="${cls}">$1</span>`);
      });
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
        <span style="font-weight:600; color:${c.is_critical ? '#f87171' : 'var(--text-main)'};">
          ${c.title}
        </span>
        <strong style="color:${c.is_critical ? '#ef4444' : '#38bdf8'}; font-family:monospace;">
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
  
  // Set threat dial
  const dialScore = document.getElementById("dialScore");
  const dialCircle = document.getElementById("dialCircle");
  dialScore.textContent = `${data.risk_score}%`;
  dialCircle.style.borderColor = data.risk_score >= 50 ? "#ef4444" : "#10b981";
  dialCircle.style.color = data.risk_score >= 50 ? "#ef4444" : "#10b981";
}

function renderTextAnalysisResults(data, rawText) {
  renderNlpHeatmap(data.nlp, { hidden_elements_count: 0 }, rawText);
  const pred = data.prediction;
  document.getElementById("dialScore").textContent = `${pred.threat_score}%`;
  document.getElementById("dialCircle").style.borderColor = pred.badge_color;
  document.getElementById("dialCircle").style.color = pred.badge_color;
  document.getElementById("severityBadge").textContent = pred.severity;
  document.getElementById("categoryTitle").textContent = pred.category;
  document.getElementById("socActionText").innerHTML = `<strong>SOC Action:</strong> ${pred.soc_action}`;
  renderXaiAttribution(pred.feature_contributions);
}

// Modal Controllers
function initModals() {
  // Sandbox Modal
  const sbModal = document.getElementById("sandboxModal");
  const closeSbBtn = document.getElementById("closeSandboxBtn");
  if (closeSbBtn) {
    closeSbBtn.addEventListener("click", () => sbModal.classList.remove("active"));
  }

  // Incident Ticket Modal
  const ticketModal = document.getElementById("ticketModal");
  const closeTicketBtn = document.getElementById("closeTicketBtn");
  const copyTicketBtn = document.getElementById("copyTicketBtn");
  const downloadTicketBtn = document.getElementById("downloadTicketBtn");

  if (closeTicketBtn) {
    closeTicketBtn.addEventListener("click", () => ticketModal.classList.remove("active"));
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
}

async function openSandboxModal(targetUrl) {
  const modal = document.getElementById("sandboxModal");
  const sbUrl = document.getElementById("sbUrl");
  const sbSsl = document.getElementById("sbSsl");
  const sbGeo = document.getElementById("sbGeo");
  const sbFormAction = document.getElementById("sbFormAction");
  const renderContainer = document.getElementById("sbRenderContainer");

  renderContainer.innerHTML = "<div style='text-align:center; padding:40px;'>Isolating virtual container and analyzing DOM...</div>";
  modal.classList.add("active");

  try {
    const resp = await fetch("/api/analyze/sandbox", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: targetUrl })
    });
    const data = await resp.json();

    sbUrl.textContent = data.target_url;
    sbSsl.textContent = data.ssl_issuer;
    sbGeo.textContent = data.ip_geolocation;
    sbFormAction.textContent = data.form_action;

    renderContainer.innerHTML = data.sandboxed_html;
  } catch (err) {
    renderContainer.innerHTML = "<div style='color:red;'>Failed to load sandbox container.</div>";
  }
}

async function openIncidentTicketModal(scenarioId) {
  const modal = document.getElementById("ticketModal");
  const textarea = document.getElementById("ticketMarkdownText");

  textarea.value = "Generating official Defense Contractor SOC Incident Ticket...";
  modal.classList.add("active");

  try {
    const resp = await fetch(`/api/export/incident/${scenarioId}`);
    const data = await resp.json();
    textarea.value = data.markdown_ticket;
  } catch (err) {
    textarea.value = "Failed to export incident ticket.";
  }
}
