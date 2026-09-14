// Scam Detective Global Scripts: Theme, Quick Scanner, and Simulator Interactivity

document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initHomeQuickScan();
  initExtensionSimulator();
});

// Theme Toggle (Dark / Light)
function initTheme() {
  const themeToggleBtn = document.getElementById("themeToggle");
  const sunIcon = document.getElementById("sunIcon");
  const moonIcon = document.getElementById("moonIcon");
  
  const savedTheme = localStorage.getItem("scam_detective_theme") || "dark";
  document.documentElement.setAttribute("data-theme", savedTheme);
  updateThemeIcons(savedTheme);

  if (themeToggleBtn) {
    themeToggleBtn.addEventListener("click", () => {
      const currentTheme = document.documentElement.getAttribute("data-theme") || "dark";
      const newTheme = currentTheme === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", newTheme);
      localStorage.setItem("scam_detective_theme", newTheme);
      updateThemeIcons(newTheme);
    });
  }

  function updateThemeIcons(theme) {
    if (!sunIcon || !moonIcon) return;
    if (theme === "light") {
      sunIcon.style.display = "block";
      moonIcon.style.display = "none";
    } else {
      sunIcon.style.display = "none";
      moonIcon.style.display = "block";
    }
  }
}

// Home Page Quick URL Analyzer
function initHomeQuickScan() {
  const quickBtn = document.getElementById("homeQuickBtn");
  const quickInput = document.getElementById("homeQuickInput");
  const resultBox = document.getElementById("homeQuickResult");

  if (!quickBtn || !quickInput || !resultBox) return;

  quickBtn.addEventListener("click", async () => {
    const url = quickInput.value.trim();
    if (!url) {
      alert("Please enter a URL to analyze.");
      return;
    }

    quickBtn.disabled = true;
    quickBtn.textContent = "Analyzing...";
    resultBox.style.display = "block";
    resultBox.innerHTML = "<div style='color:#38bdf8;'>Running multi-feature lexical analysis...</div>";

    try {
      const resp = await fetch("/api/analyze/url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });

      if (!resp.ok) throw new Error("Analysis failed");
      const data = await resp.json();

      renderHomeQuickResult(data, resultBox);
    } catch (err) {
      resultBox.innerHTML = `<div style="color:#ef4444;">Error analyzing URL. Ensure server is reachable.</div>`;
    } finally {
      quickBtn.disabled = false;
      quickBtn.textContent = "Analyze Link";
    }
  });
}

function renderHomeQuickResult(data, container) {
  const isHighRisk = data.risk_score >= 50;
  const badgeColor = isHighRisk ? "#ef4444" : (data.risk_score >= 25 ? "#f59e0b" : "#10b981");
  const badgeText = isHighRisk ? "CRITICAL THREAT" : (data.risk_score >= 25 ? "SUSPICIOUS" : "VERIFIED SAFE");

  let reasonsHtml = "";
  if (data.risk_reasons && data.risk_reasons.length > 0) {
    reasonsHtml = `<ul style="margin-top:8px; padding-left:20px; font-size:12px; color:#f87171;">
      ${data.risk_reasons.map(r => `<li>${r}</li>`).join("")}
    </ul>`;
  }

  container.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
      <div>
        <span style="font-size:11px; font-weight:bold; background:${badgeColor}22; color:${badgeColor}; padding:3px 8px; border-radius:4px;">
          ${badgeText} (${data.risk_score}% Threat Score)
        </span>
        <h4 style="margin-top:6px; font-size:15px; font-weight:700; font-family:monospace; color:#fff;">
          ${data.hostname}
        </h4>
      </div>
      <a href="/scan" class="btn btn-accent btn-sm">Deep Triage &rarr;</a>
    </div>

    <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:10px; margin-top:12px; font-size:12px;">
      <div style="background:rgba(0,0,0,0.2); padding:8px 10px; border-radius:4px;">
        <span style="color:#94a3b8;">Homoglyphs:</span>
        <strong style="color:${data.homoglyphs_detected?.length ? '#ef4444' : '#10b981'};">
          ${data.homoglyphs_detected?.length ? `${data.homoglyphs_detected.length} Confusable Glyphs` : 'None'}
        </strong>
      </div>
      <div style="background:rgba(0,0,0,0.2); padding:8px 10px; border-radius:4px;">
        <span style="color:#94a3b8;">Target Typosquat:</span>
        <strong style="color:${data.typosquat_target ? '#ef4444' : '#10b981'};">
          ${data.typosquat_target ? `Impersonating ${data.typosquat_target}` : 'None'}
        </strong>
      </div>
      <div style="background:rgba(0,0,0,0.2); padding:8px 10px; border-radius:4px;">
        <span style="color:#94a3b8;">Shannon Entropy:</span>
        <strong>${data.entropy_domain}</strong>
      </div>
    </div>
    ${reasonsHtml}
  `;
}

// In-Browser Extension Simulator Interactions
function initExtensionSimulator() {
  const simIcon = document.getElementById("simExtIcon");
  const simTestLink = document.getElementById("simTestLink");

  if (simIcon) {
    simIcon.addEventListener("click", () => {
      simIcon.classList.toggle("active");
      const popupCol = document.querySelector(".sim-popup-col");
      if (popupCol) {
        popupCol.style.animation = "none";
        setTimeout(() => {
          popupCol.style.animation = "pulse 0.4s ease";
        }, 10);
      }
    });
  }

  if (simTestLink) {
    simTestLink.addEventListener("click", (e) => {
      e.preventDefault();
      alert("⚠️ Scam Detective Blocked Navigation!\n\nThis link contains an IDN Cyrillic homoglyph (xn--cmmc-d-81a.xyz) masquerading as a legitimate defense portal.\n\nOpening destination in safe virtual sandbox...");
      window.location.href = "/scan";
    });
  }
}
