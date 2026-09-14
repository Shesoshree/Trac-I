// Trac-I Global Scripts: Theme, Quick Scanner, and Simulator Interactivity

document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initHomeQuickScan();
  initExtensionSimulator();
});

// Day and Night Theme Management
function initTheme() {
  const themeToggleBtn = document.getElementById("themeToggle");
  const sunIcon = document.getElementById("sunIcon");
  const moonIcon = document.getElementById("moonIcon");

  // Read saved theme from localStorage, or default to dark (Night mode)
  const savedTheme = localStorage.getItem("trac_i_theme") || "dark";
  applyTheme(savedTheme, false);

  if (themeToggleBtn) {
    themeToggleBtn.addEventListener("click", () => {
      const currentTheme = document.documentElement.getAttribute("data-theme") || "dark";
      const nextTheme = currentTheme === "dark" ? "light" : "dark";

      // Micro-animation on toggle click
      themeToggleBtn.style.transform = "scale(0.85) rotate(20deg)";
      setTimeout(() => {
        themeToggleBtn.style.transform = "scale(1) rotate(0deg)";
      }, 200);

      applyTheme(nextTheme, true);
    });
  }

  function applyTheme(theme, animate) {
    if (animate) {
      document.documentElement.classList.add("theme-transitioning");
      setTimeout(() => {
        document.documentElement.classList.remove("theme-transitioning");
      }, 350);
    }

    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("trac_i_theme", theme);
    updateThemeIcons(theme);

    // Notify other components (e.g. gauges / canvas dials) about theme change
    window.dispatchEvent(new CustomEvent("themechange", { detail: { theme } }));
  }

  function updateThemeIcons(theme) {
    if (!sunIcon || !moonIcon) return;
    if (theme === "dark") {
      // In Night mode, show Sun icon (Click to switch to Day mode)
      sunIcon.style.display = "block";
      moonIcon.style.display = "none";
      if (themeToggleBtn) themeToggleBtn.title = "Switch to Day Theme";
    } else {
      // In Day mode, show Moon icon (Click to switch to Night mode)
      sunIcon.style.display = "none";
      moonIcon.style.display = "block";
      if (themeToggleBtn) themeToggleBtn.title = "Switch to Night Theme";
    }
  }

  // Cross-tab synchronization
  window.addEventListener("storage", (e) => {
    if (e.key === "trac_i_theme" && e.newValue) {
      applyTheme(e.newValue, false);
    }
  });
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
    resultBox.innerHTML = "<div style='color:var(--accent-500); font-weight:600;'>Running multi-feature lexical analysis...</div>";

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
      resultBox.innerHTML = `<div style="color:var(--accent-500);">Error analyzing URL. Ensure server is reachable.</div>`;
    } finally {
      quickBtn.disabled = false;
      quickBtn.textContent = "Analyze Link";
    }
  });
}

function renderHomeQuickResult(data, container) {
  const isHighRisk = data.risk_score >= 50;
  const isSuspicious = data.risk_score >= 25;
  const isDark = document.documentElement.getAttribute("data-theme") !== "light";
  
  const badgeColor = isHighRisk ? "#ff1a35" : (isSuspicious ? "#ff4d66" : (isDark ? "#ffffff" : "#0f172a"));
  const badgeBg = isHighRisk ? "rgba(255, 26, 53, 0.2)" : (isSuspicious ? "rgba(255, 77, 102, 0.15)" : "var(--safe-bg)");
  const badgeText = isHighRisk ? "CRITICAL THREAT" : (isSuspicious ? "SUSPICIOUS THREAT" : "VERIFIED SAFE");

  let reasonsHtml = "";
  if (data.risk_reasons && data.risk_reasons.length > 0) {
    reasonsHtml = `<ul style="margin-top:8px; padding-left:20px; font-size:12px; color:var(--accent-500);">
      ${data.risk_reasons.map(r => `<li>${r}</li>`).join("")}
    </ul>`;
  }

  container.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
      <div>
        <span style="font-size:11px; font-weight:bold; background:${badgeBg}; color:${badgeColor}; border:1px solid ${isHighRisk ? '#ff1a3566' : 'var(--border-subtle)'}; padding:3px 8px; border-radius:4px;">
          ${badgeText} (${data.risk_score}% Threat Score)
        </span>
        <h4 style="margin-top:6px; font-size:15px; font-weight:700; font-family:monospace; color:var(--text-main);">
          ${data.hostname}
        </h4>
      </div>
      <a href="/scan" class="btn btn-accent btn-sm">Deep Triage &rarr;</a>
    </div>

    <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:10px; margin-top:12px; font-size:12px;">
      <div style="background:var(--bg-surface); border:1px solid var(--border-color); padding:8px 10px; border-radius:4px;">
        <span style="color:var(--text-muted);">Homoglyphs:</span>
        <strong style="color:${data.homoglyphs_detected?.length ? 'var(--accent-500)' : 'var(--text-main)'};">
          ${data.homoglyphs_detected?.length ? `${data.homoglyphs_detected.length} Confusable Glyphs` : 'None'}
        </strong>
      </div>
      <div style="background:var(--bg-surface); border:1px solid var(--border-color); padding:8px 10px; border-radius:4px;">
        <span style="color:var(--text-muted);">Target Typosquat:</span>
        <strong style="color:${data.typosquat_target ? 'var(--accent-500)' : 'var(--text-main)'};">
          ${data.typosquat_target ? `Impersonating ${data.typosquat_target}` : 'None'}
        </strong>
      </div>
      <div style="background:var(--bg-surface); border:1px solid var(--border-color); padding:8px 10px; border-radius:4px;">
        <span style="color:var(--text-muted);">Shannon Entropy:</span>
        <strong style="color:var(--text-main);">${data.entropy_domain}</strong>
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
      alert("⚠️ Trac-I Blocked Navigation!\n\nThis link contains an IDN Cyrillic homoglyph (xn--cmmc-d-81a.xyz) masquerading as a legitimate defense portal.\n\nOpening destination in safe virtual sandbox...");
      window.location.href = "/scan";
    });
  }
}
