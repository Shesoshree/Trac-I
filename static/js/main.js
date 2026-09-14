// Trac-I Global Scripts: Theme, Quick Scanner, and Simulator Interactivity

document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initHomeQuickScan();
  initExtensionSimulator();
});

// Theme Management (Black Theme Default)
function initTheme() {
  const themeToggleBtn = document.getElementById("themeToggle");
  const sunIcon = document.getElementById("sunIcon");
  const moonIcon = document.getElementById("moonIcon");
  
  // Default and enforce black dark theme
  document.documentElement.setAttribute("data-theme", "dark");
  localStorage.setItem("trac_i_theme", "dark");
  updateThemeIcons("dark");

  if (themeToggleBtn) {
    themeToggleBtn.addEventListener("click", () => {
      // Toggle animation feedback while maintaining black theme styling
      themeToggleBtn.style.transform = "scale(0.92)";
      setTimeout(() => {
        themeToggleBtn.style.transform = "scale(1)";
      }, 150);
      document.documentElement.setAttribute("data-theme", "dark");
      localStorage.setItem("trac_i_theme", "dark");
      updateThemeIcons("dark");
    });
  }

  function updateThemeIcons(theme) {
    if (!sunIcon || !moonIcon) return;
    sunIcon.style.display = "none";
    moonIcon.style.display = "block";
    moonIcon.style.color = "#ff1a35";
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
    resultBox.innerHTML = "<div style='color:#ff1a35; font-weight:600;'>Running multi-feature lexical analysis...</div>";

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
      resultBox.innerHTML = `<div style="color:#ff1a35;">Error analyzing URL. Ensure server is reachable.</div>`;
    } finally {
      quickBtn.disabled = false;
      quickBtn.textContent = "Analyze Link";
    }
  });
}

function renderHomeQuickResult(data, container) {
  const isHighRisk = data.risk_score >= 50;
  const isSuspicious = data.risk_score >= 25;
  const badgeColor = isHighRisk ? "#ff1a35" : (isSuspicious ? "#ff4d66" : "#ffffff");
  const badgeBg = isHighRisk ? "rgba(255, 26, 53, 0.2)" : (isSuspicious ? "rgba(255, 77, 102, 0.15)" : "rgba(255, 255, 255, 0.1)");
  const badgeText = isHighRisk ? "CRITICAL THREAT" : (isSuspicious ? "SUSPICIOUS THREAT" : "VERIFIED SAFE");

  let reasonsHtml = "";
  if (data.risk_reasons && data.risk_reasons.length > 0) {
    reasonsHtml = `<ul style="margin-top:8px; padding-left:20px; font-size:12px; color:#ff4d66;">
      ${data.risk_reasons.map(r => `<li>${r}</li>`).join("")}
    </ul>`;
  }

  container.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
      <div>
        <span style="font-size:11px; font-weight:bold; background:${badgeBg}; color:${badgeColor}; border:1px solid ${badgeColor}66; padding:3px 8px; border-radius:4px;">
          ${badgeText} (${data.risk_score}% Threat Score)
        </span>
        <h4 style="margin-top:6px; font-size:15px; font-weight:700; font-family:monospace; color:#ffffff;">
          ${data.hostname}
        </h4>
      </div>
      <a href="/scan" class="btn btn-accent btn-sm">Deep Triage &rarr;</a>
    </div>

    <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:10px; margin-top:12px; font-size:12px;">
      <div style="background:#000000; border:1px solid #222222; padding:8px 10px; border-radius:4px;">
        <span style="color:#a3a3a3;">Homoglyphs:</span>
        <strong style="color:${data.homoglyphs_detected?.length ? '#ff1a35' : '#ffffff'};">
          ${data.homoglyphs_detected?.length ? `${data.homoglyphs_detected.length} Confusable Glyphs` : 'None'}
        </strong>
      </div>
      <div style="background:#000000; border:1px solid #222222; padding:8px 10px; border-radius:4px;">
        <span style="color:#a3a3a3;">Target Typosquat:</span>
        <strong style="color:${data.typosquat_target ? '#ff1a35' : '#ffffff'};">
          ${data.typosquat_target ? `Impersonating ${data.typosquat_target}` : 'None'}
        </strong>
      </div>
      <div style="background:#000000; border:1px solid #222222; padding:8px 10px; border-radius:4px;">
        <span style="color:#a3a3a3;">Shannon Entropy:</span>
        <strong style="color:#ffffff;">${data.entropy_domain}</strong>
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
