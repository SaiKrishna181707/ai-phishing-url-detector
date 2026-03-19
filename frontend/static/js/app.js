const form = document.getElementById("predict-form");
const urlInput = document.getElementById("url-input");
const analyzeButton = document.getElementById("analyze-button");
const buttonLabel = document.getElementById("button-label");
const buttonSpinner = document.getElementById("button-spinner");
const resultCard = document.getElementById("result-card");
const errorCard = document.getElementById("error-card");
const predictionLabel = document.getElementById("prediction-label");
const probabilityPill = document.getElementById("probability-pill");
const scanTime = document.getElementById("scan-time");
const riskGauge = document.getElementById("risk-gauge");
const riskGaugeScore = document.getElementById("risk-gauge-score");
const safeScore = document.getElementById("safe-score");
const scamScore = document.getElementById("scam-score");
const confidenceScore = document.getElementById("confidence-score");
const riskLevel = document.getElementById("risk-level");
const explanationText = document.getElementById("explanation-text");
const domainValue = document.getElementById("domain-value");
const blacklistValue = document.getElementById("blacklist-value");
const whoisValue = document.getElementById("whois-value");
const sslValue = document.getElementById("ssl-value");
const redirectValue = document.getElementById("redirect-value");
const virustotalValue = document.getElementById("virustotal-value");
const reasonsList = document.getElementById("reasons-list");
const redirectChain = document.getElementById("redirect-chain");
const historyList = document.getElementById("history-list");
const sampleButtons = document.querySelectorAll(".sample-button");

const HISTORY_KEY = "ai-phishing-url-detector-history";

function formatPercent(value) {
  return `${(value * 100).toFixed(2)}%`;
}

function setResultAppearance(prediction, safeProbability, scamProbability) {
  probabilityPill.textContent =
    prediction === "Safe" ? `${formatPercent(safeProbability)} Safe` : `${formatPercent(scamProbability)} Scam risk`;
  probabilityPill.className = `pill ${prediction === "Scam" ? "scam" : "safe"}`;
}

function renderList(target, items, emptyMessage) {
  target.innerHTML = "";
  const content = items.length ? items : [emptyMessage];
  content.forEach((message) => {
    const item = document.createElement("li");
    item.textContent = message;
    target.appendChild(item);
  });
}

function setLoading(isLoading) {
  analyzeButton.disabled = isLoading;
  buttonLabel.textContent = isLoading ? "Scanning..." : "Analyze URL";
  buttonSpinner.classList.toggle("hidden", !isLoading);
}

function pickGaugeColor(probability) {
  if (probability >= 0.85) return "#f97316";
  if (probability >= 0.65) return "#ef4444";
  if (probability >= 0.4) return "#f59e0b";
  return "#22c55e";
}

function updateGauge(probability) {
  riskGauge.style.setProperty("--gauge-angle", `${Math.round(probability * 360)}deg`);
  riskGauge.style.setProperty("--gauge-color", pickGaugeColor(probability));
  riskGaugeScore.textContent = `${Math.round(probability * 100)}%`;
}

function loadHistory() {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
  } catch {
    return [];
  }
}

function saveHistory(entry) {
  const history = loadHistory().filter((item) => item.url !== entry.url);
  history.unshift(entry);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, 5)));
}

function renderHistory() {
  const history = loadHistory();
  historyList.innerHTML = "";

  if (!history.length) {
    const emptyItem = document.createElement("li");
    emptyItem.className = "history-empty";
    emptyItem.textContent = "No scans yet. Your recent checks will appear here.";
    historyList.appendChild(emptyItem);
    return;
  }

  history.forEach((entry) => {
    const item = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.className = "history-item";
    button.innerHTML = `
      <span class="history-url">${entry.url}</span>
      <span class="history-meta">
        <span class="history-badge ${entry.prediction.toLowerCase()}">${entry.prediction}</span>
        <span>${entry.score}</span>
      </span>
    `;
    button.addEventListener("click", async () => {
      urlInput.value = entry.url;
      try {
        await analyzeUrl(entry.url);
      } catch (error) {
        showError(error.message);
      }
    });
    item.appendChild(button);
    historyList.appendChild(item);
  });
}

function showError(message) {
  errorCard.textContent = message;
  errorCard.classList.remove("hidden");
}

function hideError() {
  errorCard.classList.add("hidden");
}

function renderResult(payload) {
  const intelligence = payload.intelligence || {};
  const virustotal = intelligence.virustotal || {};

  predictionLabel.textContent = payload.prediction;
  scanTime.textContent = new Date(payload.scanned_at).toLocaleString();
  safeScore.textContent = formatPercent(payload.safe_probability);
  scamScore.textContent = formatPercent(payload.scam_probability);
  confidenceScore.textContent = formatPercent(payload.confidence);
  riskLevel.textContent = payload.risk_level;
  explanationText.textContent = payload.explanation;
  domainValue.textContent = payload.domain || "Unavailable";
  blacklistValue.textContent = payload.blacklist_match ? "Matched" : "Clear";
  whoisValue.textContent =
    intelligence.domain_age_days != null
      ? `${intelligence.domain_age_days} days`
      : intelligence.whois_error || "Unavailable";
  sslValue.textContent =
    intelligence.ssl_valid === true
      ? "Valid"
      : intelligence.ssl_error || (intelligence.ssl_checked ? "Failed" : "Not checked");
  redirectValue.textContent = intelligence.redirect_checked
    ? `${intelligence.redirect_count} hop${intelligence.redirect_count === 1 ? "" : "s"}${intelligence.external_redirect ? " · external" : ""}`
    : intelligence.redirect_error || "Unavailable";
  virustotalValue.textContent = virustotal.checked
    ? `${virustotal.malicious} malicious / ${virustotal.suspicious} suspicious`
    : virustotal.error || "Not configured";

  setResultAppearance(payload.prediction, payload.safe_probability, payload.scam_probability);
  updateGauge(payload.scam_probability);
  renderList(reasonsList, payload.reasons || [], "No major signals were recorded for this scan.");
  renderList(redirectChain, intelligence.redirect_chain || [], "No redirect chain recorded.");

  resultCard.classList.remove("hidden");

  saveHistory({
    url: payload.url,
    prediction: payload.prediction,
    score:
      payload.prediction === "Safe"
        ? formatPercent(payload.safe_probability)
        : formatPercent(payload.scam_probability),
  });
  renderHistory();
}

async function analyzeUrl(url) {
  hideError();
  resultCard.classList.add("hidden");
  setLoading(true);

  try {
    const response = await fetch("/api/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.detail || "Unable to analyze this URL.");
    }

    renderResult(payload);
  } finally {
    setLoading(false);
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await analyzeUrl(urlInput.value);
  } catch (error) {
    showError(error.message);
  }
});

sampleButtons.forEach((button) => {
  button.addEventListener("click", async () => {
    urlInput.value = button.dataset.url;
    try {
      await analyzeUrl(button.dataset.url);
    } catch (error) {
      showError(error.message);
    }
  });
});

renderHistory();
