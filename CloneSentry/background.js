const API_URL = "https://spectarscan.onrender.com/predict";
const scannedTabs = new Map();

// ===== Fetch with timeout =====
async function fetchWithTimeout(url, options = {}, timeout = 5000) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);

    try {
        const res = await fetch(url, {
            ...options,
            signal: controller.signal
        });
        clearTimeout(id);
        return res;
    } catch (err) {
        clearTimeout(id);
        throw err;
    }
}

// ===== Risk evaluation (FIXED) =====
function evaluateRisk(data) {
    const vtHits = data.signals?.vt_hits ?? 0;
    const age = data.signals?.domain_age;
    const ssl = data.signals?.ssl ?? false;

    let risk = 0;

    // --- Domain age (weak signal) ---
    let isNewDomain = false;
    if (age !== undefined && age !== null) {
        if (age < 3) {
            risk += 40;
            isNewDomain = true;
        } else if (age < 30) {
            risk += 25;
            isNewDomain = true;
        } else if (age < 180) {
            risk += 10;
        }
    }

    // --- VirusTotal hits (strong signal) ---
    if (vtHits > 0) {
        risk += vtHits * 20;
    }

    // --- SSL (very weak signal) ---
    if (!ssl) {
        risk += 5;
    }

    // --- API verdict ---
    if (data.verdict === "Dangerous") {
        risk += 80;
    } else if (data.verdict === "Suspicious") {
        risk += 40;
    }

    // ===== Final classification =====
    let status = "SAFE";
    let message = "Site appears safe";

    if (risk >= 80) {
        status = "DANGER";
        message = "Malicious Website Detected";
    } else if (risk >= 40) {
        status = "WARNING";
        message = "Suspicious Website";
    } else if (risk >= 15) {
        status = "LOW";
        message = "Low Trust (New or Unverified Site)";
    }

    return {
        status,
        message,
        risk,
        vtHits,
        age: age ?? null,
        ssl,
        isMalicious: status === "DANGER",
        isSuspicious: status === "WARNING",
        isLowTrust: status === "LOW",
        isNewDomain
    };
}

// ===== Manual scan =====
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "PERFORM_SCAN") {
        fetchWithTimeout(API_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: request.url })
        })
        .then(res => res.json())
        .then(data => {
            const result = evaluateRisk(data);
            sendResponse({ success: true, result });
        })
        .catch(() => sendResponse({ success: false }));

        return true;
    }
});

// ===== Auto scan =====
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status !== "complete" || !tab.url?.startsWith("http")) return;
    if (scannedTabs.get(tabId) === tab.url) return;

    scannedTabs.set(tabId, tab.url);

    try {
        const res = await fetchWithTimeout(API_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: tab.url })
        });

        const data = await res.json();
        const result = evaluateRisk(data);

        await chrome.scripting.executeScript({
            target: { tabId },
            files: ["content.js"]
        }).catch(() => {});

        safeSend(tabId, {
            type: "AUTOSCAN_RESULT",
            verdict: result.message,
            isMalicious: result.isMalicious,
            isSuspicious: result.isSuspicious,
            isLowTrust: result.isLowTrust,
            isNewDomain: result.isNewDomain
        });

    } catch (e) {
        console.error("Auto-scan failed:", e);
    }
});

// ===== Safe send =====
function safeSend(tabId, payload) {
    chrome.tabs.sendMessage(tabId, payload, () => {
        if (chrome.runtime.lastError) {
            if (!chrome.runtime.lastError.message.includes("Could not establish connection")) {
                console.warn(`sendMessage failed for tab ${tabId}:`, chrome.runtime.lastError.message);
            }
        }
    });
}

// ===== Cleanup =====
chrome.tabs.onRemoved.addListener(tabId => scannedTabs.delete(tabId));