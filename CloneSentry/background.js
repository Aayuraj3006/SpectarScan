const API_URL = "https://spectarscan.onrender.com/predict";

// SINGLE SOURCE OF TRUTH → USE BACKEND VERDICT
function evaluateRisk(data) {
    const vtHits = data.signals?.vt_hits ?? null;
    const age = data.signals?.domain_age ?? 0;
    const ssl = data.signals?.ssl ?? false;

    let status = "SAFE";
    let message = "Site is Legitimate";

    if (data.verdict === "Dangerous") {
        status = "DANGER";
        message = "Malicious Website Detected";
    } else if (data.verdict === "Suspicious") {
        status = "WARNING";
        message = "Suspicious Website";
    } else if (data.verdict === "Unknown") {
        status = "WARNING";
        message = "Unknown / Unverified Website";
    }

    return {
        status,
        message,
        vtHits,
        age,
        ssl,
        isMalicious: status === "DANGER",
        isNew: status === "WARNING"
    };
}

// ===== MANUAL SCAN =====
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "PERFORM_SCAN") {
        fetch(API_URL, {
            method: "POST",
            headers: { 
                "Content-Type": "application/json",
                "x-api-key": "b5BbVpPoOv3loryfGnwNNudc0jKTz_S5nxmx3nZfWz4" // ⚠️ REQUIRED
            },
            body: JSON.stringify({ url: request.url })
        })
        .then(res => res.json())
        .then(data => {
            console.log("API RESPONSE:", data);
            const result = evaluateRisk(data);
            sendResponse({ success: true, result });
        })
        .catch(err => {
            console.error("Manual scan error:", err);
            sendResponse({ success: false });
        });

        return true;
    }
});

// ===== AUTO SCAN (WITH CACHE) =====
const scannedTabs = new Map();

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url?.startsWith('http')) {

        if (scannedTabs.get(tabId) === tab.url) return;
        scannedTabs.set(tabId, tab.url);

        try {
            const res = await fetch(API_URL, {
                method: "POST",
                headers: { 
                    "Content-Type": "application/json",
                    "x-api-key": "b5BbVpPoOv3loryfGnwNNudc0jKTz_S5nxmx3nZfWz4"
                },
                body: JSON.stringify({ url: tab.url })
            });

            const data = await res.json();
            console.log("AUTO API:", data);

            const result = evaluateRisk(data);

            sendResult(tabId, {
                type: "AUTOSCAN_RESULT",
                verdict: result.message,
                isMalicious: result.isMalicious,
                isNewDomain: result.isNew
            });

        } catch (e) {
            console.log("Auto-scan failed:", e);
        }
    }
});

// Retry send (fix timing issue)
function sendResult(tabId, payload) {
    chrome.tabs.sendMessage(tabId, payload, () => {
        if (chrome.runtime.lastError) {
            setTimeout(() => {
                chrome.tabs.sendMessage(tabId, payload);
            }, 500);
        }
    });
}