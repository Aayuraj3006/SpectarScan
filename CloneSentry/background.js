const API_URL = "https://spectarscan.onrender.com/predict";

// SINGLE SOURCE OF TRUTH FOR RISK
function evaluateRisk(data) {
    const vtHits = data.signals?.vt_hits ?? 0;
    const age = data.signals?.domain_age ?? 0;
    const ssl = data.signals?.ssl ?? false;

    let status = "SAFE";
    let message = "Site is Legitimate";

    if (vtHits >= 3) {
        status = "DANGER";
        message = "Malicious Website Detected";
    } else if (age === 1) {
        status = "WARNING";
        message = "New Website Detected";
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

// Handle Manual Popup Requests
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "PERFORM_SCAN") {
        fetch(API_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: request.url })
        })
        .then(res => res.json())
        .then(data => {
            const result = evaluateRisk(data);
            sendResponse({ success: true, result: result });
        })
        .catch(err => {
            console.error("Manual scan error:", err);
            sendResponse({ success: false });
        });
        return true; 
    }
});

// Handle Automatic Page Load Scan
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url?.startsWith('http')) {
        try {
            const res = await fetch(API_URL, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: tab.url })
            });
            const data = await res.json();
            const result = evaluateRisk(data);

            chrome.tabs.sendMessage(tabId, {
                type: "AUTOSCAN_RESULT",
                verdict: result.message,
                isMalicious: result.isMalicious,
                isNewDomain: result.isNew
            }, (response) => {
                if (chrome.runtime.lastError) {
                    // Fail silently if content script isn't injected yet
                }
            });
        } catch (e) { 
            console.log("Auto-scan failed to reach server."); 
        }
    }
});