const API_URL = "https://spectarscan.onrender.com/predict";
const API_KEY = "YOUR_BACKEND_TOKEN"; // 🔑 add your token

// Track scans per tab
const scannedTabs = {};

console.log("SpecterScan running");


// ===== AUTO SCAN =====
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {

    if (changeInfo.status !== "complete") return;
    if (!tab.url || !tab.url.startsWith("http")) return;

    // Avoid duplicate per tab
    if (scannedTabs[tabId] === tab.url) return;
    scannedTabs[tabId] = tab.url;

    try {
        const res = await fetch(API_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "x-api-key": API_KEY
            },
            body: JSON.stringify({
                url: tab.url
            })
        });

        if (!res.ok) return;

        const data = await res.json();

        chrome.tabs.sendMessage(tabId, {
            type: "SHOW_RESULT",
            verdict: data.verdict,
            risk: data.risk_level
        });

    } catch (e) {
        console.error("Scan failed:", e);
    }
});


// ===== SIGNAL HANDLER (SINGLE CLEAN LISTENER) =====
chrome.runtime.onMessage.addListener(async (msg, sender) => {

    if (!sender.tab || !sender.tab.url) return;

    const tabId = sender.tab.id;
    const url = sender.tab.url;

    try {

        // ===== CLOSE TAB =====
        if (msg.type === "CLOSE_TAB") {
            chrome.tabs.remove(tabId);
            return;
        }

        // ===== HIGH RISK EVENTS (INSTANT BLOCK) =====
        if (msg.type === "CREDENTIAL_SUBMIT") {

            chrome.tabs.sendMessage(tabId, {
                type: "SHOW_RESULT",
                verdict: "Credential theft attempt detected",
                risk: "High"
            });

            await sendSignal(url, "credential_submit");
            return;
        }

        if (msg.type === "DOMAIN_MISMATCH") {

            chrome.tabs.sendMessage(tabId, {
                type: "SHOW_RESULT",
                verdict: "Form submitting to external domain",
                risk: "High"
            });

            await sendSignal(url, "domain_mismatch");
            return;
        }

        // ===== MEDIUM SIGNALS =====
        if (msg.type === "HIDDEN_FORM") {
            await sendSignal(url, "hidden_form");
        }

        if (msg.type === "SUSPICIOUS_IFRAME") {
            await sendSignal(url, "iframe");
        }

        if (msg.type === "LOGIN_FORM_DETECTED") {
            await sendSignal(url, "login_form");
        }

    } catch (err) {
        console.error("Signal error:", err);
    }
});


// ===== HELPER FUNCTION =====
async function sendSignal(url, signal) {
    try {
        await fetch(API_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "x-api-key": API_KEY
            },
            body: JSON.stringify({
                url: url,
                signal: signal
            })
        });
    } catch (e) {
        console.error("Signal send failed");
    }
}