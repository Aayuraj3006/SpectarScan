const API_URL = "https://spectarscan.onrender.com/predict";
const API_KEY = "b5BbVpPoOv3loryfGnwNNudc0jKTz_S5nxmx3nZfWz4";

const scannedTabs = {};

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {

    if (changeInfo.status !== "complete") return;
    if (!tab.url || !tab.url.startsWith("http")) return;

    if (scannedTabs[tabId] === tab.url) return;
    scannedTabs[tabId] = tab.url;

    try {
        const res = await fetch(API_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "x-api-key": API_KEY
            },
            body: JSON.stringify({ url: tab.url })
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


// ===== SIGNAL HANDLER =====
chrome.runtime.onMessage.addListener(async (msg, sender) => {

    if (!sender.tab || !sender.tab.url) return;

    const tabId = sender.tab.id;
    const url = sender.tab.url;

    if (msg.type === "CLOSE_TAB") {
        chrome.tabs.remove(tabId);
        return;
    }

    if (msg.type === "CREDENTIAL_SUBMIT" || msg.type === "DOMAIN_MISMATCH") {

        chrome.tabs.sendMessage(tabId, {
            type: "SHOW_RESULT",
            verdict: "Security threat detected",
            risk: "High"
        });

        await sendSignal(url, msg.type.toLowerCase());
        return;
    }

    if (["HIDDEN_FORM", "SUSPICIOUS_IFRAME", "LOGIN_FORM_DETECTED"].includes(msg.type)) {
        await sendSignal(url, msg.type.toLowerCase());
    }
});


async function sendSignal(url, signal) {
    try {
        await fetch(API_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "x-api-key": API_KEY
            },
            body: JSON.stringify({ url, signal })
        });
    } catch {}
}