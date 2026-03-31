const API_URL = "https://spectarscan.onrender.com/predict";
const API_KEY = "b5BbVpPoOv3loryfGnwNNudc0jKTz_S5nxmx3nZfWz4";

document.addEventListener("DOMContentLoaded", () => {

    const btn = document.getElementById("scanBtn");
    const verdict = document.getElementById("verdict");
    const risk = document.getElementById("risk-lvl");
    const vt = document.getElementById("vt-hits");
    const age = document.getElementById("age");
    const ssl = document.getElementById("ssl");

    btn.onclick = async () => {

        verdict.innerText = "Scanning...";
        risk.innerText = "";

        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        try {
            const res = await fetch(API_URL, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "x-api-key": API_KEY
                },
                body: JSON.stringify({ url: tab.url })
            });

            const data = await res.json();

            verdict.innerText = data.verdict;
            risk.innerText = data.risk_level;

            vt.innerText = data.signals.virus_total_hits;
            age.innerText = data.signals.domain_age_days || "Unknown";
            ssl.innerText = data.signals.ssl_active ? "Secure" : "Not Secure";

        } catch {
            verdict.innerText = "Error";
            risk.innerText = "";
        }
    };
});