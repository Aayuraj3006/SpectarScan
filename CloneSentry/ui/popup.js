const API_URL = "https://spectarscan.onrender.com/predict";
const API_KEY = "YOUR_BACKEND_TOKEN";

document.addEventListener('DOMContentLoaded', () => {

    const scanBtn = document.getElementById('scanBtn');
    const statusCard = document.getElementById('status-card');
    const verdictEl = document.getElementById('verdict');
    const riskEl = document.getElementById('risk-lvl');

    const vtHitsEl = document.getElementById('vt-hits');
    const ageEl = document.getElementById('age');
    const sslEl = document.getElementById('ssl');

    const manualInput = document.getElementById("manualUrl");

    scanBtn.addEventListener('click', async () => {

        setLoadingState();

        try {
            const urlToScan = await getUrlToScan();

            if (!urlToScan) return;

            const data = await scanUrl(urlToScan);

            updateUI(data);

        } catch (error) {
            showError();
        } finally {
            scanBtn.disabled = false;
        }
    });


    // ===== HELPERS =====

    function setLoadingState() {
        verdictEl.innerText = "Scanning...";
        riskEl.innerText = "Checking threats...";
        statusCard.style.background = "#7f8c8d";
        scanBtn.disabled = true;
    }

    async function getUrlToScan() {

        // Manual input
        if (manualInput && manualInput.value.trim() !== "") {
            let input = manualInput.value.trim();
            return input.startsWith("http") ? input : "https://" + input;
        }

        // Current tab
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        if (!tab.url || !tab.url.startsWith('http')) {
            verdictEl.innerText = "Invalid Page";
            riskEl.innerText = "Cannot scan this page";
            scanBtn.disabled = false;
            return null;
        }

        return tab.url;
    }

    async function scanUrl(url) {

        const response = await fetch(API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': API_KEY
            },
            body: JSON.stringify({ url })
        });

        if (!response.ok) throw new Error('Backend error');

        return response.json();
    }

    function updateUI(data) {

        // 🔥 MAIN VERDICT
        verdictEl.innerText = formatVerdict(data);

        // 🔥 RISK LABEL
        riskEl.innerText = getRiskLabel(data.risk_level);

        // 🔍 DETAILS
        vtHitsEl.innerText = `${data.signals?.virus_total_hits || 0}`;
        ageEl.innerText = formatAge(data.signals?.domain_age_days);
        sslEl.innerText = data.signals?.ssl_active ? "Secure" : "Not Secure";

        // 🎨 COLOR
        statusCard.style.background = getColor(data.risk_level);
    }

    function formatVerdict(data) {
        if (data.risk_level === "High") return "Dangerous Website";
        if (data.risk_level === "Medium") return "Suspicious Website";
        return "Safe Website";
    }

    function getRiskLabel(level) {
        if (level === "High") return "High Risk";
        if (level === "Medium") return "Medium Risk";
        return "Low Risk";
    }

    function formatAge(days) {
        if (!days) return "Unknown";
        if (days < 7) return "Very New";
        if (days < 30) return "New";
        if (days < 365) return "Moderate";
        return "Established";
    }

    function getColor(level) {
        if (level === "High") return "#c0392b";
        if (level === "Medium") return "#d35400";
        return "#27ae60";
    }

    function showError() {
        verdictEl.innerText = "Connection Failed";
        riskEl.innerText = "Try again";
        statusCard.style.background = "#2c3e50";
    }

});