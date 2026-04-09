document.addEventListener("DOMContentLoaded", () => {
    const btn = document.getElementById("scanBtn");
    const verdict = document.getElementById("verdict");
    const statusCard = document.getElementById("status-card");
    const vtLabel = document.getElementById("vt-hits");
    const ageLabel = document.getElementById("age");
    const sslLabel = document.getElementById("ssl");

    btn.onclick = async () => {
        let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab) return;

        verdict.innerText = "Analyzing...";
        btn.disabled = true;

        chrome.runtime.sendMessage(
            { action: "PERFORM_SCAN", url: tab.url },
            (response) => {
                btn.disabled = false;

                if (!response || !response.success) {
                    verdict.innerText = "Scan Failed";
                    return;
                }

                const res = response.result;

                // ===== RESET =====
                statusCard.className = "status-card";

                // ===== STATUS COLORS =====
                if (res.isMalicious) {
                    statusCard.classList.add("danger");
                    verdict.innerText = "MALICIOUS";
                } else if (res.isSuspicious) {
                    statusCard.classList.add("warning");
                    verdict.innerText = "SUSPICIOUS";
                } else if (res.isLowTrust) {
                    statusCard.classList.add("low");
                    verdict.innerText = "LOW TRUST";
                } else {
                    statusCard.classList.add("safe");
                    verdict.innerText = "SAFE";
                }

                // ===== VirusTotal =====
                if (res.vtHits === null || res.vtHits === undefined) {
                    vtLabel.innerText = "No Threat Intelligence Data";
                } else if (res.vtHits === 0) {
                    vtLabel.innerText = "No Engines Flagged";
                } else {
                    vtLabel.innerText = `${res.vtHits} Engines Flagged`;
                }

                // ===== Domain Age =====
                if (res.age === null || res.age === undefined) {
                    ageLabel.innerText = "Domain Age Unknown";
                } else if (res.age < 3) {
                    ageLabel.innerText = "Very Recently Registered";
                } else if (res.age < 30) {
                    ageLabel.innerText = "Recently Registered";
                } else if (res.age < 180) {
                    ageLabel.innerText = "Moderately Aged Domain";
                } else {
                    ageLabel.innerText = "Established Domain";
                }

                // ===== SSL =====
                const hasSSL = res.ssl || tab.url.toLowerCase().startsWith("https://");
                sslLabel.innerText = hasSSL ? "Secure Connection (HTTPS)" : "Unsecured Connection (HTTP)";
            }
        );
    };
});