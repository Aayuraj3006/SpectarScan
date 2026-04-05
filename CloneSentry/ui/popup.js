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

                if (response && response.success) {
                    const res = response.result;

                    statusCard.className = "status-card";

                    if (res.status === "DANGER") {
                        statusCard.classList.add("danger");
                        verdict.innerText = "MALICIOUS";
                    } else if (res.status === "WARNING") {
                        statusCard.classList.add("warning");
                        verdict.innerText = "SUSPICIOUS / UNKNOWN";
                    } else {
                        statusCard.classList.add("safe");
                        verdict.innerText = "LEGITIMATE";
                    }

                    vtLabel.innerText =
                        res.vtHits === null
                            ? "No VirusTotal Data"
                            : `${res.vtHits} Engines Flagged`;

                    if (res.age === 0) {
                        ageLabel.innerText = "Very New Domain";
                    } else if (res.age < 7) {
                        ageLabel.innerText = `${res.age} Days Old`;
                    } else {
                        ageLabel.innerText = "Established Site";
                    }

                    const hasSSL = res.ssl || tab.url.toLowerCase().startsWith("https://");
                    sslLabel.innerText = hasSSL ? "Secure (HTTPS)" : "Unsecured (HTTP)";

                } else {
                    verdict.innerText = "Scan Failed";
                }
            }
        );
    };
});