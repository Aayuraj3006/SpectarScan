chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "AUTOSCAN_RESULT") {

        // 🔥 Ignore weak/early results
        if (msg.verdict.includes("Unknown")) return;

        showToast(msg.verdict, msg.isMalicious || msg.isNewDomain);

        if (msg.isMalicious || msg.isNewDomain) {
            lockInputs(msg.isMalicious ? "DANGER" : "WARNING");
        }
    }
});


function lockInputs(reason) {
    const inputs = document.querySelectorAll('input[type="password"], input[type="email"], input[type="text"]');

    inputs.forEach(input => {
        input.style.filter = "blur(8px)";
        input.disabled = true; // 🔥 real protection
        input.style.transition = "filter 0.5s";
    });

    if (!document.getElementById("specter-unlock-btn")) {
        const btn = document.createElement("button");
        btn.id = "specter-unlock-btn";

        btn.innerText =
            reason === "DANGER"
                ? "MALICIOUS SITE — UNLOCK AT YOUR OWN RISK"
                : " SUSPICIOUS SITE — CLICK TO UNLOCK";

        btn.style = `
            position:fixed;
            bottom:30px;
            right:30px;
            z-index:999999;
            padding:15px;
            border-radius:50px;
            background:#1a2a3a;
            color:white;
            font-weight:bold;
            cursor:pointer;
            border:2px solid #3498db;
            box-shadow:0 4px 15px rgba(0,0,0,0.5);
        `;

        btn.onclick = () => {
            inputs.forEach(i => {
                i.style.filter = "none";
                i.disabled = false;
            });
            btn.remove();
        };

        document.body.appendChild(btn);
    }
}

let currentToast = null;

function showToast(text, isThreat) {
    if (currentToast) {
        currentToast.remove();
    }

    const toast = document.createElement("div");
    currentToast = toast;

    toast.style = `
        position:fixed;
        top:20px;
        right:20px;
        z-index:999999;
        background:${isThreat ? '#c0392b' : '#27ae60'};
        color:white;
        padding:15px 25px;
        border-radius:8px;
        font-family:sans-serif;
        font-weight:bold;
        box-shadow:0 4px 12px rgba(0,0,0,0.3);
        transition: opacity 0.5s;
    `;

    toast.innerText = text;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => {
            toast.remove();
            if (currentToast === toast) currentToast = null;
        }, 500);
    }, 4000);
}


// ===== FIXED FORM HIJACK PROTECTION =====
document.addEventListener("submit", (e) => {
    const actionUrl = new URL(e.target.action, window.location.origin);

    if (actionUrl.hostname !== window.location.hostname) {
        const safe = ["google.com", "facebook.com", "microsoft.com", "apple.com"];

        const isSafe = safe.some(d =>
            actionUrl.hostname === d || actionUrl.hostname.endsWith(`.${d}`)
        );

        if (!isSafe) {
            e.preventDefault();
            alert("SpecterScan: Form Hijack Blocked! Data was being sent to:: " + actionUrl.hostname);
        }
    }
}, true);