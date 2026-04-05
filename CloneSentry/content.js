chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "AUTOSCAN_RESULT") {
        showToast(msg.verdict, msg.isMalicious || msg.isNewDomain);

        if (msg.isMalicious || msg.isNewDomain) {
            lockInputs(msg.isMalicious ? "DANGER" : "NEW");
        }
    }
});

function lockInputs(reason) {
    const inputs = document.querySelectorAll('input[type="password"], input[type="email"], input[type="text"]');
    inputs.forEach(input => {
        input.style.filter = "blur(10px)";
        input.style.pointerEvents = "none";
        input.style.transition = "filter 0.5s";
    });

    if (!document.getElementById("specter-unlock-btn")) {
        const btn = document.createElement("button");
        btn.id = "specter-unlock-btn";
        btn.innerText = reason === "DANGER" ? " MALICIOUS SITE: UNLOCK AT OWN RISK" : "⚠️ NEW SITE: CLICK TO UNLOCK";
        btn.style = "position:fixed; bottom:30px; right:30px; z-index:999999; padding:15px; border-radius:50px; background:#1a2a3a; color:white; font-weight:bold; cursor:pointer; border:2px solid #3498db; box-shadow: 0 4px 15px rgba(0,0,0,0.5);";
        
        btn.onclick = () => {
            inputs.forEach(i => { i.style.filter = "none"; i.style.pointerEvents = "all"; });
            btn.remove();
        };
        document.body.appendChild(btn);
    }
}

function showToast(text, isThreat) {
    const toast = document.createElement("div");
    toast.style = `position:fixed; top:20px; right:20px; z-index:999999; background:${isThreat ? '#c0392b' : '#27ae60'}; color:white; padding:15px 25px; border-radius:8px; font-family:sans-serif; font-weight:bold; box-shadow:0 4px 12px rgba(0,0,0,0.3); transition: opacity 0.5s;`;
    toast.innerText = text;
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 500);
    }, 4000);
}

document.addEventListener("submit", (e) => {
    const actionUrl = new URL(e.target.action, window.location.origin);
    if (actionUrl.hostname !== window.location.hostname) {
        const safe = ["google.com", "facebook.com", "microsoft.com", "apple.com"];
        if (!safe.some(d => actionUrl.hostname.includes(d))) {
            e.preventDefault();
            alert(" SECURITY ALERT: Form Hijack Blocked! This site is trying to send your data to an external server: " + actionUrl.hostname);
        }
    }
}, true);