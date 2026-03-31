let warningInterval = null;

function blockPage(verdict) {

    if (document.getElementById("specter-overlay")) return;

    const overlay = document.createElement("div");
    overlay.id = "specter-overlay";

    overlay.innerHTML = `
        <div style="text-align:center; max-width:500px;">
            <h1>⚠ Dangerous Website</h1>
            <p>This site may steal your data.</p>
            <p style="opacity:0.7;">${verdict}</p>

            <div style="margin-top:20px;">
                <button id="leave">Leave</button>
                <button id="proceed">Proceed Anyway</button>
            </div>
        </div>
    `;

    overlay.style = `
        position:fixed;
        top:0;left:0;
        width:100%;height:100%;
        background:#111;
        color:white;
        z-index:999999;
        display:flex;
        align-items:center;
        justify-content:center;
    `;

    document.body.innerHTML = "";
    document.body.appendChild(overlay);

    document.getElementById("leave").onclick = () => {
        chrome.runtime.sendMessage({ type: "CLOSE_TAB" });
    };

    document.getElementById("proceed").onclick = () => {
        overlay.remove();
        location.reload();

        warningInterval = setInterval(() => {
            alert("Warning: You are on a dangerous website");
        }, 15000);
    };
}


// ===== MESSAGE LISTENER =====
chrome.runtime.onMessage.addListener((msg) => {

    if (msg.type !== "SHOW_RESULT") return;

    if (msg.risk === "High") {
        blockPage(msg.verdict);
    }

    if (msg.risk === "Medium") {
        showBanner("Suspicious website detected", "#f39c12");
    }
});


function showBanner(text, color) {
    const box = document.createElement("div");

    box.innerText = text;

    box.style = `
        position:fixed;
        bottom:20px;
        right:20px;
        background:${color};
        color:white;
        padding:10px;
        border-radius:6px;
        z-index:999999;
    `;

    document.body.appendChild(box);
    setTimeout(() => box.remove(), 6000);
}


// ===== DETECTION =====
function detectLoginForm() {
    document.querySelectorAll("form").forEach(form => {
        if (form.querySelector("input[type='password']")) {
            chrome.runtime.sendMessage({ type: "LOGIN_FORM_DETECTED" });
        }
    });
}

function detectFormMismatch() {
    document.querySelectorAll("form").forEach(form => {
        const action = form.action;
        if (!action) return;

        try {
            const formURL = new URL(action, location.href);
            if (formURL.hostname !== location.hostname) {
                chrome.runtime.sendMessage({ type: "DOMAIN_MISMATCH" });
            }
        } catch {}
    });
}

function detectHiddenForms() {
    document.querySelectorAll("input[type='password']").forEach(el => {
        const style = getComputedStyle(el);
        if (style.display === "none" || style.visibility === "hidden") {
            chrome.runtime.sendMessage({ type: "HIDDEN_FORM" });
        }
    });
}

function detectIframes() {
    document.querySelectorAll("iframe").forEach(frame => {
        try {
            const src = new URL(frame.src);
            if (src.hostname !== location.hostname) {
                chrome.runtime.sendMessage({ type: "SUSPICIOUS_IFRAME" });
            }
        } catch {}
    });
}

document.addEventListener("submit", (e) => {
    if (e.target.querySelector("input[type='password']")) {
        chrome.runtime.sendMessage({ type: "CREDENTIAL_SUBMIT" });
    }
}, true);


// Run detectors
setTimeout(() => {
    detectLoginForm();
    detectFormMismatch();
    detectHiddenForms();
    detectIframes();
}, 3000);