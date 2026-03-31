// ===== STATE =====
let userAllowed = false;
let warningInterval = null;


// ===== MAIN LISTENER =====
chrome.runtime.onMessage.addListener((message) => {

    if (message.type !== "SHOW_RESULT") return;

    if (userAllowed) return;

    if (message.risk === "High") {
        showBlockingPage(message.verdict);
    }

    if (message.risk === "Medium") {
        showWarningBanner("⚠ Suspicious site detected");
    }
});


// ===== UI FUNCTIONS =====

// 🚨 FULL BLOCK PAGE
function showBlockingPage(verdict) {

    if (document.getElementById("specter-overlay")) return;

    const overlay = document.createElement("div");
    overlay.id = "specter-overlay";

    overlay.innerHTML = `
        <div style="text-align:center; max-width:500px;">
            <h1 style="font-size:26px;">⚠ Dangerous Website</h1>

            <p style="margin:15px 0;">
                This site may attempt to steal your data.
            </p>

            <p style="opacity:0.7;">${verdict}</p>

            <div style="margin-top:20px;">
                <button id="leave-site">Leave</button>
                <button id="proceed-site">Proceed Anyway</button>
            </div>
        </div>
    `;

    overlay.style = `
        position:fixed;
        top:0; left:0;
        width:100%; height:100%;
        background:#111;
        color:white;
        z-index:999999;
        display:flex;
        align-items:center;
        justify-content:center;
    `;

    document.body.appendChild(overlay);

    // ❌ CLOSE TAB
    document.getElementById("leave-site").onclick = () => {
        chrome.runtime.sendMessage({ type: "CLOSE_TAB" });
    };

    // ⚠ PROCEED
    document.getElementById("proceed-site").onclick = () => {
        userAllowed = true;
        overlay.remove();

        startPersistentWarning();
    };
}


// ⚠ BANNER
function showWarningBanner(text) {
    if (document.getElementById("specter-banner")) return;

    const box = document.createElement("div");
    box.id = "specter-banner";
    box.innerText = text;

    box.style = `
        position:fixed;
        bottom:20px;
        right:20px;
        background:#f39c12;
        color:white;
        padding:12px 16px;
        border-radius:8px;
        z-index:999999;
        font-size:14px;
    `;

    document.body.appendChild(box);

    setTimeout(() => box.remove(), 5000);
}


// 🔁 REPEATED WARNING (clean, not alert spam)
function startPersistentWarning() {

    if (warningInterval) return;

    warningInterval = setInterval(() => {
        showWarningBanner("⚠ You are browsing a dangerous site");
    }, 15000); // every 15 sec
}


// ===== BASIC DETECTION =====

// LOGIN FORM
function detectLoginForm() {
    const forms = document.querySelectorAll("form");

    forms.forEach(form => {
        const hasPassword = form.querySelector("input[type='password']");
        const hasEmail = form.querySelector("input[type='email'], input[type='text']");

        if (hasPassword && hasEmail) {
            chrome.runtime.sendMessage({
                type: "LOGIN_FORM_DETECTED",
                url: location.href
            });
        }
    });
}


// FORM SUBMIT
function monitorFormSubmit() {
    document.addEventListener("submit", (e) => {

        const form = e.target;

        const password = form.querySelector("input[type='password']");
        const email = form.querySelector("input[type='email'], input[type='text']");

        if (password && email) {
            chrome.runtime.sendMessage({
                type: "CREDENTIAL_SUBMIT",
                url: location.href
            });
        }

    }, true);
}


// ===== ADVANCED DETECTION =====

// DOMAIN MISMATCH
function detectFormActionMismatch() {
    document.querySelectorAll("form").forEach(form => {

        const action = form.getAttribute("action");
        if (!action) return;

        try {
            const formURL = new URL(action, location.href);

            if (formURL.hostname !== location.hostname) {
                chrome.runtime.sendMessage({
                    type: "DOMAIN_MISMATCH",
                    url: location.href
                });
            }
        } catch {}
    });
}


// HIDDEN FORM
function detectHiddenForms() {
    document.querySelectorAll("input[type='password']").forEach(input => {

        const style = window.getComputedStyle(input);

        if (
            style.display === "none" ||
            style.visibility === "hidden" ||
            style.opacity === "0"
        ) {
            chrome.runtime.sendMessage({
                type: "HIDDEN_FORM",
                url: location.href
            });
        }
    });
}


// IFRAME
function detectSuspiciousIframes() {
    document.querySelectorAll("iframe").forEach(frame => {

        try {
            const src = frame.src;
            if (!src) return;

            const domain = new URL(src).hostname;

            if (domain !== location.hostname) {
                chrome.runtime.sendMessage({
                    type: "SUSPICIOUS_IFRAME",
                    url: location.href
                });
            }
        } catch {}
    });
}


// ===== RUN DETECTORS =====
setTimeout(() => {
    detectLoginForm();
    detectFormActionMismatch();
    detectHiddenForms();
    detectSuspiciousIframes();
}, 2000);

monitorFormSubmit();