// ===== CONFIG =====
const TRUSTED_DOMAINS = [
    "google.com",
    "facebook.com",
    "microsoft.com",
    "apple.com",
    "paypal.com",
    "stripe.com"
];

// ===== STATE =====
let currentRisk = "SAFE";
const originalActions = new WeakMap();

// ===== UTIL =====
function isExternal(url) {
    try {
        const u = new URL(url, location.origin);
        return u.hostname !== location.hostname;
    } catch {
        return false;
    }
}

function isTrusted(hostname) {
    return TRUSTED_DOMAINS.some(d =>
        hostname === d || hostname.endsWith("." + d)
    );
}

// ===== STORE ORIGINAL FORM STATE =====
function trackForms() {
    document.querySelectorAll("form").forEach(form => {
        if (!originalActions.has(form)) {
            originalActions.set(form, form.action || location.href);
        }
    });
}

// Initial tracking
trackForms();

// ===== OBSERVE DOM CHANGES =====
const observer = new MutationObserver(() => {
    trackForms();
});
observer.observe(document.documentElement, {
    childList: true,
    subtree: true
});

// ===== MESSAGE LISTENER =====
chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "AUTOSCAN_RESULT") {

        if (msg.isMalicious) currentRisk = "DANGER";
        else if (msg.isSuspicious) currentRisk = "WARNING";
        else if (msg.isLowTrust) currentRisk = "LOW";
        else currentRisk = "SAFE";

        showToast(msg.verdict, currentRisk);

        if (currentRisk === "DANGER" || currentRisk === "WARNING") {
            lockInputs(currentRisk);
        }
    }
});

// ===== LOCK INPUTS (UX only) =====
function lockInputs(level) {
    const inputs = document.querySelectorAll("input, textarea");

    inputs.forEach(input => {
        input.dataset.specterLocked = "true";
        input.style.filter = "blur(6px)";
        input.disabled = true;
    });

    if (!document.getElementById("specter-unlock-btn")) {
        const btn = document.createElement("button");
        btn.id = "specter-unlock-btn";
        btn.innerText =
            level === "DANGER"
                ? "Malicious Site — Unlock at Your Risk"
                : "Suspicious Site — Click to Unlock";

        btn.style = `
            position:fixed;
            bottom:30px;
            right:30px;
            z-index:999999;
            padding:12px 18px;
            border-radius:30px;
            background:#1a2a3a;
            color:white;
            font-weight:bold;
            cursor:pointer;
            border:2px solid #3498db;
        `;

        btn.onclick = () => {
            document.querySelectorAll("[data-specter-locked]").forEach(i => {
                i.style.filter = "none";
                i.disabled = false;
                delete i.dataset.specterLocked;
            });
            btn.remove();
        };

        document.body.appendChild(btn);
    }
}

// ===== TOAST =====
let currentToast = null;

function showToast(text, level) {
    if (currentToast) currentToast.remove();

    const colors = {
        SAFE: "#27ae60",
        LOW: "#f1c40f",
        WARNING: "#e67e22",
        DANGER: "#c0392b"
    };

    const toast = document.createElement("div");
    currentToast = toast;

    toast.style = `
        position:fixed;
        top:20px;
        right:20px;
        z-index:999999;
        background:${colors[level]};
        color:white;
        padding:14px 22px;
        border-radius:8px;
        font-family:sans-serif;
        font-weight:bold;
    `;

    toast.innerText = text;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => {
            toast.remove();
            if (currentToast === toast) currentToast = null;
        }, 400);
    }, 3500);
}

// ===== FORM HIJACK PROTECTION =====
document.addEventListener("submit", (e) => {
    const form = e.target;

    if (!form || form.tagName !== "FORM") return;

    const original = originalActions.get(form) || location.href;
    const current = form.action || location.href;

    try {
        const origURL = new URL(original, location.origin);
        const currURL = new URL(current, location.origin);

        // Check if changed
        if (origURL.hostname !== currURL.hostname) {

            // Allow trusted
            if (!isTrusted(currURL.hostname)) {
                e.preventDefault();

                alert(
                    `SpecterScan: Form Hijack Blocked\n\nOriginal: ${origURL.hostname}\nNow sending to: ${currURL.hostname}`
                );

                return;
            }
        }

    } catch {
        e.preventDefault();
    }

}, true);

// ===== FETCH HIJACK PROTECTION =====
const originalFetch = window.fetch;

window.fetch = function (...args) {
    try {
        const url = typeof args[0] === "string" ? args[0] : args[0].url;
        const u = new URL(url, location.origin);

        if (u.hostname !== location.hostname && !isTrusted(u.hostname)) {
            console.warn("Blocked fetch to:", u.hostname);
            return Promise.reject("Blocked by SpecterScan");
        }
    } catch {}

    return originalFetch.apply(this, args);
};

// ===== XHR PROTECTION =====
const originalOpen = XMLHttpRequest.prototype.open;

XMLHttpRequest.prototype.open = function (method, url, ...rest) {
    try {
        const u = new URL(url, location.origin);

        if (u.hostname !== location.hostname && !isTrusted(u.hostname)) {
            console.warn("Blocked XHR to:", u.hostname);
            throw new Error("Blocked by SpecterScan");
        }
    } catch {}

    return originalOpen.call(this, method, url, ...rest);
};