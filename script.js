/**
 * ╔══════════════════════════════════════════════════════╗
 * ║  CYBERGUARD — script.js                             ║
 * ║  Gère : scan flow, animation terminal, dashboard    ║
 * ╚══════════════════════════════════════════════════════╝
 *
 * Responsabilités :
 *  - startScan()      : valide l'URL, appelle /api/scan, anime le terminal
 *  - renderDashboard(): hydrate la page dashboard avec les données reçues
 *  - downloadPDF()    : déclenche le téléchargement via /api/report/<id>
 *  - Helpers          : formatScore, getGradeColor, addTermLine...
 */

"use strict";

// ────────────────────────────────────────────────────────
// CONSTANTES
// ────────────────────────────────────────────────────────

const API_SCAN    = "/api/scan";
const API_REPORT  = "/api/report/";

// Séquence du terminal — donne l'impression d'une vraie analyse
const TERMINAL_SEQUENCE = [
    { text: "$ init scan protocol...",            delay: 0   },
    { text: "$ resolving hostname...",            delay: 400 },
    { text: "$ checking HTTPS endpoint...",       delay: 800 },
    { text: "$ opening TLS handshake on :443...", delay: 1300 },
    { text: "$ parsing certificate chain...",     delay: 1700 },
    { text: "$ fetching HTTP response headers...",delay: 2200 },
    { text: "$ running header audit (6 checks)...",delay: 2700},
    { text: "$ computing security score...",      delay: 3200 },
    { text: "$ generating AI recommendations...", delay: 3700 },
    { text: "$ building PDF report...",           delay: 4200 },
];


// ────────────────────────────────────────────────────────
// INDEX PAGE — Logique de scan
// ────────────────────────────────────────────────────────

/**
 * Lance le scan depuis la page d'accueil.
 * Valide l'input, anime le terminal, appelle l'API, redirige vers dashboard.
 */
async function startScan() {
    const input  = document.getElementById("urlInput");
    const btn    = document.getElementById("scanBtn");
    const errDiv = document.getElementById("scanError");
    const loading = document.getElementById("scanLoading");
    const form   = document.getElementById("scanForm");

    if (!input) return;

    const rawUrl = input.value.trim();
    if (!rawUrl) {
        showInputError(errDiv, "Veuillez entrer un domaine ou une URL.");
        return;
    }

    // Masque erreur précédente
    errDiv.style.display = "none";

    // UI: état chargement
    btn.disabled = true;
    btn.querySelector(".btn-text").textContent = "Analyse...";
    form.style.opacity = "0.5";
    loading.style.display = "block";

    // Lance l'animation terminal
    const termTimers = animateTerminal();

    try {
        const result = await callScanAPI(rawUrl);

        // Stoppe les timers de terminal restants
        termTimers.forEach(clearTimeout);

        // Ligne finale dans le terminal
        addTermLine("$ scan complete — redirecting...", "ok");

        // Sauvegarde dans sessionStorage pour la page dashboard
        sessionStorage.setItem("cyberguard_result", JSON.stringify(result));

        // Redirection courte
        setTimeout(() => { window.location.href = "/dashboard"; }, 500);

    } catch (err) {
        termTimers.forEach(clearTimeout);
        loading.style.display = "none";
        form.style.opacity   = "1";
        btn.disabled = false;
        btn.querySelector(".btn-text").textContent = "Analyser";
        showInputError(errDiv, err.message || "Erreur lors du scan. Vérifiez l'URL et réessayez.");
    }
}

/**
 * Appelle POST /api/scan avec l'URL fournie.
 * Retourne le JSON résultat ou throw une Error.
 */
async function callScanAPI(url) {
    const resp = await fetch(API_SCAN, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
    });

    const data = await resp.json();

    if (!resp.ok || data.error) {
        throw new Error(data.error || `Erreur serveur (${resp.status})`);
    }
    return data;
}

/**
 * Anime les lignes du terminal selon TERMINAL_SEQUENCE.
 * Retourne un tableau de setTimeout IDs pour pouvoir les annuler.
 */
function animateTerminal() {
    const timers = [];
    TERMINAL_SEQUENCE.forEach(({ text, delay }) => {
        const tid = setTimeout(() => addTermLine(text), delay);
        timers.push(tid);
    });
    return timers;
}

/**
 * Ajoute une ligne au terminal.
 */
function addTermLine(text, cls = "") {
    const body = document.getElementById("terminalBody");
    if (!body) return;

    const line = document.createElement("div");
    line.className = `t-line ${cls}`;
    line.textContent = text;
    body.appendChild(line);

    // Auto-scroll
    body.scrollTop = body.scrollHeight;
}

/**
 * Affiche un message d'erreur dans le formulaire.
 */
function showInputError(el, msg) {
    if (!el) return;
    el.textContent = msg;
    el.style.display = "block";
}

/**
 * Focus sur l'input depuis le bouton pricing.
 */
function focusInput() {
    const input = document.getElementById("urlInput");
    if (input) {
        input.focus();
        window.scrollTo({ top: 0, behavior: "smooth" });
    }
}

// Touche Entrée sur l'input
document.addEventListener("DOMContentLoaded", () => {
    const input = document.getElementById("urlInput");
    if (input) {
        input.addEventListener("keydown", (e) => {
            if (e.key === "Enter") startScan();
        });
    }

    // Page dashboard : auto-render si données présentes
    if (document.getElementById("dashboardContent")) {
        initDashboard();
    }
});


// ────────────────────────────────────────────────────────
// DASHBOARD PAGE — Rendu des résultats
// ────────────────────────────────────────────────────────

/**
 * Initialise le dashboard au chargement.
 * Lit les données depuis sessionStorage.
 */
function initDashboard() {
    const raw = sessionStorage.getItem("cyberguard_result");

    if (!raw) {
        showDBError("Aucun résultat trouvé. Lancez un scan depuis la page d'accueil.");
        return;
    }

    try {
        const data = JSON.parse(raw);
        renderDashboard(data);
    } catch {
        showDBError("Données corrompues. Veuillez relancer un scan.");
    }
}

/**
 * Hydrate toute la page dashboard avec les données du scan.
 */
function renderDashboard(d) {
    // Masque loading, affiche contenu
    document.getElementById("dbLoading").style.display  = "none";
    document.getElementById("dashboardContent").style.display = "block";

    // ── META ──
    setText("reportUrl", d.url);
    setText("reportDate", `Analysé le ${d.scan_date} · Durée : ${d.scan_duration_ms}ms`);
    setText("scanDuration", `ID scan : ${d.scan_id}`);

    // ── SCORE ──
    renderScore(d);

    // ── RISK ──
    const riskEl = document.getElementById("riskLevel");
    if (riskEl) {
        riskEl.textContent = d.risk_level;
        riskEl.style.color = getRiskColor(d.risk_level);
    }

    // ── CHECKS ──
    renderChecks(d);

    // ── RECOMMANDATIONS ──
    renderRecommendations(d.recommendations);

    // ── POINTS FORTS ──
    renderStrengths(d.strengths);

    // ── PDF BUTTON ──
    const dlBtn = document.getElementById("downloadBtn");
    if (dlBtn) {
        if (!d.pdf_available) {
            dlBtn.textContent = "⬇ PDF non disponible";
            dlBtn.disabled = true;
        }
        dlBtn.dataset.scanId = d.scan_id;
    }

    // Titre de l'onglet
    document.title = `Score ${d.score}/100 — ${d.domain} — CyberGuard`;
}

/**
 * Anime et affiche le score + anneau SVG.
 */
function renderScore(d) {
    const scoreEl = document.getElementById("scoreNumber");
    const gradeEl = document.getElementById("scoreGrade");
    const labelEl = document.getElementById("scoreLabel");
    const ring    = document.getElementById("ringFill");

    const color = d.score_color || getScoreColor(d.score);

    // Anime le compteur de score
    animateCounter(scoreEl, 0, d.score, 1200, (v) => {
        if (scoreEl) scoreEl.textContent = v;
    });

    if (gradeEl) { gradeEl.textContent = d.score_grade; gradeEl.style.color = color; }
    if (labelEl) { labelEl.textContent = d.score_label; }

    // Anime l'anneau SVG
    if (ring) {
        ring.style.stroke = color;
        const circumference = 2 * Math.PI * 52; // r=52
        const offset = circumference - (d.score / 100) * circumference;
        setTimeout(() => { ring.style.strokeDashoffset = offset; }, 100);
    }
}

/**
 * Affiche les cartes de vérification (HTTPS, SSL, headers).
 */
function renderChecks(d) {
    // HTTPS
    setCheck("checkHttps", "valHttps", "statusHttps",
        d.is_https,
        d.is_https ? "Connexion chiffrée" : "Non chiffré — HTTP seulement",
        "none"
    );

    // SSL Valide
    setCheck("checkSsl", "valSsl", "statusSsl",
        d.ssl_valid,
        d.ssl_valid ? `Valide · Émis par ${d.ssl_issuer}` : "Certificat invalide ou absent",
        "none"
    );

    // Expiration SSL
    const expiryOk = d.ssl_valid && d.ssl_expiry_days > 30;
    const expiryWarn = d.ssl_valid && d.ssl_expiry_days <= 30 && d.ssl_expiry_days > 0;
    const expiryCard = document.getElementById("checkExpiry");
    setText("valExpiry", d.ssl_valid ? `${d.ssl_expiry_date} (${d.ssl_expiry_days}j restants)` : "N/A");
    setText("statusExpiry", expiryOk ? "✓" : expiryWarn ? "⚠" : "✗");
    if (expiryCard) expiryCard.className = `check-card ${expiryOk ? "is-ok" : expiryWarn ? "is-warn" : "is-fail"}`;

    // Headers dynamiques
    const container = document.getElementById("headerCards");
    if (container && d.headers_found) {
        container.innerHTML = Object.entries(d.headers_found).map(([header, present]) => `
            <div class="check-card ${present ? 'is-ok' : 'is-fail'} animate-in">
                <div class="check-icon-wrap"><span class="check-icon">${present ? "🛡️" : "⚠️"}</span></div>
                <div class="check-body">
                    <div class="check-name">${header}</div>
                    <div class="check-value">${present ? "Configuré" : "Manquant"}</div>
                </div>
                <div class="check-status">${present ? "✓" : "✗"}</div>
            </div>
        `).join("");
    }
}

/**
 * Affiche les 3 recommandations IA.
 */
function renderRecommendations(recos) {
    const container = document.getElementById("recoList");
    if (!container || !recos) return;

    if (recos.length === 0) {
        container.innerHTML = `<div class="reco-card priority-low">
            <div class="reco-title">✅ Aucune recommandation critique</div>
            <div class="reco-detail">Votre site présente une bonne posture de sécurité.</div>
        </div>`;
        return;
    }

    const priorityMap = {
        "Critique": "priority-critical",
        "Urgent":   "priority-high",
        "Important":"priority-medium",
        "default":  "priority-low"
    };

    container.innerHTML = recos.map((r, i) => {
        const cls = priorityMap[r.category] || priorityMap.default;
        const catCls = "cat-" + r.category.replace(/ /g, "\\ ");
        return `
        <div class="reco-card ${cls} animate-in" style="animation-delay:${i * 80}ms">
            <div class="reco-header">
                <div class="reco-title">${r.icon} ${r.title}</div>
                <span class="reco-category ${catCls}">${r.category}</span>
            </div>
            <div class="reco-detail">${r.detail}</div>
            <div class="reco-action">${r.action}</div>
            <div class="reco-footer">
                <span class="reco-meta">Effort : <span>${r.effort}</span></span>
                <span class="reco-meta">Impact : <span>${r.impact}</span></span>
            </div>
        </div>`;
    }).join("");
}

/**
 * Affiche les points forts détectés.
 */
function renderStrengths(strengths) {
    const section = document.getElementById("strengthsSection");
    const list    = document.getElementById("strengthsList");
    if (!section || !list || !strengths || strengths.length === 0) return;

    section.style.display = "block";
    list.innerHTML = strengths.map(s => `
        <div class="strength-item">${s}</div>
    `).join("");
}


// ────────────────────────────────────────────────────────
// TÉLÉCHARGEMENT PDF
// ────────────────────────────────────────────────────────

/**
 * Déclenche le téléchargement du rapport PDF.
 */
function downloadPDF() {
    const btn = document.getElementById("downloadBtn");
    if (!btn) return;
    const scanId = btn.dataset.scanId;
    if (!scanId) return;

    // Ouvre le PDF dans un nouvel onglet (déclenche le téléchargement)
    window.open(`${API_REPORT}${scanId}`, "_blank");
}


// ────────────────────────────────────────────────────────
// NOUVEAU SCAN (depuis dashboard)
// ────────────────────────────────────────────────────────

async function rescan() {
    const input = document.getElementById("rescanInput");
    if (!input || !input.value.trim()) return;

    const rawUrl = input.value.trim();

    // Affiche loading
    document.getElementById("dashboardContent").style.display = "none";
    document.getElementById("dbLoading").style.display = "flex";

    try {
        const result = await callScanAPI(rawUrl);
        sessionStorage.setItem("cyberguard_result", JSON.stringify(result));
        renderDashboard(result);
    } catch (err) {
        showDBError(err.message);
    }
}

// Touche Entrée sur rescan
document.addEventListener("DOMContentLoaded", () => {
    const ri = document.getElementById("rescanInput");
    if (ri) ri.addEventListener("keydown", (e) => { if (e.key === "Enter") rescan(); });
});


// ────────────────────────────────────────────────────────
// HELPERS
// ────────────────────────────────────────────────────────

function showDBError(msg) {
    document.getElementById("dbLoading").style.display  = "none";
    document.getElementById("dashboardContent").style.display = "none";
    const errDiv = document.getElementById("dbError");
    const errMsg = document.getElementById("dbErrorMsg");
    if (errDiv) errDiv.style.display = "flex";
    if (errMsg) errMsg.textContent = msg;
}

function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
}

function setCheck(cardId, valId, statusId, ok, value, warn) {
    const card   = document.getElementById(cardId);
    const valEl  = document.getElementById(valId);
    const statEl = document.getElementById(statusId);
    if (card)   card.className   = `check-card ${ok ? "is-ok" : "is-fail"}`;
    if (valEl)  valEl.textContent  = value;
    if (statEl) statEl.textContent = ok ? "✓" : "✗";
}

function getScoreColor(score) {
    if (score >= 85) return "#22c55e";
    if (score >= 70) return "#84cc16";
    if (score >= 50) return "#f59e0b";
    if (score >= 30) return "#f97316";
    return "#ef4444";
}

function getRiskColor(risk) {
    const map = {
        "Critique": "#ef4444", "Élevé": "#f97316",
        "Moyen": "#f59e0b",    "Faible": "#84cc16",
        "Minimal": "#22c55e"
    };
    return map[risk] || "#94a3b8";
}

/**
 * Anime un compteur de 0 à `to` en `duration` ms.
 */
function animateCounter(el, from, to, duration, onTick) {
    if (!el) return;
    const start = performance.now();
    function tick(now) {
        const progress = Math.min((now - start) / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        onTick(Math.round(from + (to - from) * eased));
        if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
}
