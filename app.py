"""
╔══════════════════════════════════════════════════════════╗
║         CYBERGUARD MVP — Backend Principal               ║
║  Flask API + Moteur de scan + Génération PDF             ║
╚══════════════════════════════════════════════════════════╝

Fichier : app.py
Rôle    : Point d'entrée principal. Lance le serveur Flask,
          expose les routes API, orchestre les modules de
          scan, de scoring et de génération de rapport PDF.

Installation :
    pip install flask requests reportlab

Lancement :
    python app.py
    → http://localhost:5000
"""

import ssl
import socket
import json
import os
import datetime
import hashlib
import requests
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template, send_file, abort

# PDF (ReportLab)
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT

# ────────────────────────────────────────────────────────
# CONFIGURATION
# ────────────────────────────────────────────────────────

app = Flask(__name__)
app.config["REPORTS_DIR"] = os.path.join(os.path.dirname(__file__), "reports")
os.makedirs(app.config["REPORTS_DIR"], exist_ok=True)

# ────────────────────────────────────────────────────────
# MODÈLE DE DONNÉES
# ────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """Contient tous les résultats bruts d'un scan de sécurité."""
    url: str
    domain: str = ""
    scan_id: str = ""
    scan_date: str = ""

    # Checks
    is_https: bool = False
    ssl_valid: bool = False
    ssl_expiry_days: int = 0
    ssl_expiry_date: str = "N/A"
    ssl_issuer: str = "N/A"

    headers_found: dict = field(default_factory=dict)
    missing_headers: list = field(default_factory=list)

    # Score
    score: int = 0
    score_grade: str = "F"
    score_label: str = ""
    score_color: str = "#ef4444"

    # IA
    recommendations: list = field(default_factory=list)
    strengths: list = field(default_factory=list)
    risk_level: str = "Élevé"

    # Meta
    scan_duration_ms: int = 0
    error: Optional[str] = None


# ────────────────────────────────────────────────────────
# MODULE 1 — VÉRIFICATIONS DE SÉCURITÉ
# ────────────────────────────────────────────────────────

# Headers de sécurité avec poids, description et correction
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "weight": 15, "category": "Transport",
        "desc": "Force les connexions HTTPS — protège contre les attaques MITM",
        "fix": "Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "risk": "Vos utilisateurs peuvent être redirigés vers une version HTTP non sécurisée."
    },
    "Content-Security-Policy": {
        "weight": 15, "category": "Injection",
        "desc": "Bloque les attaques XSS et injections de contenu malveillant",
        "fix": "Définir une CSP stricte : Content-Security-Policy: default-src 'self'",
        "risk": "Votre site est vulnérable aux attaques Cross-Site Scripting (XSS)."
    },
    "X-Frame-Options": {
        "weight": 10, "category": "Clickjacking",
        "desc": "Empêche votre site d'être embarqué dans une iframe malveillante",
        "fix": "Ajouter : X-Frame-Options: SAMEORIGIN",
        "risk": "Des attaquants peuvent superposer votre site pour voler des clics."
    },
    "X-Content-Type-Options": {
        "weight": 10, "category": "MIME",
        "desc": "Empêche les navigateurs d'interpréter des fichiers comme du code",
        "fix": "Ajouter : X-Content-Type-Options: nosniff",
        "risk": "Des fichiers uploadés pourraient être exécutés comme du JavaScript."
    },
    "Referrer-Policy": {
        "weight": 5, "category": "Vie privée",
        "desc": "Contrôle les informations envoyées lors de navigations",
        "fix": "Ajouter : Referrer-Policy: strict-origin-when-cross-origin",
        "risk": "Des données internes peuvent fuiter vers des sites tiers."
    },
    "Permissions-Policy": {
        "weight": 5, "category": "APIs",
        "desc": "Limite l'accès aux APIs sensibles (caméra, micro, géoloc...)",
        "fix": "Ajouter : Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "risk": "Des scripts tiers peuvent accéder aux périphériques de vos utilisateurs."
    },
}


def normalize_url(url: str) -> tuple[str, str]:
    """Normalise l'URL et extrait le domaine."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split("/")[0]
    return url, domain


def check_https(url: str) -> bool:
    """Retourne True si l'URL utilise HTTPS."""
    return urlparse(url).scheme == "https"


def check_ssl(domain: str) -> tuple[bool, int, str, str]:
    """
    Vérifie le certificat SSL via connexion directe.
    Retourne : (valide, jours_restants, date_expiration, émetteur)
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        expire = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days = (expire - datetime.datetime.utcnow()).days
        date_str = expire.strftime("%d/%m/%Y")

        # Extraire l'émetteur
        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        issuer = issuer_dict.get("organizationName", issuer_dict.get("commonName", "Inconnu"))

        return True, max(days, 0), date_str, issuer

    except ssl.SSLCertVerificationError:
        return False, 0, "Certificat invalide", "N/A"
    except (ssl.SSLError, socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
        return False, 0, "Inaccessible", "N/A"
    except Exception:
        return False, 0, "Erreur interne", "N/A"


def check_headers(url: str) -> dict[str, bool]:
    """Vérifie la présence des headers de sécurité HTTP."""
    status = {h: False for h in SECURITY_HEADERS}
    try:
        r = requests.get(
            url, timeout=8, allow_redirects=True,
            headers={"User-Agent": "CyberGuard-Scanner/1.0 (+https://cyberguard.app)"},
            verify=False  # On veut tester même les certs invalides
        )
        lowered = {k.lower(): v for k, v in r.headers.items()}
        for header in SECURITY_HEADERS:
            status[header] = header.lower() in lowered
    except Exception:
        pass
    return status


# ────────────────────────────────────────────────────────
# MODULE 2 — MOTEUR DE SCORING
# ────────────────────────────────────────────────────────

def calculate_score(result: ScanResult) -> tuple[int, str, str, str]:
    """
    Calcule le score de sécurité sur 100.
    Retourne : (score, grade, label, couleur_hex)

    Grille :
      HTTPS           → 20 pts
      SSL valide      → 15 pts
      SSL > 30 jours  → 10 pts
      6 headers       → 55 pts (pondérés)
    """
    score = 0
    if result.is_https:
        score += 20
    if result.ssl_valid:
        score += 15
    if result.ssl_valid and result.ssl_expiry_days > 30:
        score += 10

    for header, present in result.headers_found.items():
        if present:
            score += SECURITY_HEADERS[header]["weight"]

    score = min(score, 100)

    if score >= 85:
        return score, "A", "Excellent", "#22c55e"
    elif score >= 70:
        return score, "B", "Bien sécurisé", "#84cc16"
    elif score >= 50:
        return score, "C", "Sécurité moyenne", "#f59e0b"
    elif score >= 30:
        return score, "D", "Sécurité faible", "#f97316"
    else:
        return score, "F", "Critique — Action urgente", "#ef4444"


# ────────────────────────────────────────────────────────
# MODULE 3 — MOTEUR IA DE RECOMMANDATIONS
# ────────────────────────────────────────────────────────

def generate_ai_recommendations(result: ScanResult) -> tuple[list, list, str]:
    """
    Moteur de recommandations intelligent basé sur le profil de risque.
    Simule un analyste sécurité senior avec priorisation contextuelle.
    Retourne : (recommandations, points_forts, niveau_risque)
    """
    issues = []
    strengths = []

    # ── ANALYSE HTTPS ──
    if not result.is_https:
        issues.append({
            "priority": 100, "icon": "🔴", "category": "Critique",
            "title": "Site non chiffré (HTTP)",
            "detail": "Toutes les données transitent en clair : mots de passe, formulaires, cookies. Un attaquant sur le même réseau peut tout intercepter.",
            "action": "Activer HTTPS via Let's Encrypt (gratuit). Contactez votre hébergeur ou installez Certbot.",
            "effort": "Faible", "impact": "Critique"
        })
    else:
        strengths.append("✅ Connexion chiffrée HTTPS activée")

    # ── ANALYSE SSL ──
    if not result.ssl_valid:
        issues.append({
            "priority": 95, "icon": "🔴", "category": "Critique",
            "title": "Certificat SSL invalide ou expiré",
            "detail": "Les navigateurs affichent une alerte 'SITE NON SÉCURISÉ' à tous vos visiteurs. Cela détruit la confiance et le référencement SEO.",
            "action": "Renouveler immédiatement le certificat SSL. Vérifier la date d'expiration dans votre hébergeur.",
            "effort": "Faible", "impact": "Critique"
        })
    elif result.ssl_expiry_days <= 14:
        issues.append({
            "priority": 90, "icon": "🔴", "category": "Urgent",
            "title": f"Certificat SSL expire dans {result.ssl_expiry_days} jours",
            "detail": "L'expiration imminente va rendre votre site inaccessible et déclencher des alertes de sécurité chez vos clients.",
            "action": "Renouveler le certificat SSL aujourd'hui. Configurez le renouvellement automatique.",
            "effort": "Faible", "impact": "Élevé"
        })
    elif result.ssl_expiry_days <= 30:
        issues.append({
            "priority": 75, "icon": "🟠", "category": "Important",
            "title": f"Certificat SSL expire dans {result.ssl_expiry_days} jours",
            "detail": "Le renouvellement doit être planifié cette semaine pour éviter toute interruption.",
            "action": "Planifier le renouvellement SSL. Activer le renouvellement automatique (recommandé).",
            "effort": "Faible", "impact": "Moyen"
        })
    else:
        strengths.append(f"✅ Certificat SSL valide jusqu'au {result.ssl_expiry_date} ({result.ssl_expiry_days}j)")

    # ── ANALYSE HEADERS ──
    missing = [(h, SECURITY_HEADERS[h]) for h, v in result.headers_found.items() if not v]
    missing.sort(key=lambda x: x[1]["weight"], reverse=True)

    for header, info in missing:
        issues.append({
            "priority": info["weight"] * 4,
            "icon": "🟡" if info["weight"] >= 10 else "⚪",
            "category": info["category"],
            "title": f"Header manquant : {header}",
            "detail": info["risk"],
            "action": info["fix"],
            "effort": "Faible", "impact": "Moyen" if info["weight"] >= 10 else "Faible"
        })

    for header, present in result.headers_found.items():
        if present:
            strengths.append(f"✅ Header {header} configuré")

    # ── PRIORISATION ──
    issues.sort(key=lambda x: x["priority"], reverse=True)
    top3 = issues[:3]

    # ── NIVEAU DE RISQUE GLOBAL ──
    critical = sum(1 for i in issues if i["category"] in ["Critique", "Urgent"])
    if critical >= 2:
        risk = "Critique"
    elif critical == 1 or len(issues) >= 4:
        risk = "Élevé"
    elif len(issues) >= 2:
        risk = "Moyen"
    elif len(issues) == 1:
        risk = "Faible"
    else:
        risk = "Minimal"

    return top3, strengths, risk


# ────────────────────────────────────────────────────────
# MODULE 4 — GÉNÉRATION PDF (ReportLab)
# ────────────────────────────────────────────────────────

def generate_pdf_report(result: ScanResult) -> str:
    """
    Génère un rapport PDF professionnel avec ReportLab.
    Retourne le chemin du fichier PDF généré.
    """
    filename = f"rapport_{result.scan_id}.pdf"
    filepath = os.path.join(app.config["REPORTS_DIR"], filename)

    doc = SimpleDocTemplate(
        filepath, pagesize=A4,
        rightMargin=20*mm, leftMargin=20*mm,
        topMargin=20*mm, bottomMargin=20*mm
    )

    # ── STYLES ──
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CustomTitle", fontSize=22, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#0f172a"), spaceAfter=4, alignment=TA_CENTER
    )
    subtitle_style = ParagraphStyle(
        "Subtitle", fontSize=11, fontName="Helvetica",
        textColor=colors.HexColor("#64748b"), spaceAfter=2, alignment=TA_CENTER
    )
    section_style = ParagraphStyle(
        "Section", fontSize=13, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#0f172a"), spaceBefore=12, spaceAfter=6
    )
    body_style = ParagraphStyle(
        "Body", fontSize=9, fontName="Helvetica",
        textColor=colors.HexColor("#334155"), spaceAfter=4, leading=14
    )
    code_style = ParagraphStyle(
        "Code", fontSize=8, fontName="Courier",
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f1f5f9"),
        leftIndent=8, rightIndent=8, spaceBefore=2, spaceAfter=6, leading=12
    )

    story = []

    # ── HEADER ──
    story.append(Paragraph("🛡️ CYBERGUARD", title_style))
    story.append(Paragraph("Rapport de Sécurité Web", subtitle_style))
    story.append(Spacer(1, 4*mm))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0ea5e9")))
    story.append(Spacer(1, 4*mm))

    # Infos générales
    info_data = [
        ["URL analysée", result.url],
        ["Domaine", result.domain],
        ["Date d'analyse", result.scan_date],
        ["ID du rapport", result.scan_id.upper()],
        ["Niveau de risque", result.risk_level],
    ]
    info_table = Table(info_data, colWidths=[50*mm, 120*mm])
    info_table.setStyle(TableStyle([
        ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,-1), 9),
        ("TEXTCOLOR", (0,0), (0,-1), colors.HexColor("#0ea5e9")),
        ("TEXTCOLOR", (1,0), (1,-1), colors.HexColor("#334155")),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.HexColor("#f8fafc"), colors.white]),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 6*mm))

    # ── SCORE ──
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
    story.append(Spacer(1, 4*mm))

    score_color_map = {"A": "#22c55e", "B": "#84cc16", "C": "#f59e0b", "D": "#f97316", "F": "#ef4444"}
    score_hex = score_color_map.get(result.score_grade, "#ef4444")

    score_data = [[
        Paragraph(f'<font size="32" color="{score_hex}"><b>{result.score}/100</b></font>', ParagraphStyle("SC", alignment=TA_CENTER)),
        Paragraph(f'<font size="20" color="{score_hex}"><b>Note : {result.score_grade}</b></font>\n{result.score_label}', ParagraphStyle("SL", alignment=TA_LEFT, leading=22))
    ]]
    score_table = Table(score_data, colWidths=[60*mm, 110*mm])
    score_table.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ("BOX", (0,0), (-1,-1), 1.5, colors.HexColor(score_hex)),
        ("TOPPADDING", (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ("LEFTPADDING", (0,0), (0,-1), 12),
        ("LEFTPADDING", (1,0), (1,-1), 12),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 6*mm))

    # ── RÉSULTATS DÉTAILLÉS ──
    story.append(Paragraph("RÉSULTATS DÉTAILLÉS", section_style))

    check_rows = [
        ["Vérification", "Résultat", "Détail"],
        ["HTTPS", "✓ Activé" if result.is_https else "✗ Absent",
         "Connexion chiffrée" if result.is_https else "Données non chiffrées"],
        ["SSL Certificat", "✓ Valide" if result.ssl_valid else "✗ Invalide",
         f"Émis par : {result.ssl_issuer}"],
        ["Expiration SSL", f"{result.ssl_expiry_days} jours", result.ssl_expiry_date],
    ]
    for header, info in SECURITY_HEADERS.items():
        present = result.headers_found.get(header, False)
        check_rows.append([
            header,
            "✓ Présent" if present else "✗ Manquant",
            info["category"]
        ])

    check_table = Table(check_rows, colWidths=[65*mm, 30*mm, 75*mm])
    check_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,-1), 8),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#f8fafc"), colors.white]),
        ("ALIGN", (1,1), (1,-1), "CENTER"),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("GRID", (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
    ]))
    # Colorier les cellules résultat
    for i, row in enumerate(check_rows[1:], 1):
        if "✓" in str(row[1]):
            check_table.setStyle(TableStyle([("TEXTCOLOR", (1,i), (1,i), colors.HexColor("#22c55e"))]))
        elif "✗" in str(row[1]):
            check_table.setStyle(TableStyle([("TEXTCOLOR", (1,i), (1,i), colors.HexColor("#ef4444"))]))

    story.append(check_table)
    story.append(Spacer(1, 6*mm))

    # ── RECOMMANDATIONS ──
    story.append(Paragraph("TOP 3 RECOMMANDATIONS PRIORITAIRES", section_style))
    for i, reco in enumerate(result.recommendations, 1):
        story.append(Paragraph(
            f'<b>{i}. {reco["icon"]} [{reco["category"]}] {reco["title"]}</b>',
            ParagraphStyle("RecoTitle", fontSize=10, fontName="Helvetica-Bold",
                           textColor=colors.HexColor("#0f172a"), spaceBefore=6, spaceAfter=2)
        ))
        story.append(Paragraph(f'<i>{reco["detail"]}</i>', body_style))
        story.append(Paragraph(f'→ Action : {reco["action"]}', code_style))

    # ── POINTS FORTS ──
    if result.strengths:
        story.append(Spacer(1, 4*mm))
        story.append(Paragraph("POINTS FORTS DÉTECTÉS", section_style))
        for strength in result.strengths:
            story.append(Paragraph(f"• {strength}", body_style))

    # ── FOOTER ──
    story.append(Spacer(1, 8*mm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph(
        "Rapport généré par CyberGuard MVP — Résultats à titre indicatif. "
        "Pour un audit complet, contactez un expert en cybersécurité certifié.",
        ParagraphStyle("Footer", fontSize=7, fontName="Helvetica",
                       textColor=colors.HexColor("#94a3b8"), alignment=TA_CENTER)
    ))

    doc.build(story)
    return filepath


# ────────────────────────────────────────────────────────
# ORCHESTRATEUR PRINCIPAL
# ────────────────────────────────────────────────────────

def run_full_scan(raw_url: str) -> ScanResult:
    """
    Lance le scan complet et retourne un ScanResult enrichi.
    C'est LE point d'entrée pour analyser une URL.
    """
    import time
    start = time.time()

    result = ScanResult(url=raw_url)
    result.scan_date = datetime.datetime.now().strftime("%d/%m/%Y à %H:%M:%S")
    result.scan_id = hashlib.md5(f"{raw_url}{result.scan_date}".encode()).hexdigest()[:10]

    # Normalisation
    result.url, result.domain = normalize_url(raw_url)

    # Checks
    result.is_https = check_https(result.url)

    if result.is_https:
        result.ssl_valid, result.ssl_expiry_days, result.ssl_expiry_date, result.ssl_issuer = check_ssl(result.domain)

    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        result.headers_found = check_headers(result.url)

    result.missing_headers = [h for h, v in result.headers_found.items() if not v]

    # Score
    result.score, result.score_grade, result.score_label, result.score_color = calculate_score(result)

    # IA
    result.recommendations, result.strengths, result.risk_level = generate_ai_recommendations(result)

    result.scan_duration_ms = int((time.time() - start) * 1000)
    return result


# ────────────────────────────────────────────────────────
# ROUTES FLASK
# ────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Page d'accueil avec formulaire de scan."""
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    """Dashboard résultats (rendu côté serveur pour SEO et partage)."""
    return render_template("dashboard.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    POST /api/scan
    Body JSON : { "url": "https://example.com" }
    Retourne  : JSON complet avec résultats + scan_id pour le PDF
    """
    data = request.get_json(silent=True)
    if not data or not data.get("url"):
        return jsonify({"error": "URL manquante ou invalide"}), 400

    url = data["url"].strip()
    if len(url) > 500:
        return jsonify({"error": "URL trop longue"}), 400

    # Validation basique anti-SSRF
    parsed = urlparse(url if url.startswith("http") else "https://" + url)
    hostname = parsed.hostname or ""
    blocked_hosts = ["localhost", "127.0.0.1", "0.0.0.0", "::1"]
    if any(hostname.startswith(b) for b in blocked_hosts) or hostname.startswith("192.168") or hostname.startswith("10."):
        return jsonify({"error": "Domaine non autorisé"}), 400

    try:
        result = run_full_scan(url)

        # Générer le PDF en arrière-plan
        try:
            generate_pdf_report(result)
            pdf_available = True
        except Exception:
            pdf_available = False

        # Sérialiser en dict (asdict gère les dataclasses)
        result_dict = asdict(result)
        result_dict["pdf_available"] = pdf_available

        return jsonify(result_dict)

    except Exception as e:
        return jsonify({"error": f"Erreur lors du scan : {str(e)}"}), 500


@app.route("/api/report/<scan_id>")
def download_report(scan_id):
    """
    GET /api/report/<scan_id>
    Télécharge le PDF du rapport identifié par son scan_id.
    """
    # Sécurité : sanitize le scan_id (alphanumérique uniquement)
    if not scan_id.isalnum() or len(scan_id) > 20:
        abort(400)

    filepath = os.path.join(app.config["REPORTS_DIR"], f"rapport_{scan_id}.pdf")
    if not os.path.exists(filepath):
        abort(404)

    return send_file(
        filepath,
        as_attachment=True,
        download_name=f"rapport_securite_{scan_id}.pdf",
        mimetype="application/pdf"
    )


@app.route("/api/health")
def health():
    """Endpoint de santé pour monitoring."""
    return jsonify({"status": "ok", "version": "1.0.0", "timestamp": datetime.datetime.utcnow().isoformat()})


# ────────────────────────────────────────────────────────
# LANCEMENT
# ────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Render (et la plupart des hébergeurs) injectent le PORT via variable d'env
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") != "production"
    print("\n" + "═"*55)
    print("  🛡️  CYBERGUARD MVP — Démarrage du serveur")
    print("═"*55)
    print(f"  → Interface web : http://localhost:{port}")
    print(f"  → API scan      : POST http://localhost:{port}/api/scan")
    print(f"  → Santé         : GET  http://localhost:{port}/api/health")
    print("═"*55 + "\n")
    app.run(debug=debug, host="0.0.0.0", port=port)
