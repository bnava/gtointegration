import json
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import LETTER
from reportlab.lib import colors

INPUT_FILE = "debricked-report.json"
OUTPUT_FILE = "Debricked_Report_Tecnico.pdf"

# =========================
# Cargar JSON
# =========================
with open(INPUT_FILE, "r", encoding="utf-8") as f:
    data = json.load(f)

vulns = data.get("vulnerabilities", [])

# =========================
# Documento A4
# =========================
doc = SimpleDocTemplate(
    OUTPUT_FILE,
    pagesize=LETTER,
    rightMargin=30,
    leftMargin=30,
    topMargin=30,
    bottomMargin=30
)

styles = getSampleStyleSheet()
normal = styles["Normal"]
title = styles["Title"]
header = styles["Heading2"]

story = []

# =========================
# Portada
# =========================
story.append(Paragraph("Debricked OSS Vulnerability Report", title))
story.append(Spacer(1, 14))
story.append(Paragraph(
    "Technical vulnerability report generated from Debricked (Fortify integration).",
    normal
))
story.append(Spacer(1, 20))

story.append(Paragraph("<b>Summary</b>", header))
story.append(Paragraph(f"Total vulnerabilities: {len(vulns)}", normal))
story.append(Spacer(1, 20))

# =========================
# Severidades
# =========================
severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
severity_colors = {
    "CRITICAL": colors.red,
    "HIGH": colors.orange,
    "MEDIUM": colors.gold,
    "LOW": colors.lightgreen
}

# =========================
# Columnas (A4)
# =========================
#col_widths = [80, 60, 150, 60, 190]
col_widths = [80, 50, 70, 60, 150, 150]

# =========================
# Funciones de extracción
# =========================
def get_cve(v):
    return v.get("cve", "N/A")


def get_version(v):
    return (
        v.get("location", {})
         .get("dependency", {})
         .get("version", "N/A")
    )


def get_file(v):
    return (
        v.get("location", {})
         .get("file", "N/A")
    )
    
def get_url(v):
    for link in v.get("links", []):
        if link.get("name", "").upper() == "CWE URL":
            return link.get("url", "N/A")
    return "N/A"

# =========================
# Procesar por severidad
# =========================
for severity in severity_order:
    sev_vulns = [
        v for v in vulns
        if v.get("severity", "").upper() == severity
    ]

    if not sev_vulns:
        continue

    story.append(PageBreak())
    story.append(Paragraph(f"{severity} Vulnerabilities", header))
    story.append(Spacer(1, 10))

    table_data = [
        ["CVE", "Version", "File", "Severity", "Description", "URL"]
    ]

    for v in sev_vulns:
        table_data.append([
            Paragraph(get_cve(v), normal),
            Paragraph(get_version(v), normal),
            Paragraph(get_file(v), normal),
            Paragraph(severity, normal),
            Paragraph(get_url(v), normal),
            Paragraph((v.get("description", "") or "")[:600], normal)
        ])

    table = Table(
        table_data,
        colWidths=col_widths,
        repeatRows=1
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("BACKGROUND", (3, 1), (3, -1), severity_colors.get(severity)),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONT", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
    ]))

    story.append(table)

# =========================
# Construir PDF
# =========================
doc.build(story)

print("PDF generado correctamente:", OUTPUT_FILE)