from pypdf import PdfReader, PdfWriter

# =========================
# Integrar Fortify & Debricked PDF
# =========================

pdf_base = "reporte_principal.pdf"
pdf_anexo = "Debricked_Report_Tecnico.pdf"
pdf_final = "reporte_final.pdf"

writer = PdfWriter()

# Agregar PDF principal
for page in PdfReader(pdf_base).pages:
    writer.add_page(page)

# Agregar PDF anexo
for page in PdfReader(pdf_anexo).pages:
    writer.add_page(page)

# Guardar resultado
with open(pdf_final, "wb") as f:
    writer.write(f)

print("PDF final generado:", pdf_final)