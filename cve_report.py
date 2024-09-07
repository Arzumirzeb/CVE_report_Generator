from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from docx import Document
from markdown2 import markdown

def create_pdf(cve_info, file_path):
    """Generate a PDF report."""
    c = canvas.Canvas(file_path, pagesize=letter)
    width, height = letter

    # Set font and initial position
    c.setFont("Helvetica", 12)
    y_position = height - 1 * inch

    # Title
    c.drawString(1 * inch, y_position, f"CVE Report for {cve_info['cve_title']}")
    y_position -= 0.5 * inch

    # CVSS Score and Vector
    c.drawString(1 * inch, y_position, f"CVSS Score: {cve_info['cvss_score']} | CVSS Vector: {cve_info['cvss_vector']}")
    y_position -= 0.5 * inch

    # Description
    description = f"Description: {cve_info['description']}"
    c.drawString(1 * inch, y_position, description)
    y_position -= 0.5 * inch

    # Affected Assets
    c.drawString(1 * inch, y_position, "Affected Assets:")
    y_position -= 0.5 * inch

    for asset in cve_info.get('affected_assets', []):
        asset_text = f"Vendor: {asset.get('vendor', 'N/A')}, Product: {asset.get('product', 'N/A')}"
        c.drawString(1 * inch, y_position, asset_text)
        y_position -= 0.25 * inch

    y_position -= 0.5 * inch
    c.drawString(1 * inch, y_position, "Exploits:")
    y_position -= 0.5 * inch

    for exploit in cve_info.get('exploits', []):
        exploit_text = f"Title: {exploit.get('title', 'N/A')}, Verified: {exploit.get('verified', 'N/A')}"
        c.drawString(1 * inch, y_position, exploit_text)
        c.drawString(1 * inch, y_position - 0.25 * inch, f"Download Link: {exploit.get('download_link', 'N/A')}")
        c.drawString(1 * inch, y_position - 0.5 * inch, f"Exploit Link: {exploit.get('exploit_link', 'N/A')}")
        y_position -= 0.75 * inch

    y_position -= 0.5 * inch
    c.drawString(1 * inch, y_position, "References:")
    y_position -= 0.5 * inch

    for ref in cve_info.get('references', []):
        ref_text = f"Description: {ref.get('description', 'N/A')}, Link: {ref.get('link', 'N/A')}"
        c.drawString(1 * inch, y_position, ref_text)
        y_position -= 0.5 * inch

    # Save the PDF
    c.save()


def create_docx(cve_info, file_path):
    """Generate a DOCX report."""
    doc = Document()
    doc.add_heading(f"CVE Report for {cve_info['cve_title']}", level=1)
    
    doc.add_paragraph(f"CVSS Score: {cve_info['cvss_score']} | CVSS Vector: {cve_info['cvss_vector']}")
    doc.add_paragraph(f"Description: {cve_info['description']}")

    doc.add_heading('Affected Assets:', level=2)
    for asset in cve_info['affected_assets']:
        doc.add_paragraph(f"Vendor: {asset['vendor']}, Product: {asset['product']}")
    
    doc.add_heading('Exploits:', level=2)
    for exploit in cve_info['exploits']:
        doc.add_paragraph(f"Title: {exploit['title']}")
        doc.add_paragraph(f"Verified: {exploit['verified']}")
        doc.add_paragraph(f"Download Link: {exploit['download_link']}")
        doc.add_paragraph(f"Exploit Link: {exploit['exploit_link']}")
    
    doc.add_heading('References:', level=2)
    for ref in cve_info['references']:
        doc.add_paragraph(f"Description: {ref['description']}")
        doc.add_paragraph(f"Link: {ref['link']}")
    
    doc.save(file_path)

def create_html(cve_info, file_path):
    """Generate an HTML report."""
    html_content = (
        "<html>"
        "<head><title>CVE Report for {0}</title></head>"
        "<body>"
        "<h1>CVE Report for {0}</h1>"
        "<p><strong>CVSS Score:</strong> {1} | <strong>CVSS Vector:</strong> {2}</p>"
        "<p><strong>Description:</strong> {3}</p>"
        "<h2>Affected Assets:</h2>"
        "<ul>"
        "{4}"
        "</ul>"
        "<h2>Exploits:</h2>"
        "<ul>"
        "{5}"
        "</ul>"
        "<h2>References:</h2>"
        "<ul>"
        "{6}"
        "</ul>"
        "</body>"
        "</html>"
    ).format(
        cve_info['cve_title'],
        cve_info['cvss_score'],
        cve_info['cvss_vector'],
        cve_info['description'],
        "".join(f"<li>Vendor: {asset['vendor']}, Product: {asset['product']}</li>" for asset in cve_info['affected_assets']),
        "".join(f"<li>Title: {exploit['title']} - Verified: {exploit['verified']} - Download Link: <a href='{exploit['download_link']}'>Download</a> - Exploit Link: <a href='{exploit['exploit_link']}'>Exploit</a></li>" for exploit in cve_info['exploits']),
        "".join(f"<li>Description: {ref['description']} - Link: <a href='{ref['link']}'>Reference</a></li>" for ref in cve_info['references'])
    )
    with open(file_path, "w") as file:
        file.write(html_content)

def create_md(cve_info, file_path):
    """Generate a Markdown report."""
    markdown_content = (
        "# CVE Report for {0}\n\n"
        "**CVSS Score:** {1} | **CVSS Vector:** {2}\n\n"
        "**Description:** {3}\n\n"
        "## Affected Assets:\n"
        "{4}\n\n"
        "## Exploits:\n"
        "{5}\n\n"
        "## References:\n"
        "{6}\n"
    ).format(
        cve_info['cve_title'],
        cve_info['cvss_score'],
        cve_info['cvss_vector'],
        cve_info['description'],
        "".join(f"- Vendor: {asset['vendor']}, Product: {asset['product']}\n" for asset in cve_info['affected_assets']),
        "".join(f"- Title: {exploit['title']} - Verified: {exploit['verified']} - Download Link: [{exploit['download_link']}]({exploit['download_link']}) - Exploit Link: [{exploit['exploit_link']}]({exploit['exploit_link']})\n" for exploit in cve_info['exploits']),
        "".join(f"- Description: {ref['description']} - Link: [{ref['link']}]({ref['link']})\n" for ref in cve_info['references'])
    )
    with open(file_path, "w") as file:
        file.write(markdown_content)

