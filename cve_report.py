from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from docx import Document
from docx.shared import Pt

def create_pdf(cve_info, file_path):
    """Generate a PDF report."""
    c = canvas.Canvas(file_path, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica", 12)
    c.drawString(1 * inch, height - 1 * inch, f"CVE Report for {cve_info['cve_title']}")
    
    c.drawString(1 * inch, height - 1.5 * inch, f"CVSS Score: {cve_info['cvss_score']} | CVSS Vector: {cve_info['cvss_vector']}")
    c.drawString(1 * inch, height - 2 * inch, f"Description: {cve_info['description']}")

    y_position = height - 3 * inch

    c.drawString(1 * inch, y_position, "Affected Assets:")
    y_position -= 0.5 * inch
    
    for asset in cve_info.get('affected_assets', []):
        if isinstance(asset, dict):
            c.drawString(1 * inch, y_position, f"Vendor: {asset.get('vendor', 'N/A')}, Product: {asset.get('product', 'N/A')}")
            y_position -= 0.25 * inch

    y_position -= 0.5 * inch
    c.drawString(1 * inch, y_position, "Exploits:")
    y_position -= 0.5 * inch
    
    for exploit in cve_info.get('exploits', []):
        if isinstance(exploit, dict):
            c.drawString(1 * inch, y_position, f"Title: {exploit.get('title', 'N/A')}, Verified: {exploit.get('verified', 'N/A')}")
            c.drawString(1 * inch, y_position - 0.25 * inch, f"Download Link: {exploit.get('download_link', 'N/A')}")
            c.drawString(1 * inch, y_position - 0.5 * inch, f"Exploit Link: {exploit.get('exploit_link', 'N/A')}")
            y_position -= 0.75 * inch

    y_position -= 0.5 * inch
    c.drawString(1 * inch, y_position, "References:")
    y_position -= 0.5 * inch

    for ref in cve_info.get('references', []):
        if isinstance(ref, dict):
            c.drawString(1 * inch, y_position, f"Description: {ref.get('description', 'N/A')}, Link: {ref.get('link', 'N/A')}")
            y_position -= 0.5 * inch

    c.save()

def create_docx(cve_info, file_path):
    """Generate a DOCX report."""
    doc = Document()
    doc.add_heading(f"CVE Report for {cve_info['cve_title']}", level=1)
    
    doc.add_paragraph(f"CVSS Score: {cve_info['cvss_score']} | CVSS Vector: {cve_info['cvss_vector']}")
    doc.add_paragraph(f"Description: {cve_info['description']}")

    doc.add_heading('Affected Assets:', level=2)
    for asset in cve_info.get('affected_assets', []):
        if isinstance(asset, dict):
            doc.add_paragraph(f"Vendor: {asset.get('vendor', 'N/A')}, Product: {asset.get('product', 'N/A')}")
    
    doc.add_heading('Exploits:', level=2)
    for exploit in cve_info.get('exploits', []):
        if isinstance(exploit, dict):
            doc.add_paragraph(f"Title: {exploit.get('title', 'N/A')}")
            doc.add_paragraph(f"Verified: {exploit.get('verified', 'N/A')}")
            doc.add_paragraph(f"Download Link: {exploit.get('download_link', 'N/A')}")
            doc.add_paragraph(f"Exploit Link: {exploit.get('exploit_link', 'N/A')}")
    
    doc.add_heading('References:', level=2)
    for ref in cve_info.get('references', []):
        if isinstance(ref, dict):
            doc.add_paragraph(f"Description: {ref.get('description', 'N/A')}")
            doc.add_paragraph(f"Link: {ref.get('link', 'N/A')}")
    
    doc.save(file_path)

# Example usage
if __name__ == "__main__":
    example_cve_info = {
        "cve_title": "CVE-2024-21410",
        "cvss_score": "7.5",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "description": "An example description of the CVE.",
        "affected_assets": [
            {"vendor": "Vendor1", "product": "Product1"},
            {"vendor": "Vendor2", "product": "Product2"}
        ],
        "exploits": [
            {"title": "Exploit 1", "download_link": "http://example.com/download1", "exploit_link": "http://example.com/exploit1", "verified": "YES"},
            {"title": "Exploit 2", "download_link": "http://example.com/download2", "exploit_link": "http://example.com/exploit2", "verified": "NO"}
        ],
        "references": [
            {"description": "Reference 1", "link": "http://example.com/reference1"},
            {"description": "Reference 2", "link": "http://example.com/reference2"}
        ],
        "state": "Published"
    }

    create_pdf(example_cve_info, "cve_report.pdf")
    create_docx(example_cve_info, "cve_report.docx")
