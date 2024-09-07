from flask import Flask, render_template, request, send_file, abort
from cve_scraper import get_info
from check_cve import check_cve
from cve_report import create_pdf, create_docx, create_html, create_md
import os

app = Flask(__name__)

# Define the directory for storing reports
REPORTS_DIR = 'static/reports'
os.makedirs(REPORTS_DIR, exist_ok=True)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        cve_id = request.form.get('cve_id')
        
        if not cve_id:
            return render_template('index.html', error="CVE ID is required.")
        
        cve_check_result = check_cve(cve_id)
        if not cve_check_result:
            return render_template('index.html', error="Invalid CVE ID.")
        
        info = get_info(cve_id)
        if not info or "cve_title" not in info:
            return render_template('index.html', error="No data found for the provided CVE ID.")
        
        # File paths
        file_paths = {
            "pdf": os.path.join(REPORTS_DIR, "cve_report.pdf"),
            "docx": os.path.join(REPORTS_DIR, "cve_report.docx"),
            "html": os.path.join(REPORTS_DIR, "cve_report.html"),
            "md": os.path.join(REPORTS_DIR, "cve_report.md")
        }
        
        # Generate the reports
        try:
            create_pdf(info, file_paths["pdf"])
            create_docx(info, file_paths["docx"])
            create_html(info, file_paths["html"])
            create_md(info, file_paths["md"])
        except Exception as e:
            return render_template('index.html', error=f"Error generating reports: {str(e)}")

        return render_template('report.html', **info)
    
    return render_template('index.html')

@app.route('/download/<file_type>')
def download(file_type):
    file_map = {
        "pdf": "cve_report.pdf",
        "docx": "cve_report.docx",
        "html": "cve_report.html",
        "md": "cve_report.md"
    }
    
    file_name = file_map.get(file_type)
    if file_name:
        file_path = os.path.join(REPORTS_DIR, file_name)
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True)
    
    # If file not found, return an error message
    return render_template('index.html', error="File not found."), 404


if __name__ == '__main__':
    app.run(debug=True)
