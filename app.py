from flask import Flask, render_template, request, send_file
from cve_scraper import get_info
from check_cve import check_cve
from cve_report import create_pdf, create_docx, create_html, create_md
import os

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        cve_id = request.form['cve_id']
        cve_check_result = check_cve(cve_id)
        if cve_check_result is not True:
            return render_template('index.html', error=cve_check_result)
        
        info = get_info(cve_id)
        if not info or "cve_title" not in info:
            return render_template('index.html', error="No data found for the provided CVE ID.")
        
        # Generate the reports
        create_pdf(info, "cve_report.pdf")
        create_docx(info, "cve_report.docx")
        create_html(info, "cve_report.html")
        create_md(info, "cve_report.md")
        
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
    
    file_path = file_map.get(file_type)
    if file_path and os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return "File not found.", 404

if __name__ == '__main__':
    app.run(debug=True)
