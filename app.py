from flask import Flask, render_template, request, send_file, abort, flash, redirect, url_for
from cve_scraper import get_info
from check_cve import check_cve
from cve_report import create_pdf, create_docx, create_html, create_md
import os
import webbrowser
from threading import Timer
 
# Fuad Aghayev -  This Flask application handles CVE ID input, validates it, and generates reports in PDF, DOCX, HTML, and Markdown formats. 
# It provides download functionality for these reports and automatically opens the application in a browser upon startup.

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for session management

# Define the directory for storing reports
REPORTS_DIR = 'static/reports'
os.makedirs(REPORTS_DIR, exist_ok=True)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        cve_id = request.form.get('cve_id')
        
        if not cve_id:
            flash("CVE ID is required.", 'error')
            return redirect(url_for('index'))
        
        # Perform CVE validation
        cve_check_result = check_cve(cve_id)
        if cve_check_result != True:  # Handle all errors
            flash(cve_check_result, 'error')
            return redirect(url_for('index'))
        
        info = get_info(cve_id)
        if not info or "cve_title" not in info:
            flash("No data found for the provided CVE ID.", 'error')
            return redirect(url_for('index'))
        
        # File paths for reports
        file_paths = {
            "pdf": os.path.join(REPORTS_DIR, f"cve_report_{cve_id}.pdf"),
            "docx": os.path.join(REPORTS_DIR, f"cve_report_{cve_id}.docx"),
            "html": os.path.join(REPORTS_DIR, f"cve_report_{cve_id}.html"),
            "md": os.path.join(REPORTS_DIR, f"cve_report_{cve_id}.md")
        }
        
        # Generate reports
        try:
            create_pdf(info, file_paths["pdf"])
            create_docx(info, file_paths["docx"])
            create_html(info, file_paths["html"])
            create_md(info, file_paths["md"])
        except Exception as e:
            flash(f"Error generating reports: {str(e)}", 'error')
            return redirect(url_for('index'))

        return render_template('report.html', **info)
    
    return render_template('index.html')

@app.route('/download/<file_type>/<cve_id>')
def download(file_type, cve_id):
    file_map = {
        "pdf": f"cve_report_{cve_id}.pdf",
        "docx": f"cve_report_{cve_id}.docx",
        "html": f"cve_report_{cve_id}.html",
        "md": f"cve_report_{cve_id}.md"
    }
    
    file_name = file_map.get(file_type)
    if file_name:
        file_path = os.path.join(REPORTS_DIR, file_name)
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True)
    
    # If file not found, return an error message
    flash("File not found.", 'error')
    return redirect(url_for('index'))

def open_browser():
    try:
        webbrowser.open_new('http://127.0.0.1:5000/')
    except OSError as e:
        print(f"Error opening browser: {e}")


if __name__ == '__main__':
    # Start a timer to open the browser after 1 second
    
    Timer(1, open_browser).start()
    app.run()


