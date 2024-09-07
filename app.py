from flask import Flask, render_template, request
from cve_scraper import get_info
from check_cve import check_cve

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
        
        return render_template('report.html', **info)
    
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
