from flask import Flask, render_template, request
from cve_scraper import get_info

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        cve_id = request.form['cve_id']
        info = get_info(cve_id)
        if not info:
            return render_template('index.html', error="No data found for the provided CVE ID.")
        return render_template('report.html', **info)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
