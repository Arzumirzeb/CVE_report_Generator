Sure! Here’s the README in the correct format, ready for you to add to GitHub:

---

# CVE Report Generator

## Overview
The **CVE Report Generator** is a comprehensive web application designed to retrieve and present detailed information about Common Vulnerabilities and Exposures (CVEs). This application integrates multiple sources to gather CVE data, including **NVD**, **MITRE**, and **Exploit-DB**. It provides users with various reporting formats, such as **PDF**, **DOCX**, **HTML**, and **Markdown**, ensuring that users can access CVE information in their preferred format.

## Features
- **Multi-source Data Retrieval:** Collects CVE details from NVD, MITRE, and Exploit-DB.
- **Dynamic Reporting:** Generates reports in **PDF**, **DOCX**, **HTML**, and **Markdown** formats.
- **Comprehensive Information:** Includes CVE title, CVSS score, CVSS vector, description, affected assets, exploits, and references.
- **Web-based Interface:** Easy-to-use web interface for inputting CVE IDs and accessing reports.
- **Exploit Details:** Provides detailed information about available exploits, including download links, verification status, and more.

## Key Components

### 1. Data Fetching
- Utilizes **web scraping** and **API requests** to gather CVE information from various sources.
- Extracts critical details such as CVE title, CVSS score, vector, description, and affected assets.

### 2. Report Generation
- Creates detailed reports in multiple formats:
  - **PDF:** Professional-looking PDF reports without tables, featuring a simple list for references.
  - **DOCX:** Well-structured DOCX reports with headings and paragraphs.
  - **HTML:** HTML reports with clear formatting for web viewing.
  - **Markdown:** Markdown reports suitable for documentation and version control.

### 3. Exploit Information
- Extracts and presents details about exploits related to the CVE from **Exploit-DB**.

### 4. References Management
- Retrieves and validates references, providing reliable links and descriptions.

## Installation

### Clone the Repository
```sh
git clone https://github.com/your-username/cve-report-generator.git
cd cve-report-generator
```

### Set Up a Virtual Environment (Optional)
It's recommended to create a virtual environment to avoid dependency conflicts:
```sh
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
```

### Install Dependencies
Install the required dependencies using `pip`:
```sh
pip install -r requirements.txt
```

### Run the Application
To start the application:
```sh
python app.py
```

Open your browser and navigate to `http://127.0.0.1:5000` to use the CVE Report Generator.

## Usage
1. **Enter a CVE ID:** Enter a valid CVE ID (e.g., `CVE-2021-34527`) in the web interface.
2. **Fetch CVE Information:** The application will retrieve data about the CVE, including affected assets and exploits.
3. **Download Reports:** Select the desired format (**PDF**, **DOCX**, **HTML**, or **Markdown**) and download the report.

## Project Structure

```bash
CVE_Report_Generator/
│
├── app.py              # Main Flask application
├── cve_scraper.py      # Script for scraping CVE data
├── check_cve.py        # CVE ID validation logic
├── cve_report.py       # Handles report generation
│
├── templates/          # HTML templates for web pages
│   ├── base.html
│   ├── index.html
│   └── report.html
│
├── static/             # Static files (CSS, images)
│   ├── css/
│   │   └── styles.css
│   └── reports/        # Directory for generated report files
│
├── requirements.txt    # Python dependencies
├── README.md           # This file
└── .env                # Environment variables (optional)
