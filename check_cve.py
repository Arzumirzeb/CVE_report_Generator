import re
import datetime

def check_cve(cve: str):
    cve_parts = cve.split('-')
    current_year = datetime.datetime.now().year
    pattern_1 = "CVE"
    pattern_2 = r'^\d{4}$'
    pattern_3 = r'\d{4,}$'
    pattern_3_1 = r'^0000'

    # Handle missing or incorrect CVE format
    if cve == "":
        return "CVE ID error: Please enter a standard CVE ID (Example: CVE-2024-21410)."
    if not cve.count('-') == 2:
        return "CVE ID error: Only 2 hyphens are allowed."
    if '-' not in cve:
        return "CVE ID error: The provided input is not a standard CVE ID (Example: CVE-2024-21410)."
    
    # Check the first part (CVE abbreviation)
    if not cve_parts[0].upper() == pattern_1:
        return "CVE abbreviation error: The CVE ID must start with the abbreviation 'CVE' (case insensitive)."
    
    # Check the second part (Year)
    if not cve_parts[1].isdigit():
        return "CVE year error: Year must contain only digits."
    if not re.match(pattern_2, cve_parts[1]):
        return "CVE year error: Enter a valid year value in the interval [1999-current]."
    if int(cve_parts[1]) < 1999:
        return "CVE year error: CVEs before 1999 do not exist."
    if not 1999 <= int(cve_parts[1]) <= current_year:
        return f"CVE year error: The year must be in the interval 1999-{current_year}."
    
    # Check the third part (CVE number)
    if not re.match(pattern_3, cve_parts[2]):
        return "CVE number error: At least 4 digits are required, or non-digit characters exist."
    if re.match(pattern_3_1, cve_parts[2]):
        return "CVE number error: The first 4 digits can't be all-zero."
    if len(cve_parts[2]) <= 4:
        return True
    if int(cve_parts[2][0]) == 0:
        return "CVE number error: CVE number greater than 9999 is required (when CVE number has more than 4 digits)."
    
    return True
