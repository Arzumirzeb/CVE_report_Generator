import re
import datetime


def check_cve(cve: str):
    cve = cve.strip()  # Remove any leading/trailing whitespace
    cve = cve.lower()  # Normalize input to lowercase for case-insensitive comparison
    cve_parts: list = cve.split('-')
    current_year: int = datetime.datetime.now().year
    pattern_1: str = "cve"  # Now in lowercase to match normalized input
    pattern_2: str = r'^\d{4}$'
    pattern_3: str = r'\d{4,}$'
    pattern_3_1: str = r'^0000'

    if cve == "":
        return "CVE ID error: Please enter a standard CVE ID. (Example: CVE-2018-0101)"
    if '-' not in cve:
        return "CVE ID error: The provided input is not a standard CVE ID. (Example: CVE-2018-0101)"
    if not cve_parts[0] == pattern_1:  # Comparison is now case-insensitive
        return "CVE abbreviation error: The CVE ID must start with the abbreviation 'CVE' (which is not case-sensitive)."
    if not cve_parts[1].isdigit():
        return "CVE year error: The year must contain only digits."
    if not re.match(pattern_2, cve_parts[1]):
        return "CVE year error: Enter a valid year in the interval of [1999-current]."
    if not 1999 <= int(cve_parts[1]) <= current_year:
        return f"CVE year error: The year must be in the interval 1999-{current_year}."
    if not re.match(pattern_3, cve_parts[2]):
        return "CVE number error: At least 4 digits are required, and no non-digit characters are allowed."
    if re.match(pattern_3_1, cve_parts[2]):
        return "CVE number error: The first 4 digits can't be all-zero."
    if not len(cve_parts[2]) > 4:
        return True
    if int(cve_parts[2][0]) == 0:
        return "CVE number error: CVE numbers greater than 9999 are required (when the CVE number has more than 4 digits)."
    if not cve.count('-') == 2:
        return "CVE ID error: Only 2 hyphens are allowed."

    return True
