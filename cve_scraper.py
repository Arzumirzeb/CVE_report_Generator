import requests
from bs4 import BeautifulSoup

def get_info(cve_id):
    """Fetch CVE details from NVD and Exploit-DB."""
    
    # URL for NVD CVE detail page
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    
    # Send request to NVD page and parse HTML response
    response = requests.get(nvd_url)
    soup = BeautifulSoup(response.text, "html.parser")
    
    # Extract CVE Title
    title_element = soup.find("span", {"data-testid": "vuln-title"})
    cve_title = title_element.text.strip() if title_element else cve_id  # Use CVE ID if title is not available
    
    # Extract CVSS Score and Vector
    cvss_score_element = soup.find("a", {"data-testid": "vuln-cvss3-panel-score"})
    cvss_score = cvss_score_element.text.strip() if cvss_score_element else "CVSS Score not available"
    vector_element = soup.find("span", {"data-testid": "vuln-cvss3-nist-vector"})
    cvss_vector = vector_element.text.strip() if vector_element else "CVSS Vector not available"
    
    # Extract Description
    description_element = soup.find("p", {"data-testid": "vuln-description"})
    description = description_element.text.strip() if description_element else "Description not available"
    
    # Extract Affected Assets
    affected_assets = []
    assets_table = soup.find("table", {"data-testid": "vuln-assets"})
    if assets_table:
        rows = assets_table.find_all("tr")[1:]  # Skip header row
        for row in rows:
            cols = row.find_all("td")
            vendor = cols[0].text.strip() if len(cols) > 0 else "N/A"
            product = cols[1].text.strip() if len(cols) > 1 else "N/A"
            affected_assets.append({"vendor": vendor, "product": product})

    # Extract Exploits from Exploit-DB
    exploits = []
    exploit_db_url = f"https://www.exploit-db.com/search?cve={cve_id}"
    response = requests.get(exploit_db_url)
    soup = BeautifulSoup(response.text, "html.parser")
    exploits_table = soup.find("table", {"class": "table table-bordered table-hover"})
    if exploits_table:
        rows = exploits_table.find_all("tr")[1:]  # Skip header row
        for row in rows:
            cols = row.find_all("td")
            if len(cols) > 2:
                title = cols[0].text.strip()
                exploit_link = cols[0].find("a")["href"].strip() if cols[0].find("a") else "N/A"
                download_link = cols[1].text.strip()
                verified = "YES" if "mdi-check" in row.decode_contents() else "NO"
                exploits.append({"title": title, "exploit_link": exploit_link, "download_link": download_link, "verified": verified})

    return {
        "cve_title": cve_title,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "description": description,
        "affected_assets": affected_assets,
        "exploits": exploits
    }
