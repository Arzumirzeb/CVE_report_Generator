import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import NoSuchElementException
import time
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

def get_exploits(cve_id):
    """Extract exploits from Exploit-DB using Selenium."""
    
    options = Options()
    options.add_argument('--headless')
    options.add_argument("--log-level=3")
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    wait = WebDriverWait(driver, 10)

    url = f"https://www.exploit-db.com/search?cve={cve_id}"
    driver.get(url)
    driver.implicitly_wait(15)
    time.sleep(10)  # Ensure the page is fully loaded

    tbody_elements = driver.find_elements(By.XPATH, "//tbody")
    all_tr_elements = tbody_elements[0].find_elements(By.TAG_NAME, "tr")
    verified_tr_elements = []
    unverified_tr_elements = []
    
    for tr_element in all_tr_elements:
        try:
            tr_element.find_element(By.XPATH, './/i[@class="mdi mdi-check mdi-18px"]')
            verified_tr_elements.append(tr_element)
        except NoSuchElementException:
            try:
                tr_element.find_element(By.XPATH, './/i[@class="mdi mdi-close mdi-18px"]')
                unverified_tr_elements.append(tr_element)
            except NoSuchElementException:
                pass

    exploits = []
    previous_href = None

    def extract_exploits(tr_elements, verified):
        nonlocal previous_href
        for tr_element in tr_elements:
            a_tags = tr_element.find_elements(By.TAG_NAME, "a")
            for a_tag in a_tags:
                href = a_tag.get_attribute('href')
                if href:
                    if "/exploits" in href:
                        if previous_href is not None:
                            exploits.append({
                                "title": a_tag.get_attribute('innerText'),
                                "exploit_link": href,
                                "download_link": previous_href,
                                "verified": "YES" if verified else "NO"
                            })
                        previous_href = None
                    elif "/download" in href:
                        previous_href = href

    extract_exploits(verified_tr_elements, verified=True)
    extract_exploits(unverified_tr_elements, verified=False)

    if not exploits:
        exploits.append({"title": "N/A", "exploit_link": "N/A", "download_link": "N/A", "verified": "N/A"})

    driver.quit()
    return exploits

def get_info(cve_id):
    """Fetch CVE details from NVD, MITRE, and Exploit-DB."""
    
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
    
    # Fetch vendor and product details from MITRE API
    mitre_api_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    mitre_response = requests.get(mitre_api_url).json()
    
    affected_assets = []
    try:
        affected_list = mitre_response['containers']['cna']['affected']
        for asset in affected_list:
            vendor = asset.get('vendor', 'N/A')
            product = asset.get('product', 'N/A')
            affected_assets.append({"vendor": vendor, "product": product})
    except KeyError:
        affected_assets.append({"vendor": "N/A", "product": "N/A"})
    
    # Extract CVE State
    cve_state = mitre_response.get('cveMetadata', {}).get('state', 'Not Available')
    
    # Extract References (Advisories, Patches, and Tools)
    references = []
    ref_table = soup.find("table", {"data-testid": "vuln-hyperlinks-table"})
    if ref_table:
        rows = ref_table.find_all("tr")[1:]  # Skip header row
        for row in rows:
            cols = row.find_all("td")
            ref_link = cols[0].find("a")["href"].strip() if cols[0].find("a") else "N/A"
            ref_desc = cols[0].text.strip() if cols[0] else "N/A"
            references.append({"description": ref_desc, "link": ref_link})

    # Extract Exploits from Exploit-DB
    exploits = get_exploits(cve_id)

    return {
        "cve_title": cve_title,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "description": description,
        "affected_assets": affected_assets,
        "references": references,
        "exploits": exploits,
        "state": cve_state  # Include CVE state in the returned data
    }

