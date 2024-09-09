import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import time
import webbrowser

def get_exploits(cve_number):
    # Setup Chrome options
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Run in headless mode for no GUI

    # Set up ChromeDriver
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=chrome_options)

    # URL of the Exploit-DB search page with the CVE number
    url = f"https://www.exploit-db.com/search?cve={cve_number}"

    # Open the URL
    driver.get(url)

    # Wait for the page to load
    time.sleep(5)  # Adjust the sleep time as needed

    # Get page source and close the driver
    page_source = driver.page_source
    driver.quit()

    # Parse the page content with BeautifulSoup
    soup = BeautifulSoup(page_source, 'html.parser')

    # Find the table containing the exploits using id
    table = soup.find('table', id='exploits-table')

    if not table:
        print("Exploit table not found")
        return []

    # Extract table rows
    tbody = table.find('tbody')
    rows = tbody.find_all('tr') if tbody else []

    exploits = []
    for row in rows:
        columns = row.find_all('td')

        # Ensure there are enough columns before accessing
        if len(columns) < 2:
            print(f"Skipping row due to insufficient columns: {columns}")
            continue

        # Check for verified/unverified status within the current row
        is_verified = row.find("i", {"class": "mdi-check"}) is not None
        is_not_verified = row.find("i", {"class": "mdi-close"}) is not None

        # Extract text from each column safely
        exploit_data = {
            'date': columns[0].text.strip(),
            'download_link': f"https://www.exploit-db.com{columns[1].find('a')['href']}" if columns[1].find('a') else "N/A",
            'exploit_link': f"https://www.exploit-db.com/exploits/{columns[1].find('a')['href'].split('/')[2]}" if columns[1].find('a') else "N/A",
            'author': columns[7].text.strip(),
            'type': columns[5].text.strip(),
            'platform': columns[6].text.strip(),
            'title': columns[4].text.strip(),
            'verified': "Yes" if is_verified else "No" if is_not_verified else "N/A",
        }

        exploits.append(exploit_data)

    return exploits


def get_info(cve_id):
    """Fetch CVE details from NVD, MITRE, and Exploit-DB."""

    # URL for NVD CVE detail page
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    # Send request to NVD page and parse HTML response
    try:
        response = requests.get(nvd_url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching NVD data: {e}")
        soup = BeautifulSoup("", "html.parser")  # Use an empty soup if the request fails

    # Extract CVE Title
    title_element = soup.find("span", {"data-testid": "vuln-title"})
    cve_title = title_element.text.strip() if title_element else cve_id  # Use CVE ID if title is not available

    # Retrieve the available CVSS base score
    cvss_element_2 = soup.find("a", {"id": ["Cvss2CalculatorAnchor","Cvss2CalculatorAnchor"]})
    cvss_element_3 = soup.find("a", {"data-testid": ["vuln-cvss3-panel-score", "vuln-cvss3-cna-panel-score"]})
    cvss_element_4 = soup.find("a", {"data-testid": ["vuln-cvss4-panel-score", "Cvss4NistCalculatorAnchorNA"]})

    cvss_score = cvss_element_4.text if cvss_element_4 else cvss_element_3.text if cvss_element_3 else cvss_element_2.text if cvss_element_2 else "Base Score is not available"
    
    # Retrieve the CVSS vector
    vector_element_3 = soup.find("span", {"data-testid": ["vuln-cvss3-cna-vector", "vuln-cvss3-nist-vector"]})
    vector_element_2 = soup.find("span", {"data-testid": ["vuln-cvss2-panel-vector","vuln-cvss2-panel-vector-na"]})
    vector_element_4 = soup.find("span", {"data-testid": ["vuln-cvss4-nist-vector", "vuln-cvss4-nist-vector-na"]})

    # Ensure the CVSS vector is selected correctly
    if vector_element_3:
        cvss_vector = vector_element_3.text.strip()
    elif vector_element_2:
        cvss_vector = vector_element_2.text.strip()
    elif vector_element_4:
        cvss_vector = vector_element_4.text.strip()
    else:
        cvss_vector = "Vector is not available"

    # Extract Description
    description_element = soup.find("p", {"data-testid": "vuln-description"})
    description = description_element.text.strip() if description_element else "Description not available"

    # If NVD data is not available, check MITRE
    if not title_element or not description_element:
        mitre_api_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        try:
            mitre_response = requests.get(mitre_api_url, timeout=10).json()

            # Check for the error message from MITRE API
            if mitre_response.get("error") == "CVE_RECORD_DNE":
                return {"error": f"CVE record for {cve_id} not found."}

            affected_assets = []
            affected_list = mitre_response.get('containers', {}).get('cna', {}).get('affected', [])
            for asset in affected_list:
                vendor = asset.get('vendor', 'N/A')
                product = asset.get('product', 'N/A')
                affected_assets.append({"vendor": vendor, "product": product})

            # Extract CVE State
            cve_state = mitre_response.get('cveMetadata', {}).get('state', 'Not Available')

            # Extract Description from MITRE if NVD does not have it
            description = mitre_response.get('containers', {}).get('cna', {}).get('description', description)

            # Check if CVE is reserved
            mitre_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
            mitre_response = requests.get(mitre_url)
            mitre_soup = BeautifulSoup(mitre_response.text, 'html.parser')
            reserved_link = mitre_soup.find("a", href="https://cve.mitre.org/about/faqs.html#reserved_signify_in_cve_entry")
            if reserved_link:
                description = "RESERVED: " + description

        except requests.exceptions.RequestException as e:
            print(f"Error fetching MITRE data: {e}")
            affected_assets = [{"vendor": "N/A", "product": "N/A"}]
            cve_state = "Not Available"

    else:
        # Default CVE state if no MITRE data
        cve_state = "Not Available"
        affected_assets = [{"vendor": "N/A", "product": "N/A"}]

    # Extract References (Advisories, Patches, and Tools)
    references = []
    ref_table = soup.find("table", {"data-testid": "vuln-hyperlinks-table"})
    if ref_table:
        rows = ref_table.find_all("tr")[1:]  # Skip header row
        for row in rows:
            # Check for "Broken Link" badge
            broken_link_badge = row.find("span", {"class": "badge"})
            if broken_link_badge and "Broken Link" in broken_link_badge.text:
                print(f"Skipping broken link: {row}")
                continue

            cols = row.find_all("td")
            ref_link = cols[0].find("a")["href"].strip() if cols[0].find("a") else "N/A"
            ref_desc = cols[0].text.strip() if cols[0] else "N/A"
            if ref_link != "N/A":
                try:
                    # Check if the reference link returns a 200 status code
                    link_response = requests.get(ref_link, timeout=10)
                    if link_response.status_code == 200:
                        references.append({"description": ref_desc, "link": ref_link})
                    else:
                        print(f"Reference link returned non-200 status: {ref_link}")
                except requests.exceptions.RequestException as e:
                    print(f"Error fetching reference link: {e}")

    # Open up to 5 reference links in the default browser
    for ref in references[:5]:
        webbrowser.open(ref["link"])

    # Get Exploits
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
