import re
from login import automated_login

# regex patterns (constant)
IDOR = re.compile(r"https?://[^\s]*\?.*=.*")
UNIQUE = re.compile(r'/([^/]+\.php)')

def check_idor(links, session, flagged_set, userfield, username, passfield, password, login_url):
    """
    1. Perform a get request with your own parameter and capture the length
    2. Perform a get request with a non existent parameter and capture the length
    3. Now do ?*=x++ and check for length difference
    """
    urls = set()

    for link in links:
        if re.search(IDOR, link[0]):
            urls.add(link[0])
    print(f"\n[===== IDOR Scans =====]")
    idor_links = get_idor(list(urls))

    # Check if it's an autenticated or unauthenticated idor scan first!
    if userfield:
        session = automated_login(userfield, username, passfield, password, login_url)

    for url in idor_links:
        print(f"\nScanning: {url}")
        sizes = {}
        # place_holder = f'{url.split('=')[0]}?'
        r = session.get(url, timeout=10, verify=False)
        yours = len(r.text)
        r = session.get(url.split('=')[0] + "=123456789123456789", timeout=10, verify=False)
        nonexistent = len(r.text)
        challenge_idor(url, "idor", session, flagged_set, nonexistent, yours)

def challenge_idor(url, keyword, session, flagged_set, nonexistent, yours, iterations=24):
    """
    data types
    url: string
    keyword: string
    session: requests.Session
    flagged_set: set
    sizes: dictionary
    nonexistent: int
    yours: int
    iterations: int
    """
    sizes = {}
    for attempt in range(1, iterations):
        r = session.get(url.split('=')[0] + f"={attempt}", timeout=10, verify=False)
        sizes[attempt] = len(r.text)
        if len(r.text) != nonexistent and len(r.text) != yours:
            print(f"    [!] Potential {keyword} found: {url.split('=')[0]}={attempt}")
            flagged_set.add((f"{url.split('=')[0]}={attempt}", keyword))
    return flagged_set

def get_idor(urls):
    """
    Return a unique list of URLs that contain the ?*= pattern
    """
    unique_pages = {}
    links = []
    for url in urls:
        match = re.search(UNIQUE, url)
        if match:
            page_type = match.group(1)  # Extracts the PHP page like 'product_page.php'
            if page_type not in unique_pages:
                unique_pages[page_type] = url

    # Print one URL from each unique page type
    for key, value in unique_pages.items():
        links.append(value)

    return links