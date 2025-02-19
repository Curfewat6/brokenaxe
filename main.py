import argparse
import concurrent.futures
import requests
import urllib3
import os
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

# regex patterns (constant)
IDOR = re.compile(r"https?://[^\s]*\?.*=.*")
UNIQUE = re.compile(r'/([^/]+\.php)')

# Disable warnings for insecure SSL connections
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def print_banner():
    banner = r""" 
    ▀█████████▄  ▄████████  ▄██████▄     ▄█   ▄█▄    ▄████████ ███▄▄▄▄      ▄████████ ▀████    ▐████▀    ▄████████      
    ███    ███   ███    ███ ███    ███   ███ ▄███▀   ███    ███ ███▀▀▀██▄   ███    ███   ███▌   ████▀    ███    ███      
    ███    ███   ███    ███ ███    ███   ███▐██▀     ███    █▀  ███   ███   ███    ███    ███  ▐███      ███    █▀       
    ▄███▄▄▄██▀ ▄███▄▄▄▄██▀ ███    ███  ▄█████▀     ▄███▄▄▄     ███   ███   ███    ███    ▀███▄███▀     ▄███▄▄▄          
    ▀▀███▀▀▀██▄▀▀███▀▀▀▀▀   ███    ███ ▀▀█████▄    ▀▀███▀▀▀     ███   ███ ▀███████████    ████▀██▄     ▀▀███▀▀▀          
    ███    ██▄  ▀███████████ ███    ███   ███▐██▄     ███    █▄  ███   ███   ███    ███   ▐███  ▀███      ███    █▄       
    ███    ███   ███    ███ ███    ███   ███ ▀███▄   ███    ███ ███   ███   ███    ███  ▄███     ███▄    ███    ███      
    ▄█████████▀  ███    ███  ▀██████▀    ███   ▀█▀   ██████████  ▀█   █▀    ███    █▀  ████       ███▄   ██████████      
                 ███    ███              ▀                                                                               
    """
    print(banner)

def load_wordlist(file_path):
    if not os.path.exists(file_path):
        print(f"[!] Wordlist file '{file_path}' does not exist.")
        return []
    with open(file_path, 'r') as f:
        return [
            line.strip() for line in f
            if line.strip() and not line.startswith("#")
        ]

def automated_login(username_field, username, password_field, password, login_url):
    """Attempts to log in using the provided credentials"""
    session = requests.Session()
    login_data = {
        username_field: username,
        password_field: password,
    }
    
    try:
        login_response = session.post(login_url, data=login_data, 
                                      allow_redirects=False, verify=False)    
        
        if login_response.status_code == 200:
            
            print("Login successful")
        elif login_response.status_code == 302:
            redirect_location = login_response.headers.get("Location", "")
            print(f"[+] Redirected to: {redirect_location}")
            if 'index.php' in redirect_location:
                print("[+] Login successful")
            else:
                print("[-] Login failed, continuing as unauthenticated user")
        else:
            print("Login failed")
        return session
            
    except requests.exceptions.RequestException as e:
        print(f"Error during login: {e}")
        return None

def fingerprint_site(session, url):
    try:
        response = session.get(url, timeout=10, verify=False)
        response.raise_for_status()
    except Exception as e:
        print(f"Error accessing {url}: {e}")
        return None

    # Analyze response headers
    headers = response.headers
    server_info = headers.get('Server', 'Unknown')
    x_powered_by = headers.get('X-Powered-By', 'Unknown')

    # Parse HTML content
    soup = BeautifulSoup(response.text, 'html.parser')
    meta_generator = soup.find('meta', attrs={'name': 'generator'})
    generator = meta_generator.get('content') if meta_generator else 'Unknown'

    # Basic CMS fingerprinting
    cms = "Unknown"
    content_lower = response.text.lower()
    if "wordpress" in content_lower or "wp-content" in content_lower:
        cms = "WordPress"
    elif "drupal" in content_lower or "sites/default" in content_lower:
        cms = "Drupal"
    elif "joomla" in content_lower:
        cms = "Joomla"
    elif "laravel" in content_lower or "csrf-token" in content_lower:
        cms = "Laravel"

    # Detect common JavaScript libraries
    js_libs = set()
    scripts = soup.find_all('script', src=True)
    for script in scripts:
        src = script['src'].lower()
        if "jquery" in src:
            js_libs.add("jQuery")
        if "angular" in src:
            js_libs.add("AngularJS")
        if "react" in src:
            js_libs.add("React")
        if "vue" in src:
            js_libs.add("Vue.js")

    return {
        'server': server_info,
        'x_powered_by': x_powered_by,
        'meta_generator': generator,
        'cms': cms,
        'js_libraries': list(js_libs),
    }

def extract_internal_links(session, html, current_url, base_netloc):
    soup = BeautifulSoup(html, 'html.parser')
    links = set()
    for tag in soup.find_all('a', href=True):
        href = tag['href']

        # Ignore Apache sorting query parameters
        if href.startswith("?C="):
            continue
        
        absolute_url = urljoin(current_url, href)
        parsed = urlparse(absolute_url)
        if parsed.netloc == base_netloc:
            clean_url = absolute_url.split('#')[0].rstrip('/')
            links.add(clean_url)
    return links

def check_special_interest(url, special_keywords, flagged_set, session):
    url_lower = url.lower()
    for kw in special_keywords:
        if kw.lower() in url_lower:
            flagged_set.add((url, kw))
            print(f"    [!] Potential interest: {url} (keyword: {kw})")

def check_directory_traversal(session, url, traversal_payloads, traversal_signatures):
    for payload in traversal_payloads:
        if not url.endswith('/'):
            test_url = url + '/' + payload
        else:
            test_url = url + payload

        try:
            r = session.get(test_url, timeout=10, verify=False)
            if r.status_code == 200 and any(sig in r.text for sig in traversal_signatures):
                print(f"    [!] Possible Directory Traversal found: {test_url}")
        except:
            pass

def test_param_injection(session, url, injection_payloads, injection_signatures):
    parsed = urlparse(url)
    if not parsed.query:
        return

    query_params = parse_qs(parsed.query)
    for param_name in query_params:
        for payload in injection_payloads:
            new_params = query_params.copy()
            new_params[param_name] = [payload]
            new_query = urlencode(new_params, doseq=True)
            new_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment
            ))
            try:
                r = session.get(new_url, timeout=10, verify=False)
                response_lower = r.text.lower()
                for sig in injection_signatures:
                    if sig.lower() in response_lower:
                        print(f"    [!] Potential Injection found: {new_url} (signature: {sig})")
            except:
                pass

def scan_word(session,
              current_url,
              word,
              special_interests,
              traversal_payloads,
              traversal_signatures):
    target_url = urljoin(current_url + '/', word.lstrip('/'))
    try:
        r = session.get(target_url, timeout=10, verify=False)
        if r.status_code in [200, 403, 401]:
            print(f"  Found: {target_url} (Status: {r.status_code})")
            flagged_set = set()
            check_special_interest(target_url, special_interests, flagged_set,session)
            check_directory_traversal(session, target_url, traversal_payloads, traversal_signatures)
            return (target_url, r.status_code, flagged_set)
    except Exception as e:
        print(f"Error scanning {target_url}: {e}")
    return (None, None, set())

def level_based_scan(userfield, 
                     username, 
                     passfield, 
                     password, 
                     login_url,
                     session,
                     base_url,
                     wordlist_files,
                     special_interests,
                     traversal_payloads,
                     traversal_signatures,
                     injection_payloads,
                     injection_signatures,
                     max_depth=3,
                     threads=5):
    # Combine wordlists
    words = set()
    for wl in wordlist_files:
        words.update(load_wordlist(wl))

    visited = set([base_url])
    flagged_interests = set()
    results = []
    current_level = [base_url]
    base_netloc = urlparse(base_url).netloc

    for depth in range(max_depth):
        if not current_level:
            break
        print(f"\n[Level {depth}] Scanning {len(current_level)} URLs ...")
        next_level = []

        for current_url in current_level:
            print(f"\nScanning: {current_url}")
            try:
                response = session.get(current_url, timeout=10, verify=False)
            except Exception as e:
                print(f"Error accessing {current_url}: {e}")
                continue

            # Add current URL to results if it returns a valid status.
            if response.status_code in [200, 403, 401]:
                if not any(r[0] == current_url for r in results):
                    results.append((current_url, response.status_code))

            # For non-base pages, print additional info and perform checks.
            if current_url != base_url:
                print(f"  -> Discovered Page: {current_url} (Status: {response.status_code})")
                if response.status_code in [200, 403, 401]:
                    check_special_interest(current_url, special_interests, flagged_interests)
                    check_directory_traversal(session, current_url, traversal_payloads, traversal_signatures)

            if response.status_code in [200, 403, 401]:
                # Parameter injection checks.
                test_param_injection(session, current_url, injection_payloads, injection_signatures)

                # Extract internal links.
                internal_links = extract_internal_links(session, response.text, current_url, base_netloc)
                for link in internal_links:
                    if link not in visited:
                        print(f"  -> Discovered Page: {link}")
                        visited.add(link)
                        if max_depth == 1:
                            # For depth 1, immediately scan and add the discovered page.
                            try:
                                r = session.get(link, timeout=10, verify=False)
                                print(f"    -> Scanned Discovered Page: {link} (Status: {r.status_code})")
                                results.append((link, r.status_code))
                            except Exception as e:
                                print(f"Error accessing {link}: {e}")
                                results.append((link, None))
                        else:
                            # For deeper scans, queue the link for further processing.
                            next_level.append(link)

                # Concurrently probe directories.
                with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                    future_to_word = {
                        executor.submit(
                            scan_word,
                            session,
                            current_url,
                            word,
                            special_interests,
                            traversal_payloads,
                            traversal_signatures,
                        ): word
                        for word in words
                    }
                    for future in concurrent.futures.as_completed(future_to_word):
                        found_url, status_code, flagged_set = future.result()
                        if found_url and found_url not in visited:
                            visited.add(found_url)
                            results.append((found_url, status_code))
                            flagged_interests.update(flagged_set)
                            if max_depth != 1:
                                next_level.append(found_url)

        current_level = list(set(next_level))
    print(session.cookies.get_dict())
    check_idor(results, session, flagged_interests, userfield, username, passfield, password, login_url)

    return results, flagged_interests

def check_idor(links, session, flagged_set, userfield, username, passfield, password, login_url):
    """
    1. Perform a get request with your own parameter and capture the length
    2. Perform a get request with a non existent parameter and capture the length
    3. Now do ?*=x++ and check for length difference
    """
    urls = set()
    # print(f'BEFORE LOGIN: {session.cookies.get_dict()}')

    for link in links:
        if re.search(IDOR, link[0]):
            urls.add(link[0])
    print(f"\n[===== IDOR Scans =====]")
    idor_links = get_idor(list(urls))

    # Check if it's an autenticated or unauthenticated idor scan first!
    if userfield:
        session = automated_login(userfield, username, passfield, password, login_url)
    # print(f'AFTER LOGIN: {session.cookies.get_dict()}')

    for url in idor_links:
        print(f"\nScanning: {url}")
        sizes = {}
        # place_holder = f'{url.split('=')[0]}?'
        r = session.get(url, timeout=10, verify=False)
        sizes['yours'] = len(r.text)
        r = session.get(url.split('=')[0] + "=098322", timeout=10, verify=False)
        sizes['nonexistent'] = len(r.text)
        skidibi(url, "IDOR", session, flagged_set, sizes)

def skidibi(url, keyword, session, flagged_set, sizes, iterations=24):
    """
    data types
    url: string
    keyword: string
    session: requests.Session
    flagged_set: set
    sizes: dictionary
    iterations: int
    """
    for attempt in range(iterations):
        r = session.get(url.split('=')[0] + f"={attempt}", timeout=10, verify=False)
        sizes[attempt] = len(r.text)
        if len(r.text) != sizes['nonexistent'] and len(r.text) != sizes['yours']:
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

def forced_browsing(session, url):
    """ False-positive prone test for forced browsing
        since it is reliant on status codes. """
    r = session.get(url, timeout=10, verify=False)
    if r.status_code == 200:
        print(f"\nBroken access control in admin-protected portal: {url}")
    elif r.status_code == 404:
        print(f"\nPage ({url}) does not exist")
    else:
        print(f"\nAccess control appears to be working: {url}")

def challenge_api(session, api_endpoints):
    for test in api_endpoints:    
        try:
            response = session.get(test, timeout=10, verify=False)
            print(f"[+] Testing API: {test}     (Status: {response.status_code})")
        except requests.exceptions.RequestException as e:
            print(f"[!] Error: {e}")

def test_api_endpoints(session, api_links, found_queries):
    api_links_to_test = []
    for api in api_links:
        for query in found_queries:
            full_api_url = f"{api}/?{query}"
            try:
                response = session.get(full_api_url, timeout=10, verify=False)
                print(f"[+] Testing API: {full_api_url}     (Status: {response.status_code})")
                if response.status_code == 200:
                    api_links_to_test.append(full_api_url)
                    print(f"    [!] Potential API query: {query}")
            except requests.exceptions.RequestException as e:
                print(f"    [!] Error: {e}")
    return api_links_to_test

def get_arguments():
    parser = argparse.ArgumentParser(
        description="---",
        usage="python main.py target [-u field:username] [-p field:password] [--auth login_page]"
    )
    parser.add_argument('target', type=str, help='Hostname or IP address')
    parser.add_argument('-u', '--username', type=str, help='Username field and value (e.g., email:steve@email.com)')
    parser.add_argument('-p', '--password', type=str, help='Password field and value (e.g., pwd:steve)')
    parser.add_argument('--auth', type=str, help='Authentication endpoint (e.g., process_login.php)')
    parser.add_argument("-d", "--depth", default=1, type=int, help="Max scanning depth (default: 1)")
    parser.add_argument("-t", "--threads", default=5, type=int, help="Number of threads (default: 5)")
    return parser.parse_args()

def main():
    print_banner()
    args = get_arguments()
    session = None 
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    userfield, username, passfield, password, login_url = None, None, None, None, None
    # Optional login
    if args.username and args.password and args.auth:
        try:
            userfield, username = args.username.split(':')
            passfield, password = args.password.split(':')
        except ValueError:
            print("[-] Incorrect format for username or password. Use: -u email:steve@email.com -p pwd:steve")
            return
        login_url = f"{args.target}/{args.auth}"
        session = automated_login(userfield, username, passfield, password, login_url)
        
        if session is None:
            print("[-] Automated login failed.")
            return
    else:
        print("[*] No login credentials provided. Proceeding with unauthenticated scan.")
        session = requests.Session()

    print(f"[*] Captured Session: {session.cookies.get_dict()}")
    
    base_url = args.target.rstrip("/")
    max_depth = args.depth
    threads = args.threads

    # Fingerprint
    fp_result = fingerprint_site(session, base_url)
    print("\n[===== Directory Traversal scans & crawling =====]")
    if fp_result:
        print("[+] Fingerprinting Results:")
        for key, value in fp_result.items():
            print(f"    {key}: {value}")
    else:
        print("Fingerprinting failed or site unreachable. Exiting...")
        return

    # Wordlists
    wordlist_files = ["wordlists/default.txt"]
    cms = fp_result.get("cms", "Unknown")
    if cms != "Unknown":
        cms_wordlist = f"wordlists/{cms.lower()}.txt"
        if os.path.exists(cms_wordlist):
            print(f"\n[+] CMS-specific wordlist found for {cms}: {cms_wordlist}")
            wordlist_files.append(cms_wordlist)

    # Special interests
    special_interests = load_wordlist("wordlists/special_interests.txt")

    # Directory traversal
    traversal_payloads = load_wordlist("wordlists/traversal_payloads.txt")
    traversal_signatures = load_wordlist("wordlists/traversal_signatures.txt")

    # Injection (SQLi/LFI/etc.)
    injection_payloads = load_wordlist("wordlists/injection_payloads.txt")
    injection_signatures = load_wordlist("wordlists/injection_signatures.txt")

    found_results, flagged = level_based_scan(
        userfield, 
        username, 
        passfield, 
        password, 
        login_url,
        session=session,
        base_url=base_url,
        wordlist_files=wordlist_files,
        special_interests=special_interests,
        traversal_payloads=traversal_payloads,
        traversal_signatures=traversal_signatures,
        injection_payloads=injection_payloads,
        injection_signatures=injection_signatures,
        max_depth=max_depth,
        threads=threads,
    )

    print("\n[+] Scan Completed.")
    print("\nValid Directories/Pages Found:")
    if found_results:
        for url_found, status in found_results:
            print(f"    {url_found} - Status: {status}")
    else:
        print("    None.")

    print("\nPotentially Interesting URLs (based on keywords):")
    if flagged:
        for (url, keyword) in flagged:
            print(f"    {url} (keyword: {keyword})")
    else:
        print("    None.")
    
    # Forced browsing
    while True:
        forced_browsing_input = input("\nTest forced browsing? (Default [N]): ").strip().lower()
        if forced_browsing_input == 'y':
            page = input("\nEnter the page to test for forced browsing (e.g., admin.php): ").strip()
            if page:
                forced_browsing(session, urljoin(base_url, page))
            break
        else:
            break

    # API endpoint testing
    if any("api" in url.lower() for url, _ in flagged):
        while True:
            api_input = input("\nTest for vulnerable API endpoint? (Default [N]): ").strip().lower()
            if api_input == 'y':

                ### Can be improved - make session persistent ###
                if args.username is None:
                    session = requests.Session()
                else:
                    session = automated_login(userfield, username, passfield, password, login_url)
                #################################################
                
                flagged_api = {item for item in flagged if "api" in item[0].lower()}
                
                for links in flagged_api:
                    url = links[0]
                    links2 = extract_internal_links(session, session.get(url, timeout=10, verify=False).text, url, urlparse(url).netloc)
                api_links = set()

                for links in links2:
                    parsed = urlparse(links)
                    if parsed.path != '':
                        api_url = urljoin(url + "/", parsed.path.lstrip("/"))
                        api_links.add(api_url)

                for api in api_links:
                    print(f"[!] Potential API endpoint: {api}")

                found_queries = set()
                for link, _ in found_results:
                    parsed_url = urlparse(link)
                    if parsed_url.query:
                        found_queries.add(parsed_url.query)

                ### Can be improved - make session persistent ###
                if args.username is None:
                    session = requests.Session()
                else:
                    session = automated_login(userfield, username, passfield, password, login_url)
                #################################################

                api_endpoints = test_api_endpoints(session, api_links, found_queries)
                if not api_endpoints:
                    print("[-] No potential API endpoints found.")
                    break

                api_input2 = input("\nEnter another valid credential to test for Weak API controls? (Default [N]): ").strip().lower()
                if api_input2 == 'y':
                    username2 = input("\nEnter the username: ").strip()
                    password2 = input("Enter the password: ").strip()

                    if args.username is None:
                        login_url = input("Enter the authentication endpoint: ").strip()
                        login_url = f"{args.target}/{login_url}"
                        print(login_url)
                        try:
                            userfield, username = username2.split(':')
                            passfield, password = password2.split(':')
                        except ValueError:
                            print("[-] Incorrect format for username or password. Use: -u email:steve@email.com -p pwd:steve")
                            return
                        print(userfield, username, passfield, password)

                    session = automated_login(userfield, username2, passfield, password2, login_url)
                    print(f"\nInvoking API with account: {username2}...\n")
                    
                    challenge_api(session, api_endpoints)
                    print(f"\nInvoking API with unauthenticated session...\n")
                    for endpoints in api_endpoints:
                        print(f"[+] Testing API: {endpoints}    (Status: {requests.get(endpoints, timeout=10, verify=False).status_code})")
                
                api_idor = input("\nTest for IDOR in API endpoints? (Default [N]): ").strip().lower()
                if api_idor == 'y':
                    api_idor_set = set()
                    for endpoints in api_endpoints:
                        lhs, _ = endpoints.split("?")
                        a = session.get(lhs, timeout=10, verify=False)
                        print(a.text)

                        # api_idor_set.add(lhs)
                    


            else:
                break
    session.close()



if __name__ == "__main__":
    main()
