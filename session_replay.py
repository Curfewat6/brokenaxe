import requests
from login import automated_login
from urllib.parse import urlparse
from report_gen import add_to_results, report_results
import time
from bs4 import BeautifulSoup

def attempt_session_replay_without_account(logged_in_cookies, protected_page):
    print(f"[*] No Credentials or Invalid Credentials received. Proceeding with test without account login")
    # Establish a session & set cookies as the user we want to test with
    session = requests.Session()
    session.cookies.update(logged_in_cookies)
    updated_testing_cookies = session.cookies.get_dict()
    print(f"[+] Established session with captured cookies: {updated_testing_cookies}")
    
    # try and access the protected pages
    response = session.get(protected_page, verify=False, allow_redirects=False)

    # determine whether successful or not based on status code
    if response.status_code == 200:
        print("[!] Session replay attack successful! unatuhorised access to page detected.")
    else:
        print(f"[-] Session replay attack failed. Status code: {response.status_code}")
        print(f"Redirect location: {response.headers.get('Location')}")

def attempt_session_replay(logged_in_cookies, protected_page, username_field, username, password_field, password, login_url):
    # user automated_login to create a session 
    testing_session = automated_login(username_field, username, password_field, password, login_url)
    if testing_session:
        testing_cookies = testing_session.cookies.get_dict()
 
        if testing_cookies:
            print(f"[*] Successfully logged in as new user. Session cookies: {testing_cookies}")
 
            # extract the ip address
            parsed_url = urlparse(login_url)
            ip_address = parsed_url.hostname 

            # Replace the normal user's cookies using the cookies we want to test with
            for cookie in list(testing_session.cookies):
                if cookie.name == 'PHPSESSID':
                    testing_session.cookies.clear(cookie.domain, cookie.path, cookie.name)

            # Now update with the new cookies
            testing_session.cookies.update(logged_in_cookies)
            updated_testing_cookies = testing_session.cookies.get_dict()
            print(f"[+] Changed cookies to captured cookies: {updated_testing_cookies}")
 
            # Attempt to access protected page (only for logged in user or for admin-only page)
            response = testing_session.get(protected_page, verify=False, allow_redirects=False)
 
            if response.status_code == 200:
                add_to_results((protected_page, "session management"))
                print("[!] Session replay attack successful! unatuhorised access to page detected.")
            else:
                print(f"[-] Session replay attack failed. Status code: {response.status_code}")
                print(f"Redirect location: {response.headers.get('Location')}")
        else:
            print("[-]Login failed: No session ID received.")
    else:
        print("[-] Automated login failed. Proceeding to replay attack using only provided session ID.")
        attempt_session_replay_without_account(logged_in_cookies,protected_page)


def find_protected_page(found_results, username_field=None, username=None, password_field=None, password=None, login_url=None):
    all_provided = None not in (username_field, username, password_field, password, login_url)
    # print("All provided: ", username_field, username, password_field, password, login_url)
    # print("Found results: ", found_results)
    if all_provided:
        session2 = automated_login(username_field, username, password_field, password, login_url)
    else:
        session2 = requests.Session()

    differences = {} 
    time.sleep(2) # give the server time to update 

    for url, expected_code in found_results:
        try:
            response = session2.get(url, verify=False, allow_redirects=False, timeout=5)
            actual_code = response.status_code
        except requests.exceptions.RequestException as e:
            actual_code = f"Error: {e}"
        
        # Compare the expected response code with the actual response code for each URL
        if actual_code != expected_code:
            differences[url] = {'expected': expected_code, 'actual': actual_code}

    print_protected_page_result(differences)
    
    return differences

def print_protected_page_result(differences):
    print(f"{'URL':<60}{'Expected Code':<15}{'Actual Code':<15}")
    print("-" * 90)

    for url, codes in differences.items():
        expected_str = str(codes['expected'])
        actual_str = str(codes['actual'])
        print(f"{url:<60}{expected_str:<15}{actual_str:<15}")

