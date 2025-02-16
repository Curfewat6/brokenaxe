import argparse
import requests
import urllib3

def print_banner():
    try:
        with open('axe.txt', 'r') as banner:
            print(banner.read())
            print()
    except FileNotFoundError:
        print('[!] Banner not found\n')
    
    except UnicodeDecodeError:
        print('[!] Error decoding banner\n')
    
def get_arguments():
    """
    This function can help us get arguments
    """
    parser = argparse.ArgumentParser(
        description="---",
        usage="python main.py target wordlist [-u field:username] [-p field:password] [--auth login_page]"
    )
    parser.add_argument('target', type=str, help='Hostname or IP address')
    parser.add_argument('wordlist', type=str, help='Wordlist file path')
    parser.add_argument('-u', '--username', type=str, help='Username field and value (e.g, email:steve@email.com)')
    parser.add_argument('-p', '--password', type=str, help='Password field and value (e.g, pwd:steve)')
    parser.add_argument('--auth', type=str, help='Authentication endpoint (e.g., process_login.php)')
    args = parser.parse_args()
    return args

def wordlist_to_list(wordlist):
    """Reads the wordlist file and returns a list of directories."""
    with open(wordlist, 'r') as file:
        lines = file.readlines()
    return [line.strip() for line in lines]

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
            print("Login successful!")
        elif login_response.status_code == 302:
            redirect_location = login_response.headers.get("Location", "")
            print(f"[+] Redirected to: {redirect_location}")
            if 'index.php' in redirect_location:
                print("[+] Login successful!")
        else:
            print("Login failed!")
        return session
            
    except requests.exceptions.RequestException as e:
        print(f"Error during login: {e}")
        return None

def main():
    """Main execution function"""
    args = get_arguments()
    session = None 

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    if args.username and args.password and args.auth:
        try:
            userfield, username = args.username.split(':')
            passfield, password = args.password.split(':')
        except ValueError:
            print("[-] Incorrect format for username or password. Use format: -u email:steve@email.com -p pwd:steve")
            return
        
        login_url = f"{args.target}/{args.auth}"
        print(login_url)
    
        session = automated_login(userfield, username, passfield, password, login_url)
        if session is None:
            print("[-] Automated login failed.")
            return   
    else:
        print("[*] No login credentials provided. Proceeding with unauthenticated scan.")
    
    print(f"[*] Captured Session: {session}")


if __name__ == '__main__':
    main()
