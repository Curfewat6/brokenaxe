import argparse
import requests

def print_banner():
    try:
        with open('axe.txt', 'r') as banner:
            print(banner.read())
            print() # echo new line cos it looks cooler
    except FileNotFoundError:
        print('[!] Banner not found')
        print()     # echo new line cos it looks cooler
    
    except UnicodeDecodeError:  # On my end i cannot print the banner so i put this
        print('[!] Error decoding banner')
        print()
    
def get_arguments():
    """
    This function can help us get arguments
    To add more arguments just copy that one line and change accordingly
    """
    parser = argparse.ArgumentParser(description='Description: We check for BAC because we got your back. For testing the wordlist can be any parameter. It will use the one that comes with this repo')
    parser.add_argument('target', type=str, help='hostname or ip address (omit http://)')     # COPY AND PASTE ME TO ADD MORE ARGUMENTS :)
    parser.add_argument('wordlist', type=str, help='full path of wordlist (rockyou.txt / seclists)')
    parser.add_argument('-u', '--username', type=str, help='Username for login')
    parser.add_argument('-p', '--password', type=str, help='Password for login')
    parser.add_argument('--auth', type=str, help='Authenticate User/Process Credentisal (e.g. process_login.php)')
    args = parser.parse_args()
    return args

def wordlist_to_list(wordlist='fake_dictionary.txt'):
    """
    This function takes in the wordlist file. Everyline in the wordlist will be an element in the list.
    Returns a list.
    """
    with open (wordlist, 'r') as file:
        lines = file.readlines()
    return [line.strip() for line in lines]

def bustee(target, directories):
    """
    This function is the busting one if can maybe add threads
    Target is hardcoded to the dvwa address for testing purposes
    """
    target = 'http://127.0.0.1:42001'
    #print(f'[*] We are attacking: http://{target} with wordlist {wordlist} (not recursive)')
    print(f'[*] This one testing so we attack: dvwa (hardcoded) with a sample wordlist')
    
    for directory in directories:
        attack = requests.get(f'{target}/{directory}')
        print(f'[*] {target}/{directory} (Status code: {attack.status_code})')
        
def automated_login(username, password, login_url):
    """
    This function will attempt to login to the website
    """
    # Create a session to handle cookies
    session = requests.Session()
    
    # Step 1: Submit the login form
    login_data = {
        'email': username,  # Form field for username
        'pwd': password,    # Form field for password
    }
    try:
        login_response = session.post(login_url, data=login_data, allow_redirects=False) # Send the POST request, not sure if need verify=False
        
        # Step 2: Check if a redirect (302) happens
        if login_response.status_code == 302:
            redirect_location = login_response.headers.get("Location", "")
            print(f"[+] Redirected to: {redirect_location}")
            
            if 'index.php' in redirect_location:
                print("[+] Login successful!")
                return session # Return the session object for further requests/Hold onto the session
            else:
                return None
            
    except requests.exceptions.RequestException as e:
        print(f"Error during login: {e}")
        return None

        

def main():
    """
    python main.py x.x.x.x blah (for testing)
    """
    print_banner()  
    args = get_arguments()  # Get arguments
    
    session = None    # Initialize session object
    
    # Check if login credentials and page are provided
    if args.username and args.password and args.auth:
        # Construct the full login URL by appending the login page to the target
        login_url = f"http://{args.target}/{args.auth}"
    
        # Perform automated login
        session = automated_login(args.username, args.password, login_url)
        if session is None:
            print("[-] Automated login failed.")
            
    else:
        print("[*] No login credentials provided. Proceeding with unauthenticated scan.")
        # session = None
        
    print(f"[*] Captured Session: {session}")


    directories = wordlist_to_list()    # Fetch the wordlist
    bustee(args.target, directories)    # The actual gobuster

if __name__ == '__main__':
    main()
