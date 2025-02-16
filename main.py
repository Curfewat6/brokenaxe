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
    parser.add_argument('--login_page', type=str, help='Page for Login (e.g. login.php)')
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
        login_response = session.post(login_url, data=login_data) # Send the POST request, not sure if need verify=False
        login_response.raise_for_status()   # Raise an exception if the status code is not 200
    except requests.exceptions.RequestException as e:
        print(f"Error during login: {e}")
        return None
    
    # Step 2: Check if login was successful by examining the status code
    if login_response.status_code == 200:
        print("[+] Login successful!")
        return login_response.status_code
    else:
        print(f"[-] Login failed. Status code: {login_response.status_code}")
        return None
        

def main():
    """
    python main.py x.x.x.x blah (for testing)
    """
    print_banner()  
    args = get_arguments()  # Get arguments
    
    # Check if login credentials and page are provided
    if args.username and args.password and args.login_page:
        # Construct the full login URL by appending the login page to the target
        login_url = f"http://{args.target}/{args.login_page}"
    
        # Perform automated login
        status_code = automated_login(args.username, args.password, login_url)
        if status_code != 200:
            print("[-] Automated login failed.")
            
    else:
        print("[*] No login credentials provided. Proceeding with unauthenticated scan.")
        # session = None


    directories = wordlist_to_list()    # Fetch the wordlist
    bustee(args.target, directories)    # The actual gobuster

if __name__ == '__main__':
    main()
