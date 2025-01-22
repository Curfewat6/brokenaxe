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

def main():
    """
    python main.py x.x.x.x blah (for testing)
    """
    print_banner()  
    args = get_arguments()  # Get arguments

    directories = wordlist_to_list()    # Fetch the wordlist
    bustee(args.target, directories)    # The actual gobuster

if __name__ == '__main__':
    main()