import argparse
import requests
import threading

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
    parser = argparse.ArgumentParser(description='Description: We check for BAC because we got your back')
    parser.add_argument('target', type=str, help='hostname or ip address (omit http://)')     # COPY AND PASTE ME TO ADD MORE ARGUMENTS :)
    args = parser.parse_args()
    return args

def bustee(target):
    """
    This function is the busting one. 
    """
    #print(f'[*] We are attacking: http://{target} (not recursive)')
    print(f'[*] This one testing phase so we attack: https://juice-shop.herokuapp.com/#/ (hardcoded)')

    x = requests.get('http://')
    print(x.status_code)

def main():
    print_banner()
    args = get_arguments()

    bustee(args.target)

if __name__ == '__main__':
    main()