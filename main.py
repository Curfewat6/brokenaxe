import argparse

def print_banner():
    try:
        with open('axe.txt', 'r') as banner:
            print(banner.read())
            print() # echo new line cos it looks cooler
    except FileNotFoundError:
        print('[!] Banner not found')
        print()     # echo new line cos it looks cooler
    
def get_arguments():
    """
    This function can help us get arguments
    To add more arguments just copy that one line and change accordingly
    """
    parser = argparse.ArgumentParser(description='Description: We check for BAC because we got your back')
    parser.add_argument('something', type=str, help='This can be anything')     # COPY AND PASTE ME TO ADD MORE ARGUMENTS :)
    args = parser.parse_args()
    return args

def main():
    print_banner()
    args = get_arguments()

    print(args.something) # print argument

if __name__ == '__main__':
    main()