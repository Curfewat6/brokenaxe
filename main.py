import argparse

def get_arguments():
    parser = argparse.ArgumentParser(description='We check for BAC because we got your back')
    parser.add_argument('something', type=str, help='This can be anything')
    args = parser.parse_args()
    return args

def main():
    args = get_arguments()
    
    print(args.something) # print argument

if __name__ == '__main__':
    main()