import colorama
from colorama import Fore, Style
import random

colorama.init(autoreset=True)

def print_banner():
    banner = r""" 
    ▀█████████▄  ▄████████  ▄██████▄    ▄█   ▄█▄  ▄████████ ███▄▄▄▄     ▄████████ ▀████    ▐████▀  ▄████████      
    ███    ███   ███    ███ ███    ███  ███ ▄███▀███    ███ ███▀▀▀██▄  ███    ███   ███▌   ████▀  ███    ███      
    ███    ███   ███    ███ ███    ███  ███▐██▀  ███    █▀  ███   ███  ███    ███    ███  ▐███    ███    █▀       
    ▄███▄▄▄██▀ ▄███▄▄▄▄██▀ ███    ███ ▄█████▀   ▄███▄▄▄     ███   ███  ███    ███    ▀███▄███▀   ▄███▄▄▄          
    ▀▀███▀▀▀██▄▀▀██████▀▀   ███    ███▀▀█████▄  ▀▀███▀▀▀     ███   ███▀███████████    ████▀██▄   ▀▀███▀▀▀          
    ███    ██▄  ▀███▀▀▀██▄▄  ███    ███  ███▐██▄  ███    █▄  ███   ███  ███    ███   ▐███  ▀███    ███    █▄       
    ███    ███   ███    ███ ███    ███  ███ ▀███▄ ███    ███ ███   ███  ███    ███  ▄███     ███▄  ███    ███      
    ▄█████████▀  ███    ███  ▀██████▀   ███   ▀█▀ ██████████  ▀█   █▀   ███    █▀  ████       ███▄ ██████████  by @lucas
    """

    colored_lines = []
    for line in banner.splitlines():
        new_line = ""
        for char in line:
            if char != " " and random.random() < 0.2:
                new_line += f"{Fore.LIGHTRED_EX}{char}{Fore.RED}"
            else:
                new_line += char
        colored_lines.append(new_line)
    
    colored_banner = "\n".join(colored_lines)
    print(Fore.RED + colored_banner + Style.RESET_ALL)

