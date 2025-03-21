import requests

first_time = True

def automated_login(username_field, username, password_field, password, login_url, additional=None):
    
    global first_time
    
    """ Attempts to log in using the provided credentials """
    session = requests.Session()
    login_data = {
        username_field: username,
        password_field: password
    }
    if additional:
        for field in additional:
            item = field.split(':')
            login_data[item[0]] = item[1]
            
    try:
        login_response = session.post(login_url, data=login_data, 
                                      allow_redirects=False, verify=False)    
        
        if first_time:
            if login_response.status_code == 200:
                print(" [+] Login successful")
            elif login_response.status_code == 302:
                redirect_location = login_response.headers.get("Location", "")
                print(f"[+] Redirected to: {redirect_location}")

                # User have to change this part according to the application they are testing due to the different ways of handling login/behaviours
                if 'index.php' in redirect_location:
                    print("[+] Login successful")
                else:
                    print("[-] Login failed, continuing as unauthenticated user")
            else:
                print("[-] Login failed")
                
        first_time = False
        
        return session
            
    except requests.exceptions.RequestException as e:
        print(f"Error during login: {e}")
        return None
    
# def main():
#     print("This script is ran as a test")
#     automated_login("username", "steve", "password", 'steve', "https://labs.hackxpert.com/IDOR/IDOR1/login.php",  ['log:Login'])

# if __name__ == '__main__':
#     main()
