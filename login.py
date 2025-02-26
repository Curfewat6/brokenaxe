import requests

def automated_login(username_field, username, password_field, password, additonal, login_url):
    """ Attempts to log in using the provided credentials """
    session = requests.Session()
    login_data = {
        username_field: username,
        password_field: password,
        "log": "Login"
    }
    
    try:
        login_response = session.post(login_url, data=login_data, 
                                      allow_redirects=False, verify=False)    
        
        if login_response.status_code == 200:
            print("Login successful")
        elif login_response.status_code == 302:
            redirect_location = login_response.headers.get("Location", "")
            print(f"[+] Redirected to: {redirect_location}")
            if 'admin.php' in redirect_location:
                print("[+] Login successful")
            else:
                print("[-] Login failed, continuing as unauthenticated user")
        else:
            print("Login failed")
        return session
            
    except requests.exceptions.RequestException as e:
        print(f"Error during login: {e}")
        return None