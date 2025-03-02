<h1>BROKENAXE</h1>
<h3>Broken Access Control vulnerability definition</h3>
<p>1. Directory & Heuristics scanning<br>
2. Forced Browsing<br>
3. Insecure Direct Object Reference IDOR<br>
4. API-IDOR<br>
5. Weak API controls - unauthenticated<br>
6. Weak API controls - authenticated<br>
7. Session management<br></p>

<p>How to DEMONSTRATE: create a BAC-vulnerable website<br>
How to IDENTIFY: create tool to determine vulnerability<br>
How to DISPLAY: generate VAPT report according to findings
</p>

<h3>Methodology of approach:</h3>
<p>Scan website<br>
Raise possible vectors according to heuristics <br>
Based on scan findings, run IDOR checks against it<br>
Upon IDOR checks, test for Session Management weaknesses with reference to the scan findings<br>
Forced browsing can be tested to see if user has access to the provided admin-protected portal<br>
API testing will come after. Based on scan findings, URLs with queries present will be extracted and tested against API endpoints; typically /api/, /v1/, /v2/ etc.<br>
Findings will be collated into a dictionary for report generation<br>
</p>

<h1>User Manual</h1>
python main.py https://<b>WEBPAGE_URL</b>/ -u <b>USERNAME_PARAMETER</b>:<b>USERNAME_VALUE</b> <b>PASSWORD_PARAMETER</b>:<b>PASSWORD_VALUE</b> --auth <b>LOGIN_ENDPOINT</b> (.php etc)

e.g. python main.py https://35.212.180.132/ -u email:webadministrator@ferriswheelweb.com -p pwd:admin! --auth process_login.php

Available commands:
-
target: Hostname or IP address [<b>MANDATORY</b>]<br>
-u, --username: Username field and value (e.g.) email:steve@email.com<br>
-p, --password: Password field and value (e.g.) pwd:steve<br>
--additional: Additional parameters to be passed to the login page<br>
--auth: Authentication endpoint (e.g. process_login.php)<br>
-d, --depth: Max scanning depth (default: 1)<br>
-t, --threads: Number of threads (default: 5)<br>

Usecase flow
-
<b>Directory & Heuristic Scan</b><br>
Directory & Heuristic scans will be executed...

<p><b>Session Management</b><br>
Test for session replay (Default: N): <br>
Enter username (optional): steve@email.com<br>
Enter password (optional): steve<br>

<h3>For Session management, User can choose to conduct the session replay attacks or not. Additionally, user may supply credentials to enhance testing phase to check for credential-protected portals<br></h3>

<h3>BrokenAxe will generate a list of URLs available for testing, if requested<br></h3>
BrokenAxe to provide a list to test?: (User can specify Y/N)<br>
URL                                                         Expected Code  Actual Code<br>
https://35.212.180.132/logout.php                           200            302<br>
https://35.212.180.132/transaction_history.php              200            302<br>
https://35.212.180.132/new_listing.php                      200            302<br>
https://35.212.180.132/shopping_cart.php?user_id=19         200            302<br>
https://35.212.180.132/console.php                          200            302<br>
https://35.212.180.132/uploads                              200            301<br>
https://35.212.180.132/api                                  200            301<br>
Attempt on https://35.212.180.132/logout.php ? (Default [N]): N
<h3>User can put N, to select any other links provided within the URLs provided<br></h3>



Enter protected page (required): https://35.212.180.132/console.php<br>
[ ] Captured Session: {'PHPSESSID': '71tqijie10jhb2nlhph3tjtuk7'}<br>
[ ] Successfully logged in as new user. Session cookies: {'PHPSESSID': '392ebtl27t4k163eor75mm7s40'}<br>
[ ] Changed cookies to captured cookies: {'PHPSESSID': '71tqijie10jhb2nlhph3tjtuk7'}<br>
[ ] Session replay attack successful! unatuhorised access to page detected.<br>

<p><b>Forced Browsing</b><br>
Test forced browsing? (Default [N]): y<br>
Enter the page to test for forced browsing (e.g., admin.php): console.php<br>
Forced browsing to admin-protected portal: https://35.212.180.132/console.php<br>

<p><b>API Testing</b><br>
Test for vulnerable API endpoints? (Default [N]): (User can state Y/N)<br>
<h3>Scanning for API endpoints will be executed...<br></h3>
Test for Weak API controls? (Default [N]): (User can state Y/N)<br>
Enter the username (optional): steve@email.com<br>
Enter the password (optional): steve<br>

Invoking API with account: steve@email.com...<br>

[+] Testing API: https://35.212.180.132/api/profile/?account_id=19     (Status: 200)<br>
[+] Testing API: https://35.212.180.132/api/cart/?user_id=19     (Status: 200)<br>

Invoking API with unauthenticated session...<br>

[+] Testing API: https://35.212.180.132/api/profile/?account_id=19    (Status: 401)<br>
[+] Testing API: https://35.212.180.132/api/cart/?user_id=19    (Status: 401)<br>

Test for IDOR in API endpoints? (Default [N]): y<br>
    [!] Potential api-idor found: https://35.212.180.132/api/profile/?account_id=2<br>
    [!] Potential api-idor found: https://35.212.180.132/api/profile/?account_id=3<br>
    [!] Potential api-idor found: https://35.212.180.132/api/profile/?account_id=4<br>
    [!] Potential api-idor found: https://35.212.180.132/api/profile/?account_id=6<br>
    [!] Potential api-idor found: https://35.212.180.132/api/profile/?account_id=8<br>
    [!] Potential api-idor found: https://35.212.180.132/api/profile/?account_id=9<br>
    [!] Potential api-idor found: https://35.212.180.132/api/profile/?account_id=20<br>
    [!] Potential api-idor found: https://35.212.180.132/api/profile/?account_id=21<br>
    [!] Potential api-idor found: https://35.212.180.132/api/cart/?user_id=2<br>
    [!] Potential api-idor found: https://35.212.180.132/api/cart/?user_id=9<br>
    [!] Potential api-idor found: https://35.212.180.132/api/cart/?user_id=20<br>

<p><b>Report Generation</b><br>
PDF report generated: vapt_report.pdf<br>
