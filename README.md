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

<h3>User Manual</h3>
python main.py https:///webpage/ -u <username_parameter>:<username_value> <password_parameter>:<password_value> --auth <login_endpoint (.php etc)>
e.g. python main.py https://35.212.180.132/ -u email:webadministrator@ferriswheelweb.com -p pwd:admin! --auth process_login.php

Directory & Heuristic scans will be executed...

Test for session replay: (User can specify Y/N)
Enter username (optional): steve@email.com
Enter password (optional): steve
BrokenAxe to provide a list to test?: (User can specify Y/N)

BrokenAxe will generate a list of URLs available for testing:
**URL                                                         Expected Code  Actual Code
------------------------------------------------------------------------------------------**
https://35.212.180.132/logout.php                           200            302
https://35.212.180.132/transaction_history.php              200            302
https://35.212.180.132/new_listing.php                      200            302
https://35.212.180.132/shopping_cart.php?user_id=19         200            302
https://35.212.180.132/console.php                          200            302
https://35.212.180.132/uploads                              200            301
https://35.212.180.132/api                                  200            301
Attempt on https://35.212.180.132/logout.php ? (Default [N]): (User can put N, to select any other links provided within the URLs provided)

Enter protected page (required): https://35.212.180.132/console.php
[*] Captured Session: {'PHPSESSID': '71tqijie10jhb2nlhph3tjtuk7'}
[*] Successfully logged in as new user. Session cookies: {'PHPSESSID': '392ebtl27t4k163eor75mm7s40'}
[+] Changed cookies to captured cookies: {'PHPSESSID': '71tqijie10jhb2nlhph3tjtuk7'}
[!] Session replay attack successful! unatuhorised access to page detected.

Test forced browsing? (Default [N]): y
Enter the page to test for forced browsing (e.g., admin.php): console.php
Forced browsing to admin-protected portal: https://35.212.180.132/console.php

Test for vulnerable API endpoints? (Default [N]): (User can state Y/N)
Scanning for API endpoints will be executed...
Test for Weak API controls? (Default [N]): (User can state Y/N)
Enter the username (optional): steve@email.com
Enter the password (optional): steve

Invoking API with account: steve@email.com...

[+] Testing API: https://35.212.180.132/api/profile/?account_id=19     (Status: 200)
[+] Testing API: https://35.212.180.132/api/cart/?user_id=19     (Status: 200)

Invoking API with unauthenticated session...

[+] Testing API: https://35.212.180.132/api/profile/?account_id=19    (Status: 401)
[+] Testing API: https://35.212.180.132/api/cart/?user_id=19    (Status: 401)

Test for IDOR in API endpoints? (Default [N]): y
    [!] Potential api-idor found: https://35.212.180.132/api/profile/?account_id=2
    [!] Potential api-idor found: https://35.212.180.132/api/profile/?account_id=3
    [!] Potential api-idor found: https://35.212.180.132/api/profile/?account_id=4
    [!] Potential api-idor found: https://35.212.180.132/api/profile/?account_id=6
    [!] Potential api-idor found: https://35.212.180.132/api/profile/?account_id=8
    [!] Potential api-idor found: https://35.212.180.132/api/profile/?account_id=9
    [!] Potential api-idor found: https://35.212.180.132/api/profile/?account_id=20
    [!] Potential api-idor found: https://35.212.180.132/api/profile/?account_id=21
    [!] Potential api-idor found: https://35.212.180.132/api/cart/?user_id=2
    [!] Potential api-idor found: https://35.212.180.132/api/cart/?user_id=9
    [!] Potential api-idor found: https://35.212.180.132/api/cart/?user_id=20
[===== Report generation =====]

PDF report generated: vapt_report.pdf
