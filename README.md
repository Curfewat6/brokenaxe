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
</p>




