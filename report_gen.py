from fpdf import FPDF
from datetime import datetime

reported_results = []
sorted_results = {
    "Directory & Heuristic scanning": [],
    "Forced Browsing": [],
    "Insecure Direct Object Reference (IDOR)": [],
    "API-IDOR": [],
    "Weak API Controls - Unauthenticated": [],
    "Weak API Controls - Authenticated": [], 
    "Session Management": []
}

description = {
    "Directory & Heuristic scanning": (
        "Directory & Heuristic Scanning is a web vulnerability assessment technique combining forced browsing "
        "and intelligent content analysis. Forced browsing uses a wordlist to systematically identify hidden "
        "directories and files on a web server, exposing resources not directly linked or indexed. Meanwhile, "
        "heuristic scanning analyzes web pages, HTTP headers, meta tags, and scripts to detect technologies, "
        "misconfigurations, and vulnerabilities like injection flaws or insecure object references."
    ),
    "Forced Browsing": (
        "Forced Browsing is a web vulnerability assessment technique that systematically enumerates directories "
        "and files on a web server. By using a wordlist, an attacker can discover hidden resources not directly "
        "linked or indexed, potentially exposing sensitive information or vulnerable applications."
    ),
    "Insecure Direct Object Reference (IDOR)": (
        "Insecure Direct Object Reference (IDOR) is a web application vulnerability where an attacker can access "
        "unauthorized resources by manipulating object references. By changing parameters or URLs, an attacker can "
        "bypass access controls and view sensitive data or perform unauthorized actions."
    ),
    "API-IDOR": (
        "API Insecure Direct Object Reference (API-IDOR) is a vulnerability in an application programming interface "
        "(API) that allows attackers to access unauthorized resources by manipulating object references. By changing "
        "parameters or URLs, an attacker can bypass access controls and view sensitive data or perform unauthorized actions."
    ),
    "Weak API Controls - Unauthenticated": (
        "Weak API Controls - Unauthenticated refers to vulnerabilities in an application programming interface (API) "
        "that allow unauthorized access or actions without proper authentication. Attackers can exploit these weaknesses "
        "to access sensitive data or perform unauthorized operations."
    ),
    "Weak API Controls - Authenticated": (
        "Weak API Controls - Authenticated refers to vulnerabilities in an application programming interface (API) "
        "that allow unauthorized access or actions even after authentication. Attackers can exploit these weaknesses "
        "to access sensitive data or perform unauthorized operations."
    ),
    "Session Management": (
        "Session Management vulnerabilities can lead to unauthorized access, session hijacking, or session fixation attacks. "
        "Insecure session handling can expose user sessions to compromise, allowing attackers to impersonate users, access "
        "sensitive data, or perform unauthorized actions."
    )
}

def add_to_results(result):
    reported_results.append(result)

def report_results():
    for result in reported_results:
        if result[1] == "forced-browsing":
            sorted_results["Forced Browsing"].append(result)
        elif result[1] == "idor":
            sorted_results["Insecure Direct Object Reference (IDOR)"].append(result)
        elif result[1] == "api-idor":
            sorted_results["API-IDOR"].append(result)
        elif result[1] == "weak API controls - unauthenticated":
            sorted_results["Weak API Controls - Unauthenticated"].append(result)
        elif result[1] == "weak API controls - authenticated":
            sorted_results["Weak API Controls - Authenticated"].append(result)
        elif result[1] == "session management":
            sorted_results["Session Management"].append(result)
        else:
            sorted_results["Directory & Heuristic scanning"].append(result)
    return sorted_results

class PDF(FPDF):
    def header(self):
        # Header with the report title
        self.set_font("Arial", "B", 16)
        self.cell(0, 10, "VAPT Report - BrokenAXE", ln=True, align="C")
        self.ln(5)

    def footer(self):
        # Footer with page numbers
        self.set_y(-15)
        self.set_font("Arial", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

def add_section(pdf, title, desc, findings):
    """
    Adds a section to the PDF for a given vulnerability category.
    Displays the section title, then the description (if available), followed by the findings.
    Each finding is expected to be a tuple, e.g., (url, result), or a string.
    """
    # Print section title
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, title, ln=True)
    pdf.ln(2)
    
    # Print description in normal font, if provided
    if desc:
        pdf.set_font("Arial", "", 12)
        pdf.multi_cell(0, 6, desc)
        pdf.ln(6)
    
    # Print findings
    pdf.set_font("Arial", "", 12)
    if not findings:
        pdf.cell(0, 10, "No findings reported.", ln=True)
    else:
        for idx, finding in enumerate(findings, start=1):
            if isinstance(finding, tuple):
                if len(finding) == 2:
                    url, result = finding
                    pdf.cell(0, 6, f"{idx}. URL: {url} - Result: {result}", ln=True)
                else:
                    pdf.cell(0, 6, f"{idx}. {finding}", ln=True)
            else:
                pdf.cell(0, 6, f"{idx}. {finding}", ln=True)
            pdf.ln(1)
    pdf.ln(5)

def add_remediation_section(pdf, sorted_results):
    """
    Adds the remediation section to the PDF report with recommendations
    ONLY for the vulnerabilities that were discovered on the target.
    Each remediation header is printed in bold.
    """
    # Define remediation guidelines for each category.
    # Each guideline is a multi-line string where the first line is the header.
    remediation_guidelines = {
        "Directory & Heuristic scanning": (
            "Directory & Heuristic Scanning / Forced Browsing:\n"
            "- Harden server configurations by disabling directory listings and removing unnecessary files.\n"
            "- Implement strict access controls on directories and files to restrict unauthorized access.\n"
            "- Deploy a Web Application Firewall (WAF) to monitor and block malicious requests."
        ),
        "Forced Browsing": (
            "Forced Browsing:\n"
            "- Prevent direct access to sensitive files by properly configuring web server rules.\n"
            "- Use authentication and authorization controls to restrict access to hidden resources.\n"
            "- Regularly review and remove unnecessary files or backup directories from the web server."
        ),
        "Insecure Direct Object Reference (IDOR)": (
            "Insecure Direct Object Reference (IDOR):\n"
            "- Enforce robust authorization checks to ensure users access only permitted resources.\n"
            "- Replace direct object references with indirect tokens that do not expose internal IDs.\n"
            "- Conduct regular security audits to validate access controls."
        ),
        "API-IDOR": (
            "API Insecure Direct Object Reference (API-IDOR):\n"
            "- Implement strict authentication and authorization checks on API endpoints.\n"
            "- Ensure API responses do not expose sensitive or predictable object references.\n"
            "- Validate user access for each API request to prevent unauthorized data exposure."
        ),
        "Weak API Controls - Unauthenticated": (
            "Weak API Controls - Unauthenticated:\n"
            "- Require authentication for all sensitive API endpoints.\n"
            "- Implement strong access control measures and enforce API rate limiting.\n"
            "- Validate all API requests to prevent data leaks or unauthorized operations."
        ),
        "Weak API Controls - Authenticated": (
            "Weak API Controls - Authenticated:\n"
            "- Ensure authenticated users have appropriate permissions.\n"
            "- Use session management best practices to prevent token reuse or hijacking.\n"
            "- Regularly audit API logs for any signs of abuse."
        ),
        "Session Management": (
            "Session Management:\n"
            "- Secure session handling using secure cookies (HttpOnly, Secure flag) and enforce session timeouts.\n"
            "- Consider token-based authentication (e.g., JWT) with proper expiration and signature verification.\n"
            "- Regularly audit session management practices and logs to detect potential abuses."
        )
    }

    pdf.add_page()
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 6, "Conclusion & Recommendations", ln=True)
    pdf.ln(2)
    pdf.set_font("Arial", "", 12)
    pdf.multi_cell(
        0,
        6,
        ("Based on the findings, the following remediation actions are recommended "
         "to address the vulnerabilities discovered on the target:")
    )
    pdf.ln(5)
    
    # Iterate through each vulnerability category and add its remediation if findings exist.
    for vuln_type, findings in sorted_results.items():
        if findings and vuln_type in remediation_guidelines:
            # Split the guideline into header and body based on newline.
            lines = remediation_guidelines[vuln_type].split('\n')
            if lines:
                # Print header in bold.
                pdf.set_font("Arial", "B", 12)
                pdf.cell(0, 12, lines[0], ln=True)
                # Prepare bullet lines (skip empty lines) and number them.
                bullet_lines = [line for line in lines[1:] if line.strip()]
                pdf.set_font("Arial", "", 12)
                for idx, line in enumerate(bullet_lines, start=1):
                    # Remove the initial dash if present.
                    bullet_text = line.lstrip('-').strip()
                    pdf.cell(0, 8, f"{idx}. {bullet_text}", ln=True)
                pdf.ln(2)

def add_summary_section(pdf, sorted_results):
    """
    Adds a summary section to the PDF report that counts the discovered vulnerabilities.
    """
    pdf.add_page()
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 6, "Summary of Discovered Vulnerabilities", ln=True)
    pdf.ln(2)
    pdf.set_font("Arial", "", 12)
    
    total_vulnerabilities = 0
    for category, findings in sorted_results.items():
        count = len(findings)
        total_vulnerabilities += count
        pdf.cell(0, 8, f"{category}: {count} vulnerability(s) discovered.", ln=True)
    
    pdf.ln(5)
    pdf.cell(0, 6, f"Total vulnerabilities discovered: {total_vulnerabilities}", ln=True)
    pdf.ln(5)

def create_vapt_pdf(sorted_results, filename="vapt_report.pdf", target=""):
    """
    Generates a VAPT PDF report from the provided sorted dictionary.
    
    Args:
        sorted_results (dict): A dictionary where keys are vulnerability types (e.g., 
                               'Directory & Heuristic scanning', 'Insecure Direct Object Reference (IDOR)', etc.)
                               and values are lists of findings.
        filename (str): The filename for the output PDF.
    """
    report_date = datetime.now().strftime("%Y-%m-%d")

    pdf = PDF()
    pdf.add_page()
    pdf.image("baxe.jpg", x=60, y=50, w=90)
    pdf.ln(150)
    pdf.set_font("Arial", "B", 20)
    pdf.cell(0, 10, "BrokenAXE: Broken Access Control Toolkit", ln=True, align="C")
    pdf.set_font("Arial", "", 14)
    pdf.cell(0, 10, "Vulnerability Assessment & Penetration Testing", ln=True, align="C")
    pdf.cell(0, 10, f"Report Date: {report_date}", ln=True, align="C")
    pdf.cell(0, 10, f"Target: {target}", ln=True, align="C")
    pdf.ln(250)

    # Executive Summary
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 6, "Executive Summary", ln=True)
    pdf.ln(2)
    pdf.set_font("Arial", "", 12)
    pdf.multi_cell(
        0,
        6,
        ("This report outlines the findings from the recent Vulnerability Assessment "
         "and Penetration Testing (VAPT) engagement. The following sections detail "
         "the vulnerabilities identified, their impact, and recommendations for remediation.")
    )
    pdf.ln(5)

    # Add a section for each vulnerability category that has findings.
    for vuln_type, findings in sorted_results.items():
        if findings:
            desc_text = description.get(vuln_type, "")
            add_section(pdf, vuln_type, desc_text, findings)

    # Add remediation/conclusion section only for detected vulnerabilities.
    add_remediation_section(pdf, sorted_results)

    # Add summary section
    add_summary_section(pdf, sorted_results)

    pdf.output(filename)
    print(f"\nPDF report generated: {filename}")
