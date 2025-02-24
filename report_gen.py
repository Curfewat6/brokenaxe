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
    "Directory & Heuristic scanning": ("Directory & Heuristic Scanning is a web vulnerability assessment technique "
                                         "combining forced browsing and intelligent content analysis. Forced browsing uses "
                                         "a wordlist to systematically identify hidden directories and files on a web server, "
                                         "exposing resources not directly linked or indexed. Meanwhile, heuristic scanning analyzes "
                                         "web pages, HTTP headers, meta tags, and scripts to detect technologies, misconfigurations, "
                                         "and vulnerabilities like injection flaws or insecure object references."),
    "Forced Browsing": ("Forced Browsing is a web vulnerability assessment technique that systematically enumerates directories "
                        "and files on a web server. By using a wordlist, an attacker can discover hidden resources not directly "
                        "linked or indexed, potentially exposing sensitive information or vulnerable applications."),
    "Insecure Direct Object Reference (IDOR)": ("Insecure Direct Object Reference (IDOR) is a web application vulnerability where an attacker "
                                                 "can access unauthorized resources by manipulating object references. By changing parameters "
                                                 "or URLs, an attacker can bypass access controls and view sensitive data or perform unauthorized actions."),
    "API-IDOR": ("API Insecure Direct Object Reference (API-IDOR) is a vulnerability in an application programming interface (API) that allows "
                 "attackers to access unauthorized resources by manipulating object references. By changing parameters or URLs, an attacker can "
                 "bypass access controls and view sensitive data or perform unauthorized actions."),
    "Weak API Controls - Unauthenticated": ("Weak API Controls - Unauthenticated refers to vulnerabilities in an application programming interface (API) "
                                              "that allow unauthorized access or actions without proper authentication. Attackers can exploit these "
                                              "weaknesses to access sensitive data or perform unauthorized operations."),
    "Weak API Controls - Authenticated": ("Weak API Controls - Authenticated refers to vulnerabilities in an application programming interface (API) "
                                            "that allow unauthorized access or actions even after authentication. Attackers can exploit these weaknesses "
                                            "to access sensitive data or perform unauthorized operations."),
    "Session Management": ("Session Management vulnerabilities can lead to unauthorized access, session hijacking, or session fixation attacks. "
                           "Insecure session handling can expose user sessions to compromise, allowing attackers to impersonate users, access "
                           "sensitive data, or perform unauthorized actions.")
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
    
    # Print description in italic, if provided
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

    # Add a section for each vulnerability category
    for vuln_type, findings in sorted_results.items():
        desc_text = description.get(vuln_type, "")
        add_section(pdf, vuln_type, desc_text, findings)

    # Conclusion & Recommendations
    pdf.add_page()
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 6, "Conclusion & Recommendations", ln=True)
    pdf.ln(2)
    pdf.set_font("Arial", "", 12)
    pdf.multi_cell(
        0,
        6,
        ("Based on the findings, immediate remediation actions are recommended to "
         "mitigate the identified vulnerabilities. A detailed remediation plan should be "
         "developed and executed to improve the overall security posture.")
    )
    
    pdf.output(filename)
    print(f"\nPDF report generated: {filename}")