reported_results = []
sorted_results = {"directory traversal": [],
                  "forced-browsing": [],
                  "idor": [],
                  "api-idor": [],
                  "weak API controls - unauthenticated": [],
                  "weak API controls - authenticated": [], 
                  "session management": []
                  }

def add_to_results(result):
    reported_results.append(result)

def report_results():
    for result in reported_results:
        if result[1] == "forced-browsing":
            sorted_results["forced-browsing"].append(result)
        elif result[1] == "idor":
            sorted_results["idor"].append(result)
        elif result[1] == "api-idor":
            sorted_results["api-idor"].append(result)
        elif result[1] == "weak API controls - unauthenticated":
            sorted_results["weak API controls - unauthenticated"].append(result)
        elif result[1] == "weak API controls - authenticated":
            sorted_results["weak API controls - authenticated"].append(result)
        elif result[1] == "session management":
            sorted_results["session management"].append(result)
        else:
            sorted_results["directory traversal"].append(result)
    return sorted_results

from fpdf import FPDF

class PDF(FPDF):
    def header(self):
        # Header with the report title
        self.set_font("Arial", "B", 16)
        self.cell(0, 10, "VAPT Report", ln=True, align="C")
        self.ln(5)

    def footer(self):
        # Footer with page numbers
        self.set_y(-15)
        self.set_font("Arial", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

def add_section(pdf, title, findings):
    """
    Adds a section to the PDF for a given vulnerability category.
    Each finding is expected to be a tuple, e.g., (url, result).
    """
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, title, ln=True)
    pdf.ln(2)
    pdf.set_font("Arial", "", 12)
    
    if not findings:
        pdf.cell(0, 10, "No findings reported.", ln=True)
    else:
        for idx, finding in enumerate(findings, start=1):
            # Depending on the tuple structure, unpack the values
            if isinstance(finding, tuple):
                if len(finding) == 2:
                    url, result = finding
                    pdf.cell(0, 10, f"{idx}. URL: {url} - Result: {result}", ln=True)
                else:
                    pdf.cell(0, 10, f"{idx}. {finding}", ln=True)
            else:
                pdf.cell(0, 10, f"{idx}. {finding}", ln=True)
            pdf.ln(1)
    pdf.ln(5)

def create_vapt_pdf(sorted_results, filename="vapt_report.pdf"):
    """
    Generates a VAPT PDF report from the provided sorted dictionary.
    
    Args:
        sorted_results (dict): A dictionary where keys are vulnerability types (e.g., 
                               'directory traversal', 'idor', etc.) and values are lists of findings.
        filename (str): The filename for the output PDF.
    """
    pdf = PDF()
    pdf.add_page()

    # Executive Summary
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Executive Summary", ln=True)
    pdf.ln(2)
    pdf.set_font("Arial", "", 12)
    pdf.multi_cell(
        0,
        10,
        ("This report outlines the findings from the recent Vulnerability Assessment "
         "and Penetration Testing (VAPT) engagement. The following sections detail "
         "the vulnerabilities identified, their impact, and recommendations for remediation.")
    )
    pdf.ln(5)

    # Add a section for each vulnerability category
    for vuln_type, findings in sorted_results.items():
        section_title = vuln_type.capitalize()
        add_section(pdf, section_title, findings)

    # Conclusion & Recommendations
    pdf.add_page()
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Conclusion & Recommendations", ln=True)
    pdf.ln(2)
    pdf.set_font("Arial", "", 12)
    pdf.multi_cell(
        0,
        10,
        ("Based on the findings, immediate remediation actions are recommended to "
         "mitigate the identified vulnerabilities. A detailed remediation plan should be "
         "developed and executed to improve the overall security posture.")
    )
    
    pdf.output(filename)
    print(f"PDF report generated: {filename}")



    
    




    
