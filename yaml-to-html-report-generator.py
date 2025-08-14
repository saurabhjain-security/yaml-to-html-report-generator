import yaml
import sys
import argparse
import pandas as pd
from datetime import datetime
from xhtml2pdf import pisa
from tqdm import tqdm

# --- Helper Functions ---

def get_severity_color(severity):
    """Returns a background color based on the severity."""
    severity_colors = {
        'CRITICAL': '#800000', 'HIGH': '#FF0000', 'MEDIUM': '#FFA500',
        'LOW': '#008000', 'UNKNOWN': '#808080'
    }
    return severity_colors.get(str(severity).upper(), '#808080')

# --- Vulnerability Report Functions ---

def generate_vuln_html(data, min_severity=None):
    """Generates HTML for a VulnerabilityReport."""
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Kubernetes Vulnerability Report</title>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.9.2/html2pdf.bundle.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 0; background-color: #f4f7f9; color: #333; }}
            .container {{ max-width: 1200px; margin: 20px auto; padding: 20px; background-color: #fff; box-shadow: 0 4px 8px rgba(0,0,0,0.1); border-radius: 8px; }}
            h1, h2 {{ color: #2c3e50; border-bottom: 2px solid #e0e0e0; padding-bottom: 10px; }}
            .header-controls {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; }}
            .export-buttons button {{ margin-left: 10px; }}
            .summary {{ display: flex; flex-wrap: wrap; justify-content: center; gap: 15px; padding: 20px 0; margin-bottom: 20px; border-radius: 8px; background-color: #ecf0f1; }}
            .summary-box {{ text-align: center; padding: 10px 20px; border-radius: 5px; color: white; flex: 1; min-width: 120px; }}
            .summary-box .count {{ font-size: 2em; font-weight: bold; }}
            .summary-box .label {{ font-size: 1em; text-transform: uppercase; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ padding: 12px; border: 1px solid #ddd; text-align: left; word-wrap: break-word; }}
            th {{ background-color: #34495e; color: white; font-weight: bold; }}
            tr:nth-child(even) {{ background-color: #f2f2f2; }}
            .severity-badge {{ color: white; padding: 5px 10px; border-radius: 12px; font-size: 0.9em; font-weight: bold; text-align: center; display: inline-block; min-width: 80px; }}
            .controls {{ display: flex; gap: 20px; margin-bottom: 20px; align-items: center; flex-wrap: wrap; }}
            #searchInput {{ width: 100%; max-width: 300px; padding: 10px; border: 1px solid #ccc; border-radius: 4px; font-size: 1em; }}
            .filter-buttons button, .export-buttons button {{ padding: 8px 15px; border: none; border-radius: 4px; cursor: pointer; background-color: #bdc3c7; color: #34495e; font-weight: bold; }}
            .filter-buttons button.active {{ background-color: #3498db; color: white; }}
            #downloadPdfBtn {{ background-color: #c0392b; color: white; }}
            #downloadExcelBtn {{ background-color: #27ae60; color: white; }}
            .footer {{ text-align: center; margin-top: 20px; font-size: 0.9em; color: #777; }}
            a {{ color: #3498db; text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
        </style>
    </head>
    <body>
        <div class="container" id="reportContainer">
            <div class="header-controls">
                <h1>Kubernetes Vulnerability Scan Report</h1>
                <div class="export-buttons">
                    <button id="downloadExcelBtn" onclick="downloadExcel()">Download Excel</button>
                    <button id="downloadPdfBtn" onclick="downloadPDF()">Download PDF</button>
                </div>
            </div>
            <p><strong>Generated on:</strong> {generation_date}</p>
            <p><strong>Scanned Repository:</strong> {repository}</p>
            <p><strong>Scanner:</strong> {scanner_name} v{scanner_version}</p>
            <h2>Summary</h2>
            <div class="summary">{summary_section}</div>
            <h2>Vulnerability Details</h2>
            <div class="controls">
                <input type="text" id="searchInput" onkeyup="filterTable()" placeholder="Search vulnerabilities...">
                <div class="filter-buttons" id="filterButtons">
                    <button class="active" onclick="toggleFilter('CRITICAL', this)">Critical</button>
                    <button class="active" onclick="toggleFilter('HIGH', this)">High</button>
                    <button class="active" onclick="toggleFilter('MEDIUM', this)">Medium</button>
                    <button class="active" onclick="toggleFilter('LOW', this)">Low</button>
                    <button class="active" onclick="toggleFilter('UNKNOWN', this)">Unknown</button>
                </div>
            </div>
            <table id="vulnTable">
                <thead>
                    <tr>
                        <th>Vulnerability ID</th>
                        <th>Severity</th>
                        <th>Resource</th>
                        <th>Installed Version</th>
                        <th>Fixed Version</th>
                        <th>Title</th>
                    </tr>
                </thead>
                <tbody>{table_rows}</tbody>
            </table>
            <div class="footer">Report generated by Python script.</div>
        </div>
        <script>
            const activeFilters = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']);
            function toggleFilter(severity, btnElement) {{ btnElement.classList.toggle('active'); if (activeFilters.has(severity)) activeFilters.delete(severity); else activeFilters.add(severity); filterTable(); }}
            function filterTable() {{ const searchInput = document.getElementById('searchInput').value.toLowerCase(); const table = document.getElementById('vulnTable'); const tr = table.getElementsByTagName('tr'); for (let i = 1; i < tr.length; i++) {{ const row = tr[i]; const severityCell = row.getElementsByTagName('td')[1]; if (severityCell) {{ const severity = severityCell.querySelector('.severity-badge').textContent.toUpperCase(); const rowText = row.textContent.toLowerCase(); const severityMatch = activeFilters.has(severity); const searchMatch = rowText.includes(searchInput); row.style.display = (severityMatch && searchMatch) ? "" : "none"; }} }} }}
            document.addEventListener('DOMContentLoaded', filterTable);
            function downloadPDF() {{ const element = document.getElementById('reportContainer'); const opt = {{ margin: 0.5, filename: 'vulnerability_report.pdf', image: {{ type: 'jpeg', quality: 0.98 }}, html2canvas: {{ scale: 2, useCORS: true }}, jsPDF: {{ unit: 'in', format: 'letter', orientation: 'landscape' }} }}; document.querySelectorAll('.controls, .export-buttons').forEach(el => el.style.display = 'none'); html2pdf().set(opt).from(element).save().then(() => {{ document.querySelectorAll('.controls, .export-buttons').forEach(el => el.style.display = 'flex'); }}); }}
            function downloadExcel() {{ const table = document.getElementById('vulnTable'); const rows = table.querySelectorAll('tr'); const data = []; const headers = []; rows[0].querySelectorAll('th').forEach(th => headers.push(th.innerText)); data.push(headers); for (let i = 1; i < rows.length; i++) {{ if (rows[i].style.display !== 'none') {{ const row = []; rows[i].querySelectorAll('td').forEach(td => row.push(td.innerText)); data.push(row); }} }} const worksheet = XLSX.utils.aoa_to_sheet(data); const workbook = XLSX.utils.book_new(); XLSX.utils.book_append_sheet(workbook, worksheet, "Vulnerabilities"); XLSX.writeFile(workbook, "vulnerability_report.xlsx"); }}
        </script>
    </body>
    </html>
    """
    report_data = data.get('report', {})
    summary = report_data.get('summary', {})
    vulnerabilities = report_data.get('vulnerabilities', [])
    artifact = report_data.get('artifact', {})
    scanner = report_data.get('scanner', {})

    summary_html = ""
    severity_order = [('criticalCount', 'Critical'), ('highCount', 'High'), ('mediumCount', 'Medium'), ('lowCount', 'Low'), ('unknownCount', 'Unknown')]
    for key, label in severity_order:
        count = summary.get(key, 0)
        summary_html += f'<div class="summary-box" style="background-color: {get_severity_color(label.upper())};"><div class="count">{count}</div><div class="label">{label}</div></div>'

    severity_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}
    if min_severity:
        min_level = severity_map[min_severity.upper()]
        vulnerabilities = [v for v in vulnerabilities if severity_map.get(str(v.get('severity', 'UNKNOWN')).upper(), 0) >= min_level]

    rows_html = ""
    if not vulnerabilities:
        rows_html = "<tr><td colspan='6' style='text-align:center;'>No vulnerabilities found for the selected criteria.</td></tr>"
    else:
        sorted_vulnerabilities = sorted(vulnerabilities, key=lambda v: severity_map.get(str(v.get('severity', 'UNKNOWN')).upper(), 0), reverse=True)
        for vuln in sorted_vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            color = get_severity_color(severity)
            vuln_id = vuln.get('vulnerabilityID', 'N/A')
            primary_link = vuln.get('primaryLink', '#')
            vuln_id_html = f'<a href="{primary_link}" target="_blank">{vuln_id}</a>' if primary_link != '#' else vuln_id
            rows_html += f"""
            <tr>
                <td>{vuln_id_html}</td>
                <td><span class="severity-badge" style="background-color: {color};">{severity}</span></td>
                <td>{vuln.get('resource', 'N/A')}</td>
                <td>{vuln.get('installedVersion', 'N/A')}</td>
                <td>{vuln.get('fixedVersion', 'N/A')}</td>
                <td>{vuln.get('title', 'N/A')}</td>
            </tr>
            """

    return html_template.format(
        generation_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        repository=f"{artifact.get('repository', 'N/A')}:{artifact.get('tag', 'N/A')}",
        scanner_name=scanner.get('name', 'N/A'),
        scanner_version=scanner.get('version', 'N/A'),
        summary_section=summary_html,
        table_rows=rows_html
    )

def export_vuln_to_excel(data, output_path, min_severity=None):
    """Exports vulnerability data to an Excel file."""
    report_data = data.get('report', {})
    vulnerabilities = report_data.get('vulnerabilities', [])

    severity_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}
    if min_severity:
        min_level = severity_map[min_severity.upper()]
        vulnerabilities = [v for v in vulnerabilities if severity_map.get(str(v.get('severity', 'UNKNOWN')).upper(), 0) >= min_level]

    if not vulnerabilities:
        print("    [!] No vulnerability data to export to Excel for the selected criteria.")
        return

    df_data = [{'Vulnerability ID': v.get('vulnerabilityID'), 'Severity': v.get('severity'), 'Resource': v.get('resource'), 'Installed Version': v.get('installedVersion'), 'Fixed Version': v.get('fixedVersion'), 'Title': v.get('title'), 'Primary Link': v.get('primaryLink')} for v in vulnerabilities]
    pd.DataFrame(df_data).to_excel(output_path, index=False, engine='openpyxl')
    print(f"    [+] SUCCESS: Exported vulnerability data to Excel: {output_path}")

def export_vuln_to_pdf(data, output_path, min_severity=None):
    """Generates a static PDF for a VulnerabilityReport."""
    pdf_template = """
    <!DOCTYPE html><html><head><meta charset="UTF-8"><title>Vulnerability Report</title><style>@page {{ size: A4 landscape; @frame footer_frame {{ -pdf-frame-content: footerContent; bottom: 1cm; margin-left: 1cm; margin-right: 1cm; height: 1cm; }} }} body {{ font-family: "Helvetica", sans-serif; font-size: 9px; }} h1, h2 {{ color: #333; }} table {{ width: 100%; border-collapse: collapse; table-layout: fixed; }} th, td {{ border: 1px solid #ccc; padding: 5px; text-align: left; word-wrap: break-word; }} tr {{ page-break-inside: avoid; }} th {{ background-color: #f2f2f2; font-weight: bold; }}</style></head><body>
        <h1>Kubernetes Vulnerability Scan Report</h1>
        <p><strong>Scanned Repository:</strong> {repository}</p>
        <p><strong>Scanner:</strong> {scanner_name} v{scanner_version}</p>
        <p><strong>Generated on:</strong> {generation_date}</p>
        <h2>Vulnerability Details</h2>
        <table><thead><tr><th style="width:15%;">Vulnerability ID</th><th style="width:10%;">Severity</th><th style="width:15%;">Resource</th><th style="width:15%;">Installed Version</th><th style="width:15%;">Fixed Version</th><th style="width:30%;">Title</th></tr></thead><tbody>{table_rows}</tbody></table>
        <div id="footerContent" style="text-align:right;">Page <pdf:pageNumber /> of <pdf:totalPages /></div>
    </body></html>
    """
    
    report_data = data.get('report', {})
    vulnerabilities = report_data.get('vulnerabilities', [])
    artifact = report_data.get('artifact', {})
    scanner = report_data.get('scanner', {})

    severity_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}
    if min_severity:
        min_level = severity_map[min_severity.upper()]
        vulnerabilities = [v for v in vulnerabilities if severity_map.get(str(v.get('severity', 'UNKNOWN')).upper(), 0) >= min_level]

    rows_html = "".join([f"<tr><td>{v.get('vulnerabilityID', 'N/A')}</td><td style='background-color:{get_severity_color(v.get('severity', 'UNKNOWN'))}; color:white;'>{v.get('severity', 'N/A')}</td><td>{v.get('resource', 'N/A')}</td><td>{v.get('installedVersion', 'N/A')}</td><td>{v.get('fixedVersion', 'N/A')}</td><td>{v.get('title', 'N/A')}</td></tr>" for v in sorted(vulnerabilities, key=lambda v: severity_map.get(str(v.get('severity', 'UNKNOWN')).upper(), 0), reverse=True)])
    
    pdf_html_content = pdf_template.format(
        generation_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        repository=f"{artifact.get('repository', 'N/A')}:{artifact.get('tag', 'N/A')}",
        scanner_name=scanner.get('name', 'N/A'),
        scanner_version=scanner.get('version', 'N/A'),
        table_rows=rows_html
    )
    
    with open(output_path, "w+b") as result_file:
        pisa_status = pisa.CreatePDF(pdf_html_content, dest=result_file)
    if not pisa_status.err:
        print(f"    [+] SUCCESS: Exported vulnerability data to PDF: {output_path}")
    else:
        print(f"    [-] ERROR: Could not convert vulnerability report to PDF: {pisa_status.err}")

# --- Config Audit Report Functions ---

def generate_config_html(data, min_severity=None):
    """Generates HTML for a ConfigAuditReport."""
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Kubernetes Configuration Audit Report</title>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.9.2/html2pdf.bundle.min.js"></script>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 0; background-color: #f4f7f9; color: #333; }}
            .container {{ max-width: 1400px; margin: 20px auto; padding: 20px; background-color: #fff; box-shadow: 0 4px 8px rgba(0,0,0,0.1); border-radius: 8px; }}
            h1, h2 {{ color: #2c3e50; border-bottom: 2px solid #e0e0e0; padding-bottom: 10px; }}
            .header-controls {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; }}
            .export-buttons button {{ margin-left: 10px; }}
            .summary {{ display: flex; flex-wrap: wrap; justify-content: center; gap: 15px; padding: 20px 0; margin-bottom: 20px; border-radius: 8px; background-color: #ecf0f1; }}
            .summary-box {{ text-align: center; padding: 10px 20px; border-radius: 5px; color: white; flex: 1; min-width: 120px; }}
            .summary-box .count {{ font-size: 2em; font-weight: bold; }}
            .summary-box .label {{ font-size: 1em; text-transform: uppercase; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; table-layout: fixed; }}
            th, td {{ padding: 12px; border: 1px solid #ddd; text-align: left; word-wrap: break-word; }}
            th {{ background-color: #34495e; color: white; font-weight: bold; }}
            tr:nth-child(even) {{ background-color: #f2f2f2; }}
            .severity-badge {{ color: white; padding: 5px 10px; border-radius: 12px; font-size: 0.9em; font-weight: bold; text-align: center; display: inline-block; min-width: 80px; }}
            .controls {{ display: flex; gap: 20px; margin-bottom: 20px; align-items: center; flex-wrap: wrap; }}
            #searchInput {{ width: 100%; max-width: 300px; padding: 10px; border: 1px solid #ccc; border-radius: 4px; font-size: 1em; }}
            .filter-buttons button, .export-buttons button {{ padding: 8px 15px; border: none; border-radius: 4px; cursor: pointer; background-color: #bdc3c7; color: #34495e; font-weight: bold; }}
            .filter-buttons button.active {{ background-color: #3498db; color: white; }}
            #downloadExcelBtn {{ background-color: #27ae60; color: white; }}
            #downloadPdfBtn {{ background-color: #c0392b; color: white; }}
            .footer {{ text-align: center; margin-top: 20px; font-size: 0.9em; color: #777; }}
            .messages {{ list-style-type: disc; padding-left: 20px; margin: 5px 0 0 0; }}
        </style>
    </head>
    <body>
        <div class="container" id="reportContainer">
            <div class="header-controls">
                <h1>Kubernetes Configuration Audit Report</h1>
                <div class="export-buttons">
                    <button id="downloadExcelBtn" onclick="downloadExcel()">Download Excel</button>
                    <button id="downloadPdfBtn" onclick="downloadPDF()">Download PDF</button>
                </div>
            </div>
            <p><strong>Generated on:</strong> {generation_date}</p>
            <p><strong>Resource Name:</strong> {resource_name}</p>
            <p><strong>Scanner:</strong> {scanner_name} v{scanner_version}</p>
            <h2>Summary of Checks</h2>
            <div class="summary">{summary_section}</div>
            <h2>Audit Check Details</h2>
            <div class="controls">
                <input type="text" id="searchInput" onkeyup="filterTable()" placeholder="Search checks...">
                <div class="filter-buttons" id="filterButtons">
                    <button class="active" onclick="toggleFilter('CRITICAL', this)">Critical</button>
                    <button class="active" onclick="toggleFilter('HIGH', this)">High</button>
                    <button class="active" onclick="toggleFilter('MEDIUM', this)">Medium</button>
                    <button class="active" onclick="toggleFilter('LOW', this)">Low</button>
                    <button class="active" onclick="toggleFilter('UNKNOWN', this)">Unknown</button>
                </div>
            </div>
            <table id="vulnTable">
                <colgroup><col style="width: 10%;"><col style="width: 10%;"><col style="width: 20%;"><col style="width: 30%;"><col style="width: 30%;"></colgroup>
                <thead><tr><th>Check ID</th><th>Severity</th><th>Title</th><th>Description & Messages</th><th>Remediation</th></tr></thead>
                <tbody>{table_rows}</tbody>
            </table>
            <div class="footer">Report generated by Python script.</div>
        </div>
        <script>
            const activeFilters = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']);
            function toggleFilter(severity, btnElement) {{ btnElement.classList.toggle('active'); if (activeFilters.has(severity)) activeFilters.delete(severity); else activeFilters.add(severity); filterTable(); }}
            function filterTable() {{ const searchInput = document.getElementById('searchInput').value.toLowerCase(); const table = document.getElementById('vulnTable'); const tr = table.getElementsByTagName('tr'); for (let i = 1; i < tr.length; i++) {{ const row = tr[i]; const severityCell = row.getElementsByTagName('td')[1]; if (severityCell) {{ const severity = severityCell.querySelector('.severity-badge').textContent.toUpperCase(); const rowText = row.textContent.toLowerCase(); const severityMatch = activeFilters.has(severity); const searchMatch = rowText.includes(searchInput); row.style.display = (severityMatch && searchMatch) ? "" : "none"; }} }} }}
            document.addEventListener('DOMContentLoaded', filterTable);
            function downloadPDF() {{ const element = document.getElementById('reportContainer'); const opt = {{ margin: 0.5, filename: 'config_audit_report.pdf', image: {{ type: 'jpeg', quality: 0.98 }}, html2canvas: {{ scale: 2, useCORS: true }}, jsPDF: {{ unit: 'in', format: 'letter', orientation: 'landscape' }} }}; document.querySelectorAll('.controls, .export-buttons').forEach(el => el.style.display = 'none'); html2pdf().set(opt).from(element).save().then(() => {{ document.querySelectorAll('.controls, .export-buttons').forEach(el => el.style.display = 'flex'); }}); }}
            function downloadExcel() {{ const table = document.getElementById('vulnTable'); const rows = table.querySelectorAll('tr'); const data = []; const headers = []; rows[0].querySelectorAll('th').forEach(th => headers.push(th.innerText)); data.push(headers); for (let i = 1; i < rows.length; i++) {{ if (rows[i].style.display !== 'none') {{ const row = []; rows[i].querySelectorAll('td').forEach(td => row.push(td.innerText)); data.push(row); }} }} const worksheet = XLSX.utils.aoa_to_sheet(data); const workbook = XLSX.utils.book_new(); XLSX.utils.book_append_sheet(workbook, worksheet, "Config Audits"); XLSX.writeFile(workbook, "config_audit_report.xlsx"); }}
        </script>
    </body>
    </html>
    """
    report_data = data.get('report', {})
    metadata = data.get('metadata', {})
    summary = report_data.get('summary', {})
    checks = report_data.get('checks', [])
    scanner = report_data.get('scanner', {})

    summary_html = ""
    severity_order = [('criticalCount', 'Critical'), ('highCount', 'High'), ('mediumCount', 'Medium'), ('lowCount', 'Low')]
    for key, label in severity_order:
        count = summary.get(key, 0)
        summary_html += f'<div class="summary-box" style="background-color: {get_severity_color(label.upper())};"><div class="count">{count}</div><div class="label">{label}</div></div>'

    severity_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}
    if min_severity:
        min_level = severity_map[min_severity.upper()]
        checks = [c for c in checks if severity_map.get(str(c.get('severity', 'UNKNOWN')).upper(), 0) >= min_level]

    rows_html = ""
    if not checks:
        rows_html = "<tr><td colspan='5' style='text-align:center;'>No configuration issues found.</td></tr>"
    else:
        sorted_checks = sorted(checks, key=lambda c: severity_map.get(str(c.get('severity', 'UNKNOWN')).upper(), 0), reverse=True)
        for check in sorted_checks:
            severity = check.get('severity', 'UNKNOWN')
            color = get_severity_color(severity)
            description = check.get('description', '')
            messages = check.get('messages', [])
            message_html = "".join([f"<li>{msg}</li>" for msg in messages])
            full_description = f"<p>{description}</p><ul class='messages'>{message_html}</ul>"
            rows_html += f"""
            <tr>
                <td>{check.get('checkID', 'N/A')}</td>
                <td><span class="severity-badge" style="background-color: {color};">{severity}</span></td>
                <td>{check.get('title', 'N/A')}</td>
                <td>{full_description}</td>
                <td>{check.get('remediation', 'N/A')}</td>
            </tr>
            """

    return html_template.format(
        generation_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        resource_name=metadata.get('name', 'N/A'),
        scanner_name=scanner.get('name', 'N/A'),
        scanner_version=scanner.get('version', 'N/A'),
        summary_section=summary_html,
        table_rows=rows_html
    )

def export_config_to_excel(data, output_path, min_severity=None):
    """Exports config audit data to an Excel file."""
    report_data = data.get('report', {})
    checks = report_data.get('checks', [])

    severity_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}
    if min_severity:
        min_level = severity_map[min_severity.upper()]
        checks = [c for c in checks if severity_map.get(str(c.get('severity', 'UNKNOWN')).upper(), 0) >= min_level]

    if not checks:
        print("    [!] No config audit data to export to Excel for the selected criteria.")
        return

    df_data = [{'Check ID': c.get('checkID'), 'Severity': c.get('severity'), 'Title': c.get('title'), 'Description': c.get('description'), 'Messages': "\n".join(c.get('messages', [])), 'Remediation': c.get('remediation')} for c in checks]
    pd.DataFrame(df_data).to_excel(output_path, index=False, engine='openpyxl')
    print(f"    [+] SUCCESS: Exported config audit data to Excel: {output_path}")

def export_config_to_pdf(data, output_path, min_severity=None):
    """Generates a static PDF for a ConfigAuditReport."""
    pdf_template = """
    <!DOCTYPE html><html><head><meta charset="UTF-8"><title>Configuration Audit Report</title><style>@page {{ size: A4 landscape; @frame footer_frame {{ -pdf-frame-content: footerContent; bottom: 1cm; margin-left: 1cm; margin-right: 1cm; height: 1cm; }} }} body {{ font-family: "Helvetica", sans-serif; font-size: 9px; }} h1, h2 {{ color: #333; }} table {{ width: 100%; border-collapse: collapse; table-layout: fixed; }} th, td {{ border: 1px solid #ccc; padding: 5px; text-align: left; word-wrap: break-word; }} tr {{ page-break-inside: avoid; }} th {{ background-color: #f2f2f2; font-weight: bold; }}</style></head><body>
        <h1>Kubernetes Configuration Audit Report</h1>
        <p><strong>Resource Name:</strong> {resource_name}</p>
        <p><strong>Scanner:</strong> {scanner_name} v{scanner_version}</p>
        <p><strong>Generated on:</strong> {generation_date}</p>
        <h2>Audit Check Details</h2>
        <table><thead><tr><th style="width:10%;">Check ID</th><th style="width:10%;">Severity</th><th style="width:20%;">Title</th><th style="width:30%;">Description & Messages</th><th style="width:30%;">Remediation</th></tr></thead><tbody>{table_rows}</tbody></table>
        <div id="footerContent" style="text-align:right;">Page <pdf:pageNumber /> of <pdf:totalPages /></div>
    </body></html>
    """
    report_data = data.get('report', {})
    metadata = data.get('metadata', {})
    checks = report_data.get('checks', [])
    scanner = report_data.get('scanner', {})

    severity_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}
    if min_severity:
        min_level = severity_map[min_severity.upper()]
        checks = [c for c in checks if severity_map.get(str(c.get('severity', 'UNKNOWN')).upper(), 0) >= min_level]

    rows_html = "".join([f"<tr><td>{c.get('checkID', 'N/A')}</td><td style='background-color:{get_severity_color(c.get('severity', 'UNKNOWN'))}; color:white;'>{c.get('severity', 'N/A')}</td><td>{c.get('title', 'N/A')}</td><td>{c.get('description', 'N/A')}<br/><b>Messages:</b> {'; '.join(c.get('messages',[]))}</td><td>{c.get('remediation', 'N/A')}</td></tr>" for c in sorted(checks, key=lambda c: severity_map.get(str(c.get('severity', 'UNKNOWN')).upper(), 0), reverse=True)])

    pdf_html_content = pdf_template.format(
        generation_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        resource_name=metadata.get('name', 'N/A'),
        scanner_name=scanner.get('name', 'N/A'),
        scanner_version=scanner.get('version', 'N/A'),
        table_rows=rows_html
    )

    with open(output_path, "w+b") as result_file:
        pisa_status = pisa.CreatePDF(pdf_html_content, dest=result_file)
    if not pisa_status.err:
        print(f"    [+] SUCCESS: Exported config audit data to PDF: {output_path}")
    else:
        print(f"    [-] ERROR: Could not convert config audit report to PDF: {pisa_status.err}")

# --- Main Execution ---

def main():
    """
    Main function to parse arguments, detect report type, and generate reports.
    """
    parser = argparse.ArgumentParser(
        description="A universal tool to convert Kubernetes YAML reports (Vulnerability or ConfigAudit) into interactive HTML, Excel, and PDF formats.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""examples:
  # Generate an HTML report for a single file
  python %(prog)s dvwa-report.yaml

  # Generate HTML, PDF, and Excel reports for multiple files
  python %(prog)s dvwa-report.yaml dvwa-config-report.yaml --pdf --excel

  # Generate a high-severity vulnerability report in HTML and PDF
  python %(prog)s dvwa-report.yaml --severity HIGH --pdf
"""
    )
    parser.add_argument("yaml_files", nargs='+', help="One or more paths to input YAML files.")
    parser.add_argument("--severity", choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], help="Filter report by minimum severity.")
    parser.add_argument("--excel", action="store_true", help="Export the report to an Excel file.")
    parser.add_argument("--pdf", action="store_true", help="Export the report to a PDF file.")
    args = parser.parse_args()

    success_count = 0
    failure_count = 0

    for yaml_file_path in tqdm(args.yaml_files, desc="Processing files", unit="file"):
        print(f"\nProcessing file: {yaml_file_path}")
        base_output_path = yaml_file_path.rsplit('.', 1)[0]
        
        try:
            with open(yaml_file_path, 'r') as f:
                data = yaml.safe_load(f)
            if not data or 'kind' not in data:
                print(f"  [-] FAILURE: YAML file is empty, invalid, or missing the 'kind' identifier.")
                failure_count += 1
                continue

            report_kind = data.get('kind')

            if report_kind == 'VulnerabilityReport':
                html_content = generate_vuln_html(data, args.severity)
                html_output_path = base_output_path + '_vuln.html'
                with open(html_output_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                print(f"  [+] SUCCESS: HTML report generated at {html_output_path}")
                
                if args.excel:
                    export_vuln_to_excel(data, base_output_path + '_vuln.xlsx', args.severity)
                if args.pdf:
                    export_vuln_to_pdf(data, base_output_path + '_vuln.pdf', args.severity)
            
            elif report_kind == 'ConfigAuditReport':
                html_content = generate_config_html(data, args.severity)
                html_output_path = base_output_path + '_config.html'
                with open(html_output_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                print(f"  [+] SUCCESS: HTML report generated at {html_output_path}")

                if args.excel:
                    export_config_to_excel(data, base_output_path + '_config.xlsx', args.severity)
                if args.pdf:
                    export_config_to_pdf(data, base_output_path + '_config.pdf', args.severity)
            
            else:
                print(f"  [-] FAILURE: Unsupported report kind '{report_kind}'.")
                failure_count += 1
                continue
            
            success_count += 1

        except FileNotFoundError:
            print(f"  [-] FAILURE: The file was not found.")
            failure_count += 1
        except Exception as e:
            print(f"  [-] FAILURE: An unexpected error occurred: {e}")
            failure_count += 1

    print(f"\n--- Processing Complete ---")
    print(f"Successfully processed: {success_count} file(s)")
    print(f"Failed to process: {failure_count} file(s)")

if __name__ == '__main__':
    main()
