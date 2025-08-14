<<<<<<< HEAD
# 🚀 Kubernetes Security Report Generator
<<<<<<< HEAD
# 🚀 Kubernetes Security Report Generator

A versatile **Python script** that parses **Trivy-generated Kubernetes security reports** in YAML format and converts them into **user-friendly**, **interactive HTML**, **professional PDF**, and **structured Excel (.xlsx)** files.

This tool supports both `VulnerabilityReport` and `ConfigAuditReport` kinds, automatically detecting the report type and generating the appropriate output.

![alt text](image.png)

---

## ✨ Features

- **Universal Parser** — Handles both `VulnerabilityReport` and `ConfigAuditReport` YAML files from Trivy Operator.
- **Multiple Output Formats**:
  - 🖥 **Interactive HTML** — Dynamic single-page report with live search & severity filtering.
  - 📄 **Professional PDF** — Print-friendly document with proper formatting & pagination.
  - 📊 **Structured Excel** — Easy-to-filter and analyze `.xlsx` spreadsheet.
- **Client-Side Exports** — HTML report includes **download buttons** for PDF/Excel.
- **Batch Processing** — Process multiple YAML files in one go with a **progress bar**.
- **Command-Line Friendly** — Choose formats, filter by severity, or run batch jobs easily.
- **Clear Output** — Command-line progress and success/failure indicators.

---

## 📋 Prerequisites

- **Python** 3.6+
- Required Python libraries:
  ```txt
  PyYAML
  pandas
  openpyxl
  xhtml2pdf
  tqdm
  ```
---

## ⚙️ Installation

### Clone the repository

```
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name
```

# Install dependencies

```
pip install -r requirements.txt
```
---

## 🚀 Usage
### Basic Usage

#### Generate an HTML report from a single YAML file:

````python
python universal_report_generator.py path/to/your/report.yaml
````

#### Process multiple YAML files:

````python
python universal_report_generator.py report1.yaml report2.yaml
````
---

## Export Options

#### Generate all formats (HTML + PDF + Excel):
````python
python universal_report_generator.py report.yaml --pdf --excel
````
#### Generate only Excel (with HTML by default):
````python
python universal_report_generator.py report.yaml --excel
````

### Filtering by Severity

Generate a report with only HIGH & CRITICAL findings:

````python
python universal_report_generator.py dvwa-report.yaml --severity HIGH
````

### Combine filtering with multiple exports:

````python
python universal_report_generator.py dvwa-config-report.yaml --severity MEDIUM --pdf
````
---

## 📄 Output Files

For an input file named:

```text
my-report.yaml
```

### The generated files will be:

* HTML → my-report_vuln.html or my-report_config.html
* Excel → my-report_vuln.xlsx or my-report_config.xlsx (if --excel used)
* PDF → my-report_vuln.pdf or my-report_config.pdf (if --pdf used)

---

## 🤝 Author : Saurabh Jain

Contributions, issues, and feature requests are welcome!
Check the issues page to see current requests.

---

## 📜 License

This project is licensed under the MIT License — see the LICENSE.md file for details.
=======
# yaml-to-html-report-generator
The aim of this script is to convert the kubernates yaml reports to html
>>>>>>> 5304253f37074711ecd1eb6ea80a0c929643fdc1

A versatile **Python script** that parses **Trivy-generated Kubernetes security reports** in YAML format and converts them into **user-friendly**, **interactive HTML**, **professional PDF**, and **structured Excel (.xlsx)** files.

This tool supports both `VulnerabilityReport` and `ConfigAuditReport` kinds, automatically detecting the report type and generating the appropriate output.

![alt text](image.png)

---

## ✨ Features

- **Universal Parser** — Handles both `VulnerabilityReport` and `ConfigAuditReport` YAML files from Trivy Operator.
- **Multiple Output Formats**:
  - 🖥 **Interactive HTML** — Dynamic single-page report with live search & severity filtering.
  - 📄 **Professional PDF** — Print-friendly document with proper formatting & pagination.
  - 📊 **Structured Excel** — Easy-to-filter and analyze `.xlsx` spreadsheet.
- **Client-Side Exports** — HTML report includes **download buttons** for PDF/Excel.
- **Batch Processing** — Process multiple YAML files in one go with a **progress bar**.
- **Command-Line Friendly** — Choose formats, filter by severity, or run batch jobs easily.
- **Clear Output** — Command-line progress and success/failure indicators.

---

## 📋 Prerequisites

- **Python** 3.6+
- Required Python libraries:
  ```txt
  PyYAML
  pandas
  openpyxl
  xhtml2pdf
  tqdm
  ```
---

## ⚙️ Installation

### Clone the repository

```
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name
```

# Install dependencies

```
pip install -r requirements.txt
```
---

## 🚀 Usage
### Basic Usage

#### Generate an HTML report from a single YAML file:

````python
python universal_report_generator.py path/to/your/report.yaml
````

#### Process multiple YAML files:

````python
python universal_report_generator.py report1.yaml report2.yaml
````
---

## Export Options

#### Generate all formats (HTML + PDF + Excel):
````python
python universal_report_generator.py report.yaml --pdf --excel
````
#### Generate only Excel (with HTML by default):
````python
python universal_report_generator.py report.yaml --excel
````

### Filtering by Severity

Generate a report with only HIGH & CRITICAL findings:

````python
python universal_report_generator.py dvwa-report.yaml --severity HIGH
````

### Combine filtering with multiple exports:

````python
python universal_report_generator.py dvwa-config-report.yaml --severity MEDIUM --pdf
````
---

## 📄 Output Files

For an input file named:

```text
my-report.yaml
```

### The generated files will be:

* HTML → my-report_vuln.html or my-report_config.html
* Excel → my-report_vuln.xlsx or my-report_config.xlsx (if --excel used)
* PDF → my-report_vuln.pdf or my-report_config.pdf (if --pdf used)

---

## 🤝 Author : Saurabh Jain

Contributions, issues, and feature requests are welcome!
Check the issues page to see current requests.

---

## 📜 License

This project is licensed under the MIT License — see the LICENSE.md file for details.
=======
# yaml-to-html-report-generator
The aim of this script is to convert the kubernates yaml reports to html
>>>>>>> 5304253f37074711ecd1eb6ea80a0c929643fdc1
