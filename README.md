# CTI Enrichement Report Generator

## Overview

**CTI Enrichment Report Generator** is a Python-based threat intelligence utility that performs **passive IOC enrichment** using open threat intelligence platforms and produces an analyst-ready PDF report.

The tool is designed to simulate a **SOC / CTI analyst workflow**, where raw indicators (IP, domain, URL, hash) are enriched, risk-scored, and documented without active scanning or exploitation.

> [!WARNING]
> This tool uses **passive intelligence only** and **does not perform scanning, exploitation, or OpenCTI automation**.
---

## Key Features

* Supports multiple IOC types:
  * IPv4 / IPv6
  * Domains
  * URLs
  * File hashes (MD5 / SHA1 / SHA256)
* Threat enrichment using:
  * **VirusTotal**
  * **AbuseIPDB**
* Automated risk scoring & severity classification
* Extracts:
  * Country
  * ASN & organization
  * Usage tags / categories
  * Attack descriptions (if available)
  * Domain resolution to associated IPs
  * **PDF report generation for analyst documentation**
  * Clean terminal output using `rich`
---

## Why This Project Exists

In real-world CTI and SOC roles, analysts are expected to:
* Enrich indicators quickly
* Correlate data from multiple intelligence sources
* Assign risk and severity
* Produce readable reports for stakeholders
This project demonstrates:
* Threat intelligence fundamentals
* Python automation for analyst workflows
* Reporting and documentation skills
* OPSEC-aware, passive analysis methodology
---

## Supported IOC Types

| IOC Type	   | Supported  |
|  :---:       | :---:      |
| IPv4 / IPv6	 |   ✅      |
| Domain	     |   ✅      |
| URL	         |   ✅      |
| File Hash	   |   ✅      |
---

## Risk Scoring Logic

Risk score is calculated using:
* VirusTotal detections:
  * Malicious detections × 10
  * Suspicious detections × 5
* AbuseIPDB confidence score (IP only)
Score Range: `0 – 100`
### Severity Classification

| Score Range	| Severity |
| :---:       | :---:    |
| 75 – 100	  | HIGH     |
| 40 – 74	    | MEDIUM   |
| 15 – 39	    | LOW      |
| 0 – 14	    | CLEAN    |
---

## Example Output (Terminal)

* IOC type detection
* Risk score & severity
* AbuseIPDB reputation (for IPs)
* ASN, organization, country
* Usage tags and attack categories
* PDF export confirmation
---

## PDF Report Contents

Each report includes:
* IOC & IOC type
* Risk score & severity
* VirusTotal detection summary
* AbuseIPDB reputation (if applicable)
* ASN & organization
* Country information
* Usage tags / attack description
* Hostnames / detection engines

Generated reports are suitable for:
* CTI documentation
* Case studies
* Portfolio evidence
* Analyst handover notes
---

## Installation

1. Clone Repository:
   ```bash
   git clone https://github.com/yourusername/cti-enrichment-report-generator.git
   cd cti-enrichment-report-generator
   ```
2. Install Dependencies:
   ```bash
   pip install -r requirements.txt
   ```
Required libraries:
* requests
* python-dotenv
* rich
* reportlab
---

## API Configuration

Create a .env file in the project directory:
```bash
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
```
> [!NOTE]
> Free-tier API keys are sufficient.
---

## Usage

### Single IOC
```bash
python cti_report_full.py 8.8.8.8
```
### Multiple IOC
```bash
python cti_report_full.py example.com malicious-ip.txt
```
### File Input
```bash
python cti_report_full.py iocs.txt
```
Each IOC generates a separate PDF report.
---

## Limitations

* No active scanning or probing
* No OpenCTI or MISP automation
* API rate limits apply
* Domain enrichment depends on DNS resolution
---

## MITRE ATT&CK Context

This tool supports **Reconnaissance-phase intelligence analysis**, aligned with:
* **T1590** – Gather Victim Network Information
* **T1596** – Search Open Technical Databases
It does **not** simulate attacker behavior or exploitation.
---

## Ethical Use

This tool is intended for:
* Defensive security research
* Threat intelligence learning
* Blue-team analysis
* Interview and portfolio demonstration
Do not use this tool for unauthorized investigations.
---

## Author Notes

This project was built as part of a threat intelligence learning roadmap, focusing on:
* Passive OSINT
* Analyst reporting
* OPSEC-safe workflows
Future enhancements may include:
* IOC batch correlation
* MITRE ATT&CK auto-mapping
* OpenCTI-compatible output formats
---

## License
[MIT](https://choosealicense.com/licenses/mit/)
