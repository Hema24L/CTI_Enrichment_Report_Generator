"""
CTI Enrichment Report Generator
- VirusTotal + AbuseIPDB enrichment
- Risk scoring
- Country, ASN, organization, usage type, hostnames
- Attack description if available
- PDF report generation
- No OpenCTI automation
"""

import os, sys, socket, ipaddress, base64, requests
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4

# --------------------------------------------------
# Init
# --------------------------------------------------
console = Console()
load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

if not all([VT_API_KEY, ABUSEIPDB_API_KEY]):
    console.print("[bold red][!] Missing API keys[/bold red]")
    sys.exit(1)

# --------------------------------------------------
# Helpers
# --------------------------------------------------
def get_ioc_type(ioc):
    try:
        ip = ipaddress.ip_address(ioc)
        return "ipv6" if ip.version == 6 else "ipv4"
    except ValueError:
        pass
    if ioc.startswith(("http://","https://")):
        return "url"
    if len(ioc) in (32,40,64):
        return "hash"
    return "domain"

def resolve_domain(domain):
    ips = []
    try:
        for r in socket.getaddrinfo(domain, None):
            ips.append(r[4][0])
    except socket.gaierror:
        pass
    return list(set(ips))

# --------------------------------------------------
# VirusTotal
# --------------------------------------------------
def vt_lookup(ioc,ioc_type):
    headers = {"x-apikey": VT_API_KEY}
    if ioc_type in ("ipv4","ipv6"):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    elif ioc_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    elif ioc_type == "url":
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    else:
        raise ValueError("Unsupported IOC type")

    r = requests.get(url, headers=headers, timeout=20)
    r.raise_for_status()
    resp = r.json()
    if not resp.get("data"):
        return {"data":{"attributes":{"last_analysis_stats":{"malicious":0,"suspicious":0},"reputation":0}}}
    return resp

# --------------------------------------------------
# AbuseIPDB(IP only)
# --------------------------------------------------
def abuseipdb_lookup(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY,"Accept":"application/json"}
    params = {"ipAddress":ip,"maxAgeInDays":90,"verbose":True}
    r = requests.get(url, headers=headers, params=params, timeout=15)
    r.raise_for_status()
    return r.json()["data"]

# --------------------------------------------------
# Risk Scoring
# --------------------------------------------------
def calculate_risk(vt_stats, abuse_score=0):
    score = vt_stats.get("malicious",0)*10 + vt_stats.get("suspicious",0)*5 + abuse_score
    return min(score,100)

def severity(score):
    if score>=75: return "HIGH","red"
    elif score>=40: return "MEDIUM","yellow"
    elif score>=15: return "LOW","cyan"
    return "CLEAN","green"

# --------------------------------------------------
# PDF Export
# --------------------------------------------------
def export_pdf(filename, content):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(filename,pagesize=A4)
    elements = []
    elements.append(Paragraph("<b>CTI Enrichment Report</b>", styles["Title"]))
    elements.append(Spacer(1,12))
    for k,v in content.items():
        elements.append(Paragraph(f"<b>{k}:</b> {v}", styles["Normal"]))
        elements.append(Spacer(1,6))
    doc.build(elements)

# --------------------------------------------------
# Enrichment & Report
# --------------------------------------------------
def enrich_and_report(ioc):
    console.print(f"\n[bold cyan][*] Enriching IOC:[/bold cyan] {ioc}")
    ioc_type = get_ioc_type(ioc)

    vt_data = vt_lookup(ioc,ioc_type)
    attributes = vt_data.get("data", {}).get("attributes", {})

    vt_stats = attributes.get("last_analysis_stats", {"malicious":0,"suspicious":0})
    score = 0
    abuse_score = 0
    abuse_text = "Not applicable"
    resolved_ips = []

    # AbuseIPDB info for IPs
    if ioc_type in ("ipv4","ipv6"):
        resolved_ips = [ioc]
        abuse = abuseipdb_lookup(ioc)
        if abuse["totalReports"] > 0:
            abuse_score = abuse.get("abuseConfidenceScore",0)
            abuse_text = f"Reported YES | Confidence: {abuse_score}% | Total Reports (last 90 days): {abuse['totalReports']}"
        else:
            abuse_text="IP is not reported"
    elif ioc_type=="domain":
        resolved_ips = resolve_domain(ioc)

    score = calculate_risk(vt_stats, abuse_score)
    sev,color = severity(score)

    # Additional info from VT
    country = attributes.get("country", "N/A")
    as_owner = attributes.get("as_owner", "N/A")
    asn = attributes.get("asn", "N/A")
    usage_type = attributes.get("tags", "N/A")  # tags may indicate attack type or usage
    hostnames = attributes.get("last_analysis_results", {}).keys()  # list of engines used
    hostnames_str = ", ".join(hostnames) if hostnames else "N/A"

    # Attack description: from VT categories if present
    attack_desc = ", ".join(attributes.get("categories", {}).values()) if attributes.get("categories") else "N/A"

    # Terminal Output
    table = Table(show_header=False)
    table.add_row("IOC", ioc)
    table.add_row("Type", ioc_type.upper())
    table.add_row("Risk Score", f"[bold {color}]{score}/100[/bold {color}]")
    table.add_row("Severity", f"[bold {color}]{sev}[/bold {color}]")
    table.add_row("AbuseIPDB", abuse_text)
    table.add_row("Country", country)
    table.add_row("ASN / Org", f"{asn} / {as_owner}")
    table.add_row("Usage / Tags", usage_type if usage_type else "N/A")
    table.add_row("Attack Description", attack_desc)
    table.add_row("Hostnames / Engines", hostnames_str)
    console.print(Panel(table, title="Threat Summary", border_style=color))

    # PDF
    pdf_data = {
        "IOC": ioc,
        "IOC Type": ioc_type,
        "Risk Score": f"{score}/100",
        "Severity": sev,
        "VT Malicious": vt_stats.get("malicious",0),
        "VT Suspicious": vt_stats.get("suspicious",0),
        "Country": country,
        "ASN / Organization": f"{asn} / {as_owner}",
        "Usage Type / Tags": usage_type if usage_type else "N/A",
        "Attack Description": attack_desc,
        "Hostnames / Engines": hostnames_str
    }
    if ioc_type in ("ipv4","ipv6"):
        pdf_data["AbuseIPDB Status"] = abuse_text

    pdf_name = f"CTI_Report_{ioc.replace('/', '_')}.pdf"
    export_pdf(pdf_name, pdf_data)
    console.print(f"[bold green][+] PDF exported:[/bold green] {pdf_name}")

# --------------------------------------------------
# CLI / Batch
# --------------------------------------------------
if __name__=="__main__":
    if len(sys.argv)<2:
        console.print("[bold red]Usage: python cti_report_full.py <IOC1> [IOC2 ...] or file path[/bold red]")
        sys.exit(1)

    iocs = sys.argv[1:]
    if len(iocs)==1 and os.path.isfile(iocs[0]):
        with open(iocs[0], "r") as f:
            iocs = [line.strip() for line in f if line.strip()]

    for ioc in iocs:
        try:
            enrich_and_report(ioc)
        except Exception as e:
            console.print(f"[bold red][!] Error processing {ioc}: {e}[/bold red]")
