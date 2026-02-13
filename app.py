import streamlit as st
import requests
import socket
import pandas as pd
import ipaddress
import concurrent.futures

st.title("AWS Usage Checker Pro")

MAX_WORKERS = 25
TIMEOUT = 4
RETRIES = 2

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0"})

# ---------- AWS IP RANGES ----------

@st.cache_data(ttl=3600)
def load_aws_ips():
    r = requests.get("https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=10)
    data = r.json()
    return [
        ipaddress.ip_network(p["ip_prefix"])
        for p in data["prefixes"]
        if "ip_prefix" in p
    ]

aws_networks = load_aws_ips()

# ---------- SIGNAL LIBRARY ----------

AWS_HTML = ["amazonaws", "awsstatic"]
AWS_HEADERS = ["x-amz", "amazons3", "awselb"]

SERVICE_PATTERNS = {
    "cloudfront": ["cloudfront"],
    "s3": ["s3.amazonaws", "amazons3"],
    "elb": ["awselb", "elasticloadbalancing"],
    "apigw": ["execute-api"]
}

# ---------- HELPERS ----------

def fetch_with_retry(url):
    for _ in range(RETRIES):
        try:
            return session.get(url, timeout=TIMEOUT, allow_redirects=True)
        except:
            continue
    return None


def aws_label(score):
    if score >= 80:
        return "AWS Confirmed"
    if score >= 50:
        return "AWS Likely"
    if score >= 25:
        return "AWS Possible"
    return "No AWS Signals"


# ---------- DOMAIN CHECK ----------

def check_domain(domain):
    domain = str(domain).strip()

    score = 0
    ip_found = ""
    sig_ip = False
    sig_header = False
    sig_html = False

    service_flags = {
        "cloudfront": False,
        "s3": False,
        "elb": False,
        "apigw": False
    }

    try:
        ip = socket.gethostbyname(domain)
        ip_found = ip
        ip_obj = ipaddress.ip_address(ip)

        for net in aws_networks:
            if ip_obj in net:
                sig_ip = True
                score += 70
                break

        r = fetch_with_retry(f"https://{domain}") or fetch_with_retry(f"http://{domain}")

        if r:
            headers = str(r.headers).lower()
            html = r.text.lower()
            blob = headers + " " + html

            if any(h in headers for h in AWS_HEADERS):
                sig_header = True
                score += 20

            if any(h in html for h in AWS_HTML):
                sig_html = True
                score += 15

            # service detection
            for svc, patterns in SERVICE_PATTERNS.items():
                if any(p in blob for p in patterns):
                    service_flags[svc] = True
                    score += 5

    except Exception as e:
        return {
            "domain": domain,
            "ip": ip_found,
            "confidence": 0,
            "classification": "Error",
            "aws_ip_signal": False,
            "header_signal": False,
            "html_signal": False,
            "aws_service_cloudfront": False,
            "aws_service_s3": False,
            "aws_service_elb": False,
            "aws_service_apigw": False,
            "service_hits": "",
            "error": str(e)
        }

    score = min(score, 100)

    services = [k for k, v in service_flags.items() if v]

    return {
        "domain": domain,
        "ip": ip_found,
        "confidence": score,
        "classification": aws_label(score),
        "aws_ip_signal": sig_ip,
        "header_signal": sig_header,
        "html_signal": sig_html,
        "aws_service_cloudfront": service_flags["cloudfront"],
        "aws_service_s3": service_flags["s3"],
        "aws_service_elb": service_flags["elb"],
        "aws_service_apigw": service_flags["apigw"],
        "service_hits": ",".join(services),
        "error": ""
    }


# ---------- UI ----------

file = st.file_uploader("Upload domain CSV", type=["csv"])

if file:
    df = pd.read_csv(file, header=None, names=["domain"])
    domains = df["domain"].dropna().tolist()

    results = []
    bar = st.progress(0)

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = [ex.submit(check_domain, d) for d in domains]

        for i, f in enumerate(concurrent.futures.as_completed(futures), 1):
            results.append(f.result())
            bar.progress(i / len(domains))

    out = pd.DataFrame(results)

    st.success(f"Checked {len(out)} domains")
    st.dataframe(out)

    st.download_button(
        "Download AWS Results CSV",
        out.to_csv(index=False),
        "aws_results.csv"
    )

