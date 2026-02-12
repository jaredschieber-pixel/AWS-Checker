import streamlit as st
import requests
import socket
import pandas as pd
import ipaddress
import json

st.title("AWS Usage Checker (Advanced)")

# Load AWS IP ranges
@st.cache_data(ttl=3600)
def load_aws_ips():
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    r = requests.get(url, timeout=10)
    data = r.json()
    aws_networks = [ipaddress.ip_network(prefix["ip_prefix"]) for prefix in data["prefixes"] if "ip_prefix" in prefix]
    return aws_networks

aws_networks = load_aws_ips()

# AWS hints in HTML and headers
AWS_HINTS_HTML = ["amazonaws.com", "cloudfront.net", "awsstatic"]
AWS_HINTS_HEADERS = ["x-amz-", "server: AmazonS3"]

def check_domain(domain):
    domain = domain.strip()
    result = {"domain": domain, "aws_signal": False, "reason": ""}

    try:
        # Get IP
        ip = socket.gethostbyname(domain)
        ip_obj = ipaddress.ip_address(ip)

        # Check if IP is in AWS ranges
        for net in aws_networks:
            if ip_obj in net:
                result["aws_signal"] = True
                result["reason"] = f"AWS IP ({ip})"
                break

        # Request HTML
        r = requests.get(f"http://{domain}", timeout=6)
        html = r.text.lower()

        # Check HTML hints
        if any(hint in html for hint in AWS_HINTS_HTML):
            result["aws_signal"] = True
            result["reason"] += " | HTML hints"

        # Check headers
        headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
        if any(hint in str(headers_lower) for hint in AWS_HINTS_HEADERS):
            result["aws_signal"] = True
            result["reason"] += " | Headers hints"

    except Exception as e:
        result["reason"] += f" | Error: {str(e)}"

    return result

# Upload CSV
file = st.file_uploader("Upload domain CSV", type=["csv"])
if file:
    df = pd.read_csv(file, header=None, names=["domain"])
    results = []

    for d in df["domain"]:
        results.append(check_domain(d))

    out = pd.DataFrame(results)
    st.dataframe(out)

    st.download_button(
        "Download Results",
        out.to_csv(index=False),
        "aws_results.csv"
    )
