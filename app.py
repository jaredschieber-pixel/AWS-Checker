import streamlit as st
import pandas as pd
import socket
import ipaddress
import requests
import asyncio
import aiohttp
import ssl
from functools import lru_cache

st.set_page_config(page_title="AWS Usage Checker", layout="wide")
st.title("AWS Usage Checker – Advanced")

# --------------------
# Load AWS IP ranges
# --------------------
@st.cache_data(ttl=3600)
def load_aws_ips():
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    r = requests.get(url, timeout=10)
    data = r.json()
    return [ipaddress.ip_network(prefix["ip_prefix"]) for prefix in data["prefixes"] if "ip_prefix" in prefix]

aws_networks = load_aws_ips()

# --------------------
# AWS hints
# --------------------
AWS_HINTS_HTML = ["amazonaws.com", "cloudfront.net", "awsstatic"]
AWS_HINTS_HEADERS = ["x-amz-", "server: amazonS3", "x-amz-cf-id", "via: cloudfront"]

# --------------------
# Helper functions
# --------------------
@lru_cache(maxsize=None)
def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

async def fetch(session, url):
    try:
        async with session.get(url, timeout=6, ssl=False) as response:
            html = await response.text()
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            return html.lower(), headers
    except:
        return "", {}

def check_ip_aws(ip):
    if not ip:
        return False
    ip_obj = ipaddress.ip_address(ip)
    for net in aws_networks:
        if ip_obj in net:
            return True
    return False

def confidence_score(ip_match, html_match, header_match):
    score = 0
    if ip_match: score += 50
    if html_match: score += 25
    if header_match: score += 25
    return min(score, 100)

async def check_domain_async(session, domain):
    domain = domain.strip()
    result = {"domain": domain, "aws_signal": False, "reason": "", "confidence": 0, "services": []}

    ip = resolve_ip(domain)
    ip_match = check_ip_aws(ip)
    reason_list = []
    if ip_match:
        reason_list.append(f"AWS IP ({ip})")
        result["services"].append("AWS-hosted")

    url = f"http://{domain}"
    html, headers = await fetch(session, url)

    html_match = any(hint in html for hint in AWS_HINTS_HTML)
    header_match = any(hint in str(headers) for hint in AWS_HINTS_HEADERS)

    if html_match: reason_list.append("HTML hints")
    if header_match: reason_list.append("Header hints")

    result["aws_signal"] = ip_match or html_match or header_match
    result["reason"] = " | ".join(reason_list)
    result["confidence"] = confidence_score(ip_match, html_match, header_match)

    # Identify services
    if "cloudfront.net" in html or "x-amz-cf-id" in headers:
        result["services"].append("CloudFront")
    if "amazonaws.com" in html or "x-amz-" in headers:
        result["services"].append("S3")
    if "elb.amazonaws.com" in html:
        result["services"].append("ELB")
    if "execute-api" in html:
        result["services"].append("API Gateway")

    return result

# --------------------
# Upload CSV
# --------------------
file = st.file_uploader("Upload domain CSV", type=["csv"])
if file:
    df = pd.read_csv(file, header=None, names=["domain"])
    results = []

    progress_bar = st.progress(0)
    total = len(df)

    async def process_all(domains):
        async with aiohttp.ClientSession() as session:
            tasks = [check_domain_async(session, d) for d in domains]
            for i, task in enumerate(asyncio.as_completed(tasks)):
                res = await task
                results.append(res)
                progress_bar.progress((i + 1) / total)
    
    asyncio.run(process_all(df["domain"]))

    out = pd.DataFrame(results)
    st.dataframe(out)

    st.download_button(
        "Download Results",
        out.to_csv(index=False),
        "aws_results.csv"
    )

