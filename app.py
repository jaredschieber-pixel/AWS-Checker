import streamlit as st
import aiohttp
import asyncio
import socket
import pandas as pd
import ipaddress
import requests
import dns.resolver

st.set_page_config(page_title="AWS Usage Checker (Async)", layout="wide")
st.title("AWS Usage Checker (Async)")

# Load AWS IP ranges (cached 1 hour)
@st.cache_data(ttl=3600)
def load_aws_ips():
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    r = requests.get(url, timeout=10)
    data = r.json()
    aws_networks = [ipaddress.ip_network(prefix["ip_prefix"]) for prefix in data["prefixes"] if "ip_prefix" in prefix]
    return aws_networks

aws_networks = load_aws_ips()

# AWS hints
AWS_HINTS_HTML = ["amazonaws.com", "cloudfront.net", "awsstatic"]
AWS_HINTS_HEADERS = ["x-amz-", "server: AmazonS3"]
COMMON_SUBDOMAINS = ["www", "cdn", "static", "media"]

# Async domain checker
async def check_domain_async(session, domain):
    domain = domain.strip()
    result = {
        "domain": domain,
        "aws_signal": False,
        "confidence": 0,
        "on_aws": False,
        "reason": "",
        "details": []
    }

    tried_domains = [domain] + [f"{sub}.{domain}" for sub in COMMON_SUBDOMAINS]

    for d in tried_domains:
        try:
            # IP check
            ip = socket.gethostbyname(d)
            ip_obj = ipaddress.ip_address(ip)
            ip_hit = False
            for net in aws_networks:
                if ip_obj in net:
                    result["confidence"] = 100
                    ip_hit = True
                    result["details"].append(f"{d} IP {ip} in AWS range")
                    break
            if not ip_hit:
                result["details"].append(f"{d} IP {ip} not in AWS range")

            # DNS CNAME check
            try:
                answers = dns.resolver.resolve(d, 'CNAME')
                cname_hits = [ans.to_text() for ans in answers if any(hint in ans.to_text() for hint in AWS_HINTS_HTML)]
                if cname_hits:
                    result["confidence"] = max(result["confidence"], 90)
                    result["details"].append(f"{d} CNAME hints: {', '.join(cname_hits)}")
            except Exception:
                result["details"].append(f"{d} no CNAME / CloudFront hints")

            # HTTP request
            try:
                async with session.get(f"http://{d}", timeout=6) as resp:
                    html = await resp.text()
                    html = html.lower()
                    headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}

                    # HTML hints
                    html_hits = [hint for hint in AWS_HINTS_HTML if hint in html]
                    if html_hits:
                        result["confidence"] = max(result["confidence"], 80)
                        result["details"].append(f"{d} HTML hints found: {', '.join(html_hits)}")

                    # Header hints
                    header_hits = [hint for hint in AWS_HINTS_HEADERS if hint in str(headers_lower)]
                    if header_hits:
                        result["confidence"] = max(result["confidence"], 90)
                        result["details"].append(f"{d} Header hints found: {', '.join(header_hits)}")

            except Exception as e:
                result["details"].append(f"{d} HTTP error: {str(e)}")

        except Exception as e:
            result["details"].append(f"{d} DNS/IP error: {str(e)}")

    # Final determination
    result["on_aws"] = result["confidence"] >= 100
    result["aws_signal"] = result["confidence"] > 0
    result["reason"] = " | ".join(result["details"])

    return result

# Upload CSV
file = st.file_uploader("Upload domain CSV", type=["csv"])
if file:
    df = pd.read_csv(file, header=None, names=["domain"])
    st.info(f"Checking {len(df)} domains asynchronously (including common subdomains)...")

    async def run_checks():
        async with aiohttp.ClientSession() as session:
            tasks = [check_domain_async(session, d) for d in df["domain"]]
            return await asyncio.gather(*tasks)

    results = asyncio.run(run_checks())
    out = pd.DataFrame(results)

    st.dataframe(out)

    st.download_button(
        "Download Results",
        out.to_csv(index=False),
        "aws_results.csv"
    )
