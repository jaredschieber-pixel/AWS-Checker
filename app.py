import streamlit as st
import aiohttp
import asyncio
import socket
import pandas as pd
import ipaddress
import requests
import dns.resolver
from datetime import datetime
import ssl
import certifi

st.set_page_config(page_title="AWS Usage Checker Pro", layout="wide")
st.title("🔍 AWS Usage Checker Pro - Enhanced Edition")

# Configuration
MAX_CONCURRENT_REQUESTS = 50  # Semaphore limit for controlled concurrency
TCP_CONNECTOR_LIMIT = 200  # Increased from default 100
TIMEOUT_SECONDS = 8
COMMON_SUBDOMAINS = ["www", "cdn", "static", "media", "api", "app"]

# Load AWS IP ranges with IPv6 support
@st.cache_data(ttl=3600)
def load_aws_ips():
    """Load both IPv4 and IPv6 AWS ranges"""
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    r = requests.get(url, timeout=10)
    data = r.json()
    
    # IPv4 ranges
    ipv4_networks = []
    ipv4_details = {}
    for prefix in data.get("prefixes", []):
        if "ip_prefix" in prefix:
            net = ipaddress.ip_network(prefix["ip_prefix"])
            ipv4_networks.append(net)
            ipv4_details[str(net)] = {
                "service": prefix.get("service", "UNKNOWN"),
                "region": prefix.get("region", "GLOBAL")
            }
    
    # IPv6 ranges
    ipv6_networks = []
    ipv6_details = {}
    for prefix in data.get("ipv6_prefixes", []):
        if "ipv6_prefix" in prefix:
            net = ipaddress.ip_network(prefix["ipv6_prefix"])
            ipv6_networks.append(net)
            ipv6_details[str(net)] = {
                "service": prefix.get("service", "UNKNOWN"),
                "region": prefix.get("region", "GLOBAL")
            }
    
    return {
        "ipv4": ipv4_networks,
        "ipv6": ipv6_networks,
        "ipv4_details": ipv4_details,
        "ipv6_details": ipv6_details,
        "sync_token": data.get("syncToken", "unknown"),
        "create_date": data.get("createDate", "unknown")
    }

aws_data = load_aws_ips()
st.sidebar.success(f"✅ AWS IP ranges loaded")
st.sidebar.info(f"Last updated: {aws_data['create_date']}")
st.sidebar.info(f"IPv4 ranges: {len(aws_data['ipv4'])}")
st.sidebar.info(f"IPv6 ranges: {len(aws_data['ipv6'])}")

# Enhanced AWS detection hints
AWS_HINTS = {
    "dns": [
        "amazonaws.com", "awsglobalaccelerator.com", "cloudfront.net",
        "elb.amazonaws.com", "s3.amazonaws.com", "awsstatic.com",
        "awsdns", "elasticbeanstalk.com", "amplifyapp.com"
    ],
    "headers": {
        "x-amz-": 90,
        "x-amzn-": 90,
        "server: amazons3": 95,
        "server: cloudfront": 95,
        "x-cache": 70,  # CloudFront caching header
        "via: cloudfront": 95,
        "cloudfront-": 85
    },
    "html": [
        "amazonaws.com", "cloudfront.net", "awsstatic",
        "aws-amplify", "s3.amazonaws"
    ],
    "ssl_org": ["Amazon", "AWS", "CloudFront"]
}

def check_ip_in_aws(ip_str):
    """Check if IP is in AWS ranges and return details"""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        
        # Check IPv4
        if ip_obj.version == 4:
            for net in aws_data['ipv4']:
                if ip_obj in net:
                    details = aws_data['ipv4_details'].get(str(net), {})
                    return True, details.get("service", "UNKNOWN"), details.get("region", "UNKNOWN")
        
        # Check IPv6
        elif ip_obj.version == 6:
            for net in aws_data['ipv6']:
                if ip_obj in net:
                    details = aws_data['ipv6_details'].get(str(net), {})
                    return True, details.get("service", "UNKNOWN"), details.get("region", "UNKNOWN")
        
        return False, None, None
    except Exception:
        return False, None, None

async def check_ssl_cert(domain, session):
    """Check SSL certificate for AWS indicators"""
    try:
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        conn = aiohttp.TCPConnector(ssl=ssl_context, limit=TCP_CONNECTOR_LIMIT)
        
        async with aiohttp.ClientSession(connector=conn) as ssl_session:
            async with ssl_session.get(f"https://{domain}", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.connection and hasattr(resp.connection, 'transport'):
                    cert = resp.connection.transport.get_extra_info('peercert')
                    if cert:
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        org = issuer.get('organizationName', '').lower()
                        for aws_org in AWS_HINTS['ssl_org']:
                            if aws_org.lower() in org:
                                return True, org
        return False, None
    except Exception:
        return False, None

async def check_domain_async(session, domain, semaphore):
    """Enhanced async domain checker with semaphore for concurrency control"""
    async with semaphore:
        domain = domain.strip().lower()
        result = {
            "domain": domain,
            "on_aws": False,
            "confidence": 0,
            "aws_service": "N/A",
            "aws_region": "N/A",
            "ip_addresses": [],
            "detection_methods": [],
            "cname_records": [],
            "http_status": "N/A",
            "redirect_url": "N/A",
            "ssl_cert_org": "N/A"
        }
        
        tried_domains = [domain] + [f"{sub}.{domain}" for sub in COMMON_SUBDOMAINS]
        max_confidence = 0
        
        for d in tried_domains:
            try:
                # DNS Resolution - IPv4 and IPv6
                try:
                    ips = []
                    try:
                        ipv4_answers = dns.resolver.resolve(d, 'A')
                        ips.extend([str(rdata) for rdata in ipv4_answers])
                    except Exception:
                        pass
                    
                    try:
                        ipv6_answers = dns.resolver.resolve(d, 'AAAA')
                        ips.extend([str(rdata) for rdata in ipv6_answers])
                    except Exception:
                        pass
                    
                    # Check each IP against AWS ranges
                    for ip in ips:
                        result["ip_addresses"].append(ip)
                        in_aws, service, region = check_ip_in_aws(ip)
                        if in_aws:
                            result["confidence"] = 100
                            result["aws_service"] = service
                            result["aws_region"] = region
                            result["detection_methods"].append(f"IP {ip} in AWS {service} ({region})")
                            max_confidence = 100
                
                except Exception as e:
                    result["detection_methods"].append(f"DNS resolution error for {d}")
                
                # CNAME Check
                try:
                    cname_answers = dns.resolver.resolve(d, 'CNAME')
                    for cname in cname_answers:
                        cname_str = str(cname).lower()
                        result["cname_records"].append(cname_str)
                        for hint in AWS_HINTS["dns"]:
                            if hint in cname_str:
                                conf = 95 if "cloudfront" in cname_str or "elb" in cname_str else 85
                                max_confidence = max(max_confidence, conf)
                                result["detection_methods"].append(f"CNAME: {cname_str}")
                except Exception:
                    pass
                
                # HTTP/HTTPS Check
                for protocol in ["https", "http"]:
                    try:
                        timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)
                        async with session.get(
                            f"{protocol}://{d}",
                            timeout=timeout,
                            allow_redirects=True,
                            ssl=False if protocol == "http" else None
                        ) as resp:
                            result["http_status"] = resp.status
                            result["redirect_url"] = str(resp.url) if resp.url != f"{protocol}://{d}" else "None"
                            
                            # Header analysis
                            headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
                            for hint, confidence in AWS_HINTS["headers"].items():
                                if ":" in hint:
                                    key, val = hint.split(":", 1)
                                    if key.strip() in headers_lower and val.strip() in headers_lower[key.strip()]:
                                        max_confidence = max(max_confidence, confidence)
                                        result["detection_methods"].append(f"Header: {hint}")
                                else:
                                    for header_key, header_val in headers_lower.items():
                                        if hint in header_key or hint in header_val:
                                            max_confidence = max(max_confidence, confidence)
                                            result["detection_methods"].append(f"Header match: {hint}")
                            
                            # HTML content analysis (first 50KB only)
                            try:
                                html_chunk = await resp.content.read(50000)
                                html = html_chunk.decode('utf-8', errors='ignore').lower()
                                for hint in AWS_HINTS["html"]:
                                    if hint in html:
                                        max_confidence = max(max_confidence, 75)
                                        result["detection_methods"].append(f"HTML: {hint}")
                            except Exception:
                                pass
                            
                            break  # Success, no need to try other protocol
                    except Exception as e:
                        continue
                
                # SSL Certificate Check (for HTTPS)
                if max_confidence < 100:
                    ssl_aws, ssl_org = await check_ssl_cert(d, session)
                    if ssl_aws:
                        max_confidence = max(max_confidence, 85)
                        result["ssl_cert_org"] = ssl_org
                        result["detection_methods"].append(f"SSL cert: {ssl_org}")
                
            except Exception as e:
                result["detection_methods"].append(f"Error checking {d}: {str(e)[:50]}")
        
        # Final determination
        result["confidence"] = max_confidence
        result["on_aws"] = max_confidence >= 100
        result["ip_addresses"] = ", ".join(result["ip_addresses"][:5])  # Limit to 5 IPs
        result["cname_records"] = ", ".join(result["cname_records"][:3])  # Limit to 3 CNAMEs
        result["detection_methods"] = " | ".join(result["detection_methods"][:10])  # Limit verbosity
        
        return result

# File upload
st.markdown("### 📤 Upload Domain List")
file = st.file_uploader("Upload CSV file with domains (one per line or first column)", type=["csv", "txt"])

if file:
    try:
        # Try reading as CSV
        try:
            df = pd.read_csv(file, header=None, names=["domain"])
        except:
            # Try reading as text file
            file.seek(0)
            content = file.read().decode('utf-8')
            domains = [line.strip() for line in content.split('\n') if line.strip()]
            df = pd.DataFrame({"domain": domains})
        
        # Clean domains
        df["domain"] = df["domain"].str.strip().str.lower()
        df = df[df["domain"] != ""]
        df = df.drop_duplicates()
        
        st.success(f"✅ Loaded {len(df)} unique domains")
        
        if st.button("🚀 Start AWS Detection", type="primary"):
            progress_bar = st.progress(0)
            status_text = st.empty()
            start_time = datetime.now()
            
            async def run_checks():
                connector = aiohttp.TCPConnector(limit=TCP_CONNECTOR_LIMIT, limit_per_host=30)
                timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)
                semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
                
                async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                    tasks = [check_domain_async(session, d, semaphore) for d in df["domain"]]
                    
                    # Process with progress updates
                    results = []
                    for i, task in enumerate(asyncio.as_completed(tasks)):
                        result = await task
                        results.append(result)
                        progress_bar.progress((i + 1) / len(tasks))
                        status_text.text(f"Processed: {i + 1}/{len(tasks)} domains")
                    
                    return results
            
            results = asyncio.run(run_checks())
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            out = pd.DataFrame(results)
            
            # Statistics
            aws_count = out["on_aws"].sum()
            aws_percent = (aws_count / len(out)) * 100
            
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total Domains", len(out))
            col2.metric("On AWS", aws_count)
            col3.metric("AWS %", f"{aws_percent:.1f}%")
            col4.metric("Duration", f"{duration:.1f}s")
            
            # Display results
            st.markdown("### 📊 Results")
            
            # Filter options
            show_filter = st.radio("Filter:", ["All", "AWS Only", "Non-AWS Only"], horizontal=True)
            if show_filter == "AWS Only":
                display_df = out[out["on_aws"] == True]
            elif show_filter == "Non-AWS Only":
                display_df = out[out["on_aws"] == False]
            else:
                display_df = out
            
            st.dataframe(
                display_df.style.applymap(
                    lambda x: 'background-color: #90EE90' if x == True else ('background-color: #FFB6C6' if x == False else ''),
                    subset=['on_aws']
                ),
                use_container_width=True,
                height=400
            )
            
            # Download button
            csv = out.to_csv(index=False)
            st.download_button(
                label="📥 Download Full Results CSV",
                data=csv,
                file_name=f"aws_detection_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
            
    except Exception as e:
        st.error(f"Error processing file: {str(e)}")

# Help section
with st.expander("ℹ️ How it works"):
    st.markdown("""
    **This tool detects AWS usage through multiple methods:**
    
    1. **IP Range Matching (100% confidence)**: Checks if domain IPs are in official AWS ranges
    2. **CNAME Analysis (85-95% confidence)**: Looks for AWS service indicators in DNS records
    3. **HTTP Headers (70-95% confidence)**: Detects AWS-specific headers (X-Amz, CloudFront, etc.)
    4. **SSL Certificates (85% confidence)**: Checks if cert is issued by AWS
    5. **HTML Content (75% confidence)**: Scans for AWS service references
    
    **Performance optimizations:**
    - Concurrent processing with semaphore control
    - TCP connector limit increased to 200
    - Efficient async generators
    - IPv4 and IPv6 support
    - Progress tracking
    """)
