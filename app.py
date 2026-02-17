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
from typing import List, Dict

# Import the cache
from cache import ResultCache

# Initialize cache (cached in Streamlit session state)
if 'domain_cache' not in st.session_state:
    st.session_state.domain_cache = ResultCache(cache_file="domain_cache.json", ttl_hours=24)

cache = st.session_state.domain_cache

# Page config with modern theme
st.set_page_config(
    page_title="AWS Infrastructure Analyzer",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Modern CSS styling
st.markdown("""
<style>
    /* Main container */
    .main {
        padding: 2rem;
    }
    
    /* Headers */
    h1 {
        font-weight: 700;
        font-size: 2.5rem;
        margin-bottom: 0.5rem;
        background: linear-gradient(90deg, #1f77b4 0%, #2ca02c 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    
    /* Metrics styling */
    [data-testid="stMetricValue"] {
        font-size: 2rem;
        font-weight: 600;
    }
    
    /* Cards */
    .info-card {
        background: rgba(28, 131, 225, 0.1);
        border-left: 4px solid #1c83e1;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 0.5rem;
    }
    
    .success-card {
        background: rgba(44, 160, 44, 0.1);
        border-left: 4px solid #2ca02c;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 0.5rem;
    }
    
    .warning-card {
        background: rgba(255, 127, 14, 0.1);
        border-left: 4px solid #ff7f0e;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 0.5rem;
    }
    
    /* Table styling */
    .dataframe {
        font-size: 0.9rem;
    }
    
    /* Button styling */
    .stButton>button {
        width: 100%;
        background: linear-gradient(90deg, #1f77b4 0%, #2ca02c 100%);
        color: white;
        border: none;
        padding: 0.75rem 2rem;
        font-weight: 600;
        border-radius: 0.5rem;
        transition: all 0.3s;
    }
    
    .stButton>button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    }
    
    /* Progress bar */
    .stProgress > div > div > div > div {
        background: linear-gradient(90deg, #1f77b4 0%, #2ca02c 100%);
    }
    
    /* Upload box */
    [data-testid="stFileUploader"] {
        border: 2px dashed #1c83e1;
        border-radius: 0.5rem;
        padding: 2rem;
        background: rgba(28, 131, 225, 0.05);
    }
</style>
""", unsafe_allow_html=True)

# Performance configurations - OPTIMIZED FOR SPEED
MAX_CONCURRENT_REQUESTS = 100
TCP_CONNECTOR_LIMIT = 300
TIMEOUT_SECONDS = 5
DNS_TIMEOUT = 2
COMMON_SUBDOMAINS = ["www", "cdn", "static", "api"]

# Cache AWS data longer for performance
@st.cache_data(ttl=7200, show_spinner=False)
def load_aws_ips():
    """Load AWS IP ranges - cached for 2 hours"""
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    r = requests.get(url, timeout=10)
    data = r.json()
    
    # Pre-build lookup dictionaries for O(1) access
    ipv4_lookup = {}
    ipv6_lookup = {}
    
    for prefix in data.get("prefixes", []):
        if "ip_prefix" in prefix:
            net = ipaddress.ip_network(prefix["ip_prefix"])
            ipv4_lookup[str(net)] = {
                "network": net,
                "service": prefix.get("service", "UNKNOWN"),
                "region": prefix.get("region", "GLOBAL")
            }
    
    for prefix in data.get("ipv6_prefixes", []):
        if "ipv6_prefix" in prefix:
            net = ipaddress.ip_network(prefix["ipv6_prefix"])
            ipv6_lookup[str(net)] = {
                "network": net,
                "service": prefix.get("service", "UNKNOWN"),
                "region": prefix.get("region", "GLOBAL")
            }
    
    return {
        "ipv4": list(ipv4_lookup.values()),
        "ipv6": list(ipv6_lookup.values()),
        "count": len(ipv4_lookup) + len(ipv6_lookup),
        "updated": data.get("createDate", "unknown")
    }

# Enhanced AWS detection patterns
AWS_PATTERNS = {
    "dns": ["amazonaws.com", "cloudfront.net", "awsglobalaccelerator.com", "elasticbeanstalk.com"],
    "headers": {
        "x-amz": 95, "x-amzn": 95, "cloudfront": 95, "amazons3": 100,
        "via": 70, "x-cache": 70, "server": 60
    },
    "html": ["amazonaws", "cloudfront", "aws-amplify"],
}

def check_ip_in_aws(ip_str: str, aws_data: Dict) -> tuple:
    """Optimized IP checking with early exit"""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        networks = aws_data['ipv4'] if ip_obj.version == 4 else aws_data['ipv6']
        
        for net_data in networks:
            if ip_obj in net_data["network"]:
                return True, net_data["service"], net_data["region"]
        return False, None, None
    except:
        return False, None, None

async def check_domain_fast(session: aiohttp.ClientSession, domain: str, aws_data: Dict, semaphore: asyncio.Semaphore) -> Dict:
    """Optimized async checker with detailed explanations"""
    
    # Check cache first
    cached_result = cache.get(domain)
    if cached_result is not None:
        cached_result["cached"] = True
        return cached_result
    
    async with semaphore:
        domain = domain.strip().lower()
        result = {
            "domain": domain,
            "status": "Not on AWS",
            "confidence": 0,
            "service": "-",
            "region": "-",
            "ip": "-",
            "method": "-",
            "why": "No AWS indicators found",
            "evidence": [],
            "cached": False
        }
        
        # Track all evidence found
        evidence_list = []
        confidence_breakdown = []
        
        try:
            # FAST DNS check with timeout
            try:
                loop = asyncio.get_event_loop()
                ips = await asyncio.wait_for(
                    loop.run_in_executor(None, socket.gethostbyname, domain),
                    timeout=DNS_TIMEOUT
                )
                
                result["ip"] = ips
                in_aws, service, region = check_ip_in_aws(ips, aws_data)
                
                if in_aws:
                    evidence_list.append(f"✓ IP address {ips} is in official AWS IP range")
                    confidence_breakdown.append("IP Match: +100 points")
                    result.update({
                        "status": "AWS Confirmed",
                        "confidence": 100,
                        "service": service,
                        "region": region,
                        "method": "IP Range Match",
                        "why": f"IP address {ips} is registered to AWS {service} service in {region} region. This is definitive proof of AWS hosting.",
                        "evidence": evidence_list
                    })
                    cache.set(domain, result)
                    return result
                else:
                    evidence_list.append(f"✗ IP address {ips} is NOT in AWS IP ranges")
                    
            except asyncio.TimeoutError:
                evidence_list.append("⚠ DNS lookup timed out")
                result["method"] = "DNS Timeout"
                result["why"] = "Could not resolve domain name within timeout period"
                cache.set(domain, result)
                return result
            except Exception as e:
                evidence_list.append(f"✗ DNS resolution failed: {str(e)[:50]}")
            
            # Quick CNAME check
            try:
                cname_answers = await asyncio.wait_for(
                    loop.run_in_executor(None, dns.resolver.resolve, domain, 'CNAME'),
                    timeout=DNS_TIMEOUT
                )
                cname_found = False
                for cname in cname_answers:
                    cname_str = str(cname).lower()
                    for pattern in AWS_PATTERNS["dns"]:
                        if pattern in cname_str:
                            cname_found = True
                            evidence_list.append(f"✓ CNAME points to {cname_str}")
                            
                            if "cloudfront" in cname_str:
                                confidence_breakdown.append("CloudFront CNAME: +95 points")
                                result.update({
                                    "status": "AWS Detected",
                                    "confidence": 95,
                                    "method": "CNAME to CloudFront",
                                    "why": f"Domain's CNAME record points to AWS CloudFront CDN ({cname_str}). CloudFront is Amazon's content delivery network, indicating AWS infrastructure.",
                                    "evidence": evidence_list
                                })
                            elif "elb" in cname_str or "elasticbeanstalk" in cname_str:
                                confidence_breakdown.append("ELB/Elastic Beanstalk CNAME: +90 points")
                                result.update({
                                    "status": "AWS Detected",
                                    "confidence": 90,
                                    "method": "CNAME to AWS Service",
                                    "why": f"Domain's CNAME points to AWS Elastic Load Balancer or Elastic Beanstalk ({cname_str}). These are AWS-specific services.",
                                    "evidence": evidence_list
                                })
                            else:
                                confidence_breakdown.append(f"AWS CNAME pattern '{pattern}': +85 points")
                                result.update({
                                    "status": "AWS Detected",
                                    "confidence": 85,
                                    "method": f"CNAME to {pattern}",
                                    "why": f"Domain's CNAME record contains AWS pattern '{pattern}' ({cname_str}), indicating AWS hosting.",
                                    "evidence": evidence_list
                                })
                            cache.set(domain, result)
                            return result
                
                if not cname_found:
                    evidence_list.append("✗ No AWS patterns found in CNAME records")
                    
            except dns.resolver.NoAnswer:
                evidence_list.append("ℹ No CNAME records found")
            except Exception:
                evidence_list.append("✗ CNAME lookup failed")
            
            # Fast HTTP check - only if not found yet
            if result["confidence"] < 90:
                try:
                    async with session.head(f"https://{domain}", timeout=aiohttp.ClientTimeout(total=3), ssl=False) as resp:
                        headers_found = []
                        for key, val in resp.headers.items():
                            key_lower = key.lower()
                            val_lower = val.lower()
                            
                            # Check specific AWS headers
                            if "x-amz-" in key_lower or "x-amzn-" in key_lower:
                                headers_found.append(f"Header: {key}")
                                confidence_breakdown.append(f"AWS header '{key}': +95 points")
                                evidence_list.append(f"✓ AWS-specific header found: {key}")
                                result.update({
                                    "status": "AWS Confirmed",
                                    "confidence": 95,
                                    "method": "AWS Headers",
                                    "why": f"HTTP response contains AWS-specific header '{key}'. This header is only added by AWS services like S3, CloudFront, or API Gateway.",
                                    "evidence": evidence_list
                                })
                                cache.set(domain, result)
                                return result
                            
                            # Check for CloudFront in headers
                            if "cloudfront" in key_lower or "cloudfront" in val_lower:
                                headers_found.append(f"CloudFront in {key}")
                                confidence_breakdown.append("CloudFront header: +95 points")
                                evidence_list.append(f"✓ CloudFront detected in headers: {key}={val}")
                                result.update({
                                    "status": "AWS Detected",
                                    "confidence": 95,
                                    "method": "CloudFront Header",
                                    "why": f"HTTP header '{key}' indicates CloudFront CDN usage. CloudFront is Amazon's content delivery network.",
                                    "evidence": evidence_list
                                })
                                cache.set(domain, result)
                                return result
                            
                            # Check for AmazonS3 server header
                            if key_lower == "server" and "amazons3" in val_lower:
                                headers_found.append("Server: AmazonS3")
                                confidence_breakdown.append("AmazonS3 server header: +100 points")
                                evidence_list.append(f"✓ Server header identifies as AmazonS3")
                                result.update({
                                    "status": "AWS Confirmed",
                                    "confidence": 100,
                                    "service": "S3",
                                    "method": "S3 Server Header",
                                    "why": "HTTP Server header explicitly identifies as 'AmazonS3'. This is definitive proof the site is hosted on AWS S3 storage.",
                                    "evidence": evidence_list
                                })
                                cache.set(domain, result)
                                return result
                            
                            # Check cache headers (common with CloudFront)
                            if key_lower in ["x-cache", "via"]:
                                if "cloudfront" in val_lower:
                                    headers_found.append(f"{key}: CloudFront")
                                    confidence_breakdown.append(f"CloudFront cache header: +95 points")
                                    evidence_list.append(f"✓ Cache header shows CloudFront: {key}={val}")
                                    result.update({
                                        "status": "AWS Detected",
                                        "confidence": 95,
                                        "method": "CloudFront Cache",
                                        "why": f"Cache header '{key}' contains CloudFront signature, indicating AWS CDN usage.",
                                        "evidence": evidence_list
                                    })
                                    cache.set(domain, result)
                                    return result
                                elif "hit" in val_lower or "miss" in val_lower:
                                    headers_found.append(f"{key} (CDN indicator)")
                                    confidence_breakdown.append(f"Cache header (possible CDN): +60 points")
                                    evidence_list.append(f"~ CDN cache header found: {key}={val}")
                                    if result["confidence"] < 60:
                                        result.update({
                                            "status": "AWS Possible",
                                            "confidence": 60,
                                            "method": "Cache Headers",
                                            "why": f"Cache header '{key}' suggests CDN usage. Could be CloudFront or another CDN. Not definitive without other AWS indicators.",
                                            "evidence": evidence_list
                                        })
                        
                        if not headers_found:
                            evidence_list.append("✗ No AWS-specific headers found")
                            
                except Exception as e:
                    evidence_list.append(f"✗ HTTP check failed: {str(e)[:50]}")
            
        except Exception as e:
            evidence_list.append(f"✗ Error: {str(e)[:50]}")
            result["method"] = f"Error"
        
        # Final result if nothing definitive found
        if result["confidence"] == 0:
            result["why"] = "No AWS indicators detected. IP address not in AWS ranges, no AWS patterns in DNS records, and no AWS-specific HTTP headers found."
            result["evidence"] = evidence_list
        elif result["confidence"] < 70:
            result["why"] = f"Weak indicators suggest possible AWS usage (confidence: {result['confidence']}%), but no definitive proof found. " + " ".join(confidence_breakdown)
            result["evidence"] = evidence_list
        
        cache.set(domain, result)
        return result

# Batch processing for large lists
async def process_batch(domains: List[str], aws_data: Dict, batch_size: int = 100) -> List[Dict]:
    """Process domains in optimized batches"""
    connector = aiohttp.TCPConnector(
        limit=TCP_CONNECTOR_LIMIT,
        limit_per_host=50,
        ttl_dns_cache=300,
        force_close=False,
        enable_cleanup_closed=True
    )
    
    timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECONDS, connect=2)
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = [check_domain_fast(session, d, aws_data, semaphore) for d in domains]
        return await asyncio.gather(*tasks, return_exceptions=True)

# UI Header
st.title("AWS Infrastructure Analyzer")
st.markdown("**Enterprise-grade AWS hosting detection with sub-second per-domain analysis**")

# Sidebar configuration
with st.sidebar:
    st.header("Configuration")
    
    # Load AWS data
    with st.spinner("Loading AWS IP ranges..."):
        aws_data = load_aws_ips()
    
    st.markdown(f"""
    <div class="success-card">
        <strong>AWS Data Loaded</strong><br>
        IP Ranges: {aws_data['count']:,}<br>
        Updated: {aws_data['updated']}
    </div>
    """, unsafe_allow_html=True)
    
    # Cache statistics
    cache_stats = cache.get_stats()
    st.markdown(f"""
    <div class="info-card">
        <strong>Cache Status</strong><br>
        Cached Domains: {cache_stats['valid']:,}<br>
        Expired: {cache_stats['expired']:,}
    </div>
    """, unsafe_allow_html=True)
    
    # Cache management
    with st.expander("Cache Management"):
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("Save Cache"):
                cache.save()
                st.success("Cache saved!")
        
        with col2:
            if st.button("Clear Cache"):
                cache.clear()
                st.success("Cache cleared!")
    
    # Performance settings
    with st.expander("Performance Settings"):
        st.slider("Concurrent Requests", 50, 200, MAX_CONCURRENT_REQUESTS, 10, disabled=True, help="Currently set to 100")
        st.slider("Timeout (seconds)", 3, 10, TIMEOUT_SECONDS, 1, disabled=True, help="Currently set to 5")
        
        st.caption("Higher concurrency = faster processing but more resource intensive")
    
    # Export options
    with st.expander("Export Options"):
        export_format = st.selectbox("Format", ["CSV", "JSON"])
        include_timestamp = st.checkbox("Include timestamp", value=True)

# Main content
col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("Upload Domain List")
    uploaded_file = st.file_uploader(
        "Supported formats: CSV, TXT (one domain per line)",
        type=["csv", "txt"],
        help="Upload a file containing domain names to analyze"
    )

with col2:
    st.subheader("Quick Test")
    manual_domain = st.text_input("Test single domain", placeholder="example.com")
    if st.button("Quick Check") and manual_domain:
        with st.spinner("Analyzing..."):
            result = asyncio.run(process_batch([manual_domain], aws_data))
            if result and isinstance(result[0], dict):
                r = result[0]
                st.markdown(f"""
                <div class="{'success-card' if r['confidence'] >= 90 else 'info-card'}">
                    <strong>{r['domain']}</strong><br>
                    Status: {r['status']}<br>
                    Confidence: {r['confidence']}%<br>
                    Service: {r['service']}<br>
                    Region: {r['region']}<br><br>
                    <strong>Why:</strong> {r['why']}
                </div>
                """, unsafe_allow_html=True)
                
                if r.get('evidence'):
                    st.markdown("**Evidence:**")
                    for evidence in r['evidence']:
                        st.markdown(f"- {evidence}")

# Process uploaded file
if uploaded_file:
    try:
        # Parse file
        if uploaded_file.name.endswith('.csv'):
            df = pd.read_csv(uploaded_file, header=None, names=["domain"])
        else:
            content = uploaded_file.read().decode('utf-8')
            domains = [line.strip() for line in content.split('\n') if line.strip()]
            df = pd.DataFrame({"domain": domains})
        
        # Clean data
        df["domain"] = df["domain"].str.strip().str.lower()
        df = df[df["domain"] != ""].drop_duplicates()
        
        st.markdown(f"""
        <div class="info-card">
            <strong>File Loaded</strong><br>
            {len(df):,} unique domains ready for analysis
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("Start Analysis", type="primary"):
            start_time = datetime.now()
            
            # Progress tracking
            progress_bar = st.progress(0)
            status_container = st.empty()
            
            # Process domains
            status_container.info("Processing domains...")
            results = asyncio.run(process_batch(df["domain"].tolist(), aws_data))
            
            # Filter out exceptions
            results = [r for r in results if isinstance(r, dict)]
            
            # Calculate metrics
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            results_df = pd.DataFrame(results)
            aws_count = (results_df["confidence"] >= 90).sum()
            cache_hits = results_df["cached"].sum() if "cached" in results_df.columns else 0
            avg_time = duration / len(results_df) if len(results_df) > 0 else 0
            
            progress_bar.progress(100)
            status_container.success(f"Analysis complete in {duration:.2f}s")
            
            # Display metrics
            col1, col2, col3, col4, col5, col6 = st.columns(6)
            col1.metric("Total Domains", f"{len(results_df):,}")
            col2.metric("AWS Detected", f"{aws_count:,}")
            col3.metric("Detection Rate", f"{(aws_count/len(results_df)*100):.1f}%")
            col4.metric("Cache Hits", f"{cache_hits:,}")
            col5.metric("Total Time", f"{duration:.2f}s")
            col6.metric("Avg per Domain", f"{avg_time:.3f}s")
            
            if cache_hits > 0:
                cache_hit_rate = (cache_hits / len(results_df) * 100)
                st.info(f"⚡ {cache_hit_rate:.1f}% of results loaded from cache (instant)")
            
            # Results table
            st.subheader("Analysis Results")
            
            # Filters
            filter_col1, filter_col2 = st.columns(2)
            with filter_col1:
                status_filter = st.selectbox("Filter by Status", ["All", "AWS Confirmed", "AWS Detected", "AWS Possible", "Not on AWS"])
            with filter_col2:
                min_confidence = st.slider("Minimum Confidence", 0, 100, 0)
            
            # Apply filters
            filtered_df = results_df.copy()
            if status_filter != "All":
                filtered_df = filtered_df[filtered_df["status"] == status_filter]
            filtered_df = filtered_df[filtered_df["confidence"] >= min_confidence]
            
            # Color coding
            def highlight_status(row):
                if row["confidence"] >= 90:
                    return ['background-color: #d4edda'] * len(row)
                elif row["confidence"] >= 70:
                    return ['background-color: #fff3cd'] * len(row)
                else:
                    return ['background-color: #f8d7da'] * len(row)
            
            # Reorder columns to show 'why' prominently
            display_columns = ["domain", "status", "confidence", "why", "service", "region", "ip", "method"]
            available_columns = [col for col in display_columns if col in filtered_df.columns]
            display_df = filtered_df[available_columns]
            
            st.dataframe(
                display_df.style.apply(highlight_status, axis=1),
                use_container_width=True,
                height=500
            )
            
            # Add expandable evidence viewer
            if len(filtered_df) > 0:
                with st.expander("View Detailed Evidence for Individual Domains"):
                    selected_domain = st.selectbox("Select domain to see evidence:", filtered_df["domain"].tolist())
                    if selected_domain:
                        domain_data = filtered_df[filtered_df["domain"] == selected_domain].iloc[0]
                        st.markdown(f"### {selected_domain}")
                        st.markdown(f"**Status:** {domain_data['status']}")
                        st.markdown(f"**Confidence:** {domain_data['confidence']}%")
                        st.markdown(f"**Explanation:** {domain_data['why']}")
                        
                        if "evidence" in domain_data and domain_data["evidence"]:
                            st.markdown("**Evidence Found:**")
                            evidence_items = domain_data["evidence"]
                            if isinstance(evidence_items, str):
                                st.markdown(f"- {evidence_items}")
                            else:
                                for evidence in evidence_items:
                                    st.markdown(f"- {evidence}")
            
            # Export
            st.subheader("Export Results")
            
            filename_base = f"aws_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}" if include_timestamp else "aws_analysis"
            
            if export_format == "CSV":
                # Convert evidence list to string for CSV export
                export_df = results_df.copy()
                if "evidence" in export_df.columns:
                    export_df["evidence"] = export_df["evidence"].apply(lambda x: " | ".join(x) if isinstance(x, list) else str(x))
                csv = export_df.to_csv(index=False)
                st.download_button("Download CSV", csv, f"{filename_base}.csv", "text/csv")
            elif export_format == "JSON":
                json_str = results_df.to_json(orient="records", indent=2)
                st.download_button("Download JSON", json_str, f"{filename_base}.json", "application/json")
            
    except Exception as e:
        st.error(f"Error processing file: {str(e)}")

# Help section
with st.expander("Detection Methods & Accuracy"):
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        **Detection Methods**
        
        1. IP Range Matching (100%)
           - Checks against official AWS IP ranges
           - Most reliable method
        
        2. CNAME Analysis (85-95%)
           - Detects CloudFront, ELB, S3 endpoints
           - High accuracy for CDN detection
        
        3. HTTP Headers (60-95%)
           - Analyzes AWS-specific headers
           - Variable confidence based on header type
        
        4. Evidence Tracking
           - Shows exactly what was found
           - Transparent decision making
        """)
    
    with col2:
        st.markdown("""
        **Performance Tips**
        
        - Batch size: 100-500 domains optimal
        - For 1000+ domains: Results are cached
        - Slow network: Cached results help
        - Rate limits: 100 concurrent by default
        
        **Understanding "Why" Explanations**
        
        - Each result shows plain English reasoning
        - Evidence list shows all checks performed
        - Confidence scores are transparent
        - Select any domain to see detailed evidence
        """)

  
