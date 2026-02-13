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
import json

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
MAX_CONCURRENT_REQUESTS = 100  # Increased from 50
TCP_CONNECTOR_LIMIT = 300  # Increased from 200
TIMEOUT_SECONDS = 5  # Reduced from 8
DNS_TIMEOUT = 2  # Fast DNS timeout
COMMON_SUBDOMAINS = ["www", "cdn", "static", "api"]  # Reduced list for speed

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
    """Optimized async checker with aggressive timeouts"""
    async with semaphore:
        domain = domain.strip().lower()
        result = {
            "domain": domain,
            "status": "Not on AWS",
            "confidence": 0,
            "service": "-",
            "region": "-",
            "ip": "-",
            "method": "-"
        }
        
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
                    result.update({
                        "status": "AWS Confirmed",
                        "confidence": 100,
                        "service": service,
                        "region": region,
                        "method": "IP Range"
                    })
                    return result  # Early exit - no need for further checks
                    
            except asyncio.TimeoutError:
                result["method"] = "DNS Timeout"
                return result
            except:
                pass
            
            # Quick CNAME check
            try:
                cname_answers = await asyncio.wait_for(
                    loop.run_in_executor(None, dns.resolver.resolve, domain, 'CNAME'),
                    timeout=DNS_TIMEOUT
                )
                for cname in cname_answers:
                    cname_str = str(cname).lower()
                    for pattern in AWS_PATTERNS["dns"]:
                        if pattern in cname_str:
                            result.update({
                                "status": "AWS Detected",
                                "confidence": 90,
                                "method": f"CNAME: {pattern}"
                            })
                            return result  # Early exit
            except:
                pass
            
            # Fast HTTP check - only if not found yet
            if result["confidence"] < 90:
                try:
                    async with session.head(f"https://{domain}", timeout=aiohttp.ClientTimeout(total=3), ssl=False) as resp:
                        for key, val in resp.headers.items():
                            key_lower = key.lower()
                            for pattern, conf in AWS_PATTERNS["headers"].items():
                                if pattern in key_lower or pattern in val.lower():
                                    result.update({
                                        "status": "AWS Likely",
                                        "confidence": conf,
                                        "method": f"Header: {pattern}"
                                    })
                                    if conf >= 90:
                                        return result  # Early exit for high confidence
                except:
                    pass
            
        except Exception as e:
            result["method"] = f"Error: {str(e)[:30]}"
        
        return result

# Batch processing for large lists
async def process_batch(domains: List[str], aws_data: Dict, batch_size: int = 100) -> List[Dict]:
    """Process domains in optimized batches"""
    connector = aiohttp.TCPConnector(
        limit=TCP_CONNECTOR_LIMIT,
        limit_per_host=50,
        ttl_dns_cache=300,  # Cache DNS for 5 minutes
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
    
    # Performance settings
    with st.expander("Performance Settings"):
        custom_concurrency = st.slider("Concurrent Requests", 50, 200, MAX_CONCURRENT_REQUESTS, 10)
        custom_timeout = st.slider("Timeout (seconds)", 3, 10, TIMEOUT_SECONDS, 1)
        
        st.caption("Higher concurrency = faster processing but more resource intensive")
    
    # Export options
    with st.expander("Export Options"):
        export_format = st.selectbox("Format", ["CSV", "JSON", "Excel"])
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
            if result:
                r = result[0]
                st.markdown(f"""
                <div class="{'success-card' if r['confidence'] >= 90 else 'info-card'}">
                    <strong>{r['domain']}</strong><br>
                    Status: {r['status']}<br>
                    Confidence: {r['confidence']}%<br>
                    Service: {r['service']}<br>
                    Region: {r['region']}
                </div>
                """, unsafe_allow_html=True)

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
            metrics_container = st.empty()
            
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
            avg_time = duration / len(results_df) if len(results_df) > 0 else 0
            
            progress_bar.progress(100)
            status_container.success(f"Analysis complete in {duration:.2f}s")
            
            # Display metrics
            col1, col2, col3, col4, col5 = st.columns(5)
            col1.metric("Total Domains", f"{len(results_df):,}")
            col2.metric("AWS Detected", f"{aws_count:,}")
            col3.metric("Detection Rate", f"{(aws_count/len(results_df)*100):.1f}%")
            col4.metric("Total Time", f"{duration:.2f}s")
            col5.metric("Avg per Domain", f"{avg_time:.3f}s")
            
            # Results table
            st.subheader("Analysis Results")
            
            # Filters
            filter_col1, filter_col2 = st.columns(2)
            with filter_col1:
                status_filter = st.selectbox("Filter by Status", ["All", "AWS Confirmed", "AWS Detected", "AWS Likely", "Not on AWS"])
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
            
            st.dataframe(
                filtered_df.style.apply(highlight_status, axis=1),
                use_container_width=True,
                height=500
            )
            
            # Export
            st.subheader("Export Results")
            
            filename_base = f"aws_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}" if include_timestamp else "aws_analysis"
            
            if export_format == "CSV":
                csv = results_df.to_csv(index=False)
                st.download_button("Download CSV", csv, f"{filename_base}.csv", "text/csv")
            elif export_format == "JSON":
                json_str = results_df.to_json(orient="records", indent=2)
                st.download_button("Download JSON", json_str, f"{filename_base}.json", "application/json")
            elif export_format == "Excel":
                # Note: requires openpyxl
                st.info("Excel export requires openpyxl. Add to requirements.txt")
            
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
        
        2. CNAME Analysis (90-95%)
           - Detects CloudFront, ELB, S3 endpoints
           - High accuracy for CDN detection
        
        3. HTTP Headers (60-95%)
           - Analyzes AWS-specific headers
           - Variable confidence based on header type
        """)
    
    with col2:
        st.markdown("""
        **Performance Tips**
        
        - Batch size: 100-500 domains optimal
        - For 1000+ domains: Use higher concurrency
        - Slow network: Increase timeout
        - Rate limits: Reduce concurrent requests
        
        **Limitations**
        
        - Private/internal domains cannot be checked
        - Firewall blocks may cause false negatives
        - CDN layers may mask actual hosting
        """)
