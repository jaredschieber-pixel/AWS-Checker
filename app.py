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
    page_title="Cloud Infrastructure Analyzer (AWS & Azure)",
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
        background: linear-gradient(90deg, #1f77b4 0%, #0078d4 50%, #2ca02c 100%);
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
    
    .azure-card {
        background: rgba(0, 120, 212, 0.1);
        border-left: 4px solid #0078d4;
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
        background: linear-gradient(90deg, #1f77b4 0%, #0078d4 50%, #2ca02c 100%);
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
        background: linear-gradient(90deg, #1f77b4 0%, #0078d4 50%, #2ca02c 100%);
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

# Cache Azure data
@st.cache_data(ttl=7200, show_spinner=False)
def load_azure_ips():
    """Load Azure IP ranges - cached for 2 hours"""
    # Azure publishes IP ranges - we'll try the discovery endpoint first
    try:
        # Try to get the current download URL from Azure's discovery page
        discovery_url = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
        
        # Fallback to a known working direct link
        # This URL is more stable - it's the "Public Cloud" service tags
        url = "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public.json"
        
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        data = r.json()
        
        ipv4_lookup = {}
        ipv6_lookup = {}
        
        for service in data.get("values", []):
            service_name = service.get("name", "UNKNOWN")
            properties = service.get("properties", {})
            region = properties.get("region", "")
            
            for prefix in properties.get("addressPrefixes", []):
                try:
                    net = ipaddress.ip_network(prefix)
                    lookup_dict = ipv4_lookup if net.version == 4 else ipv6_lookup
                    
                    lookup_dict[str(net)] = {
                        "network": net,
                        "service": service_name,
                        "region": region if region else "GLOBAL"
                    }
                except:
                    continue
        
        return {
            "ipv4": list(ipv4_lookup.values()),
            "ipv6": list(ipv6_lookup.values()),
            "count": len(ipv4_lookup) + len(ipv6_lookup),
            "updated": data.get("changeNumber", "unknown")
        }
    except Exception as e:
        st.warning(f"Could not load Azure IP ranges: {e}. Azure detection will be limited.")
        return {
            "ipv4": [],
            "ipv6": [],
            "count": 0,
            "updated": "error"
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

# Enhanced Azure detection patterns
AZURE_PATTERNS = {
    "dns": ["azurewebsites.net", "azure.com", "azureedge.net", "trafficmanager.net", 
            "cloudapp.azure.com", "blob.core.windows.net", "azurefd.net", 
            "database.windows.net", "azurecontainer.io"],
    "headers": {
        "x-ms": 95, "x-azure": 95, "azure": 90, "x-aspnet-version": 70,
        "server": 60, "x-powered-by": 65
    },
    "html": ["azure", "azureedge", "azurewebsites"],
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

def check_ip_in_azure(ip_str: str, azure_data: Dict) -> tuple:
    """Check if IP is in Azure ranges"""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        networks = azure_data['ipv4'] if ip_obj.version == 4 else azure_data['ipv6']
        
        for net_data in networks:
            if ip_obj in net_data["network"]:
                return True, net_data["service"], net_data["region"]
        return False, None, None
    except:
        return False, None, None

async def check_domain_fast(session: aiohttp.ClientSession, domain: str, aws_data: Dict, azure_data: Dict, semaphore: asyncio.Semaphore) -> Dict:
    """Optimized async checker with AWS and Azure detection"""
    
    # Check cache first
    cached_result = cache.get(domain)
    if cached_result is not None:
        cached_result["cached"] = True
        return cached_result
    
    async with semaphore:
        domain = domain.strip().lower()
        result = {
            "domain": domain,
            "provider": "None",
            "status": "Not on AWS/Azure",
            "confidence": 0,
            "service": "-",
            "region": "-",
            "ip": "-",
            "method": "-",
            "why": "No AWS or Azure indicators found",
            "evidence": [],
            "cached": False
        }
        
        # Track all evidence found
        evidence_list = []
        confidence_breakdown = []
        aws_confidence = 0
        azure_confidence = 0
        
        try:
            # FAST DNS check with timeout
            try:
                loop = asyncio.get_event_loop()
                ips = await asyncio.wait_for(
                    loop.run_in_executor(None, socket.gethostbyname, domain),
                    timeout=DNS_TIMEOUT
                )
                
                result["ip"] = ips
                
                # Check AWS IP
                in_aws, aws_service, aws_region = check_ip_in_aws(ips, aws_data)
                if in_aws:
                    aws_confidence = 100
                    result["provider"] = "AWS"
                    result["service"] = aws_service
                    result["region"] = aws_region
                    result["method"] = "IP Range Match"
                    result["why"] = f"IP {ips} is in official AWS IP ranges for {aws_service} in {aws_region}"
                    evidence_list.append(f"✓ IP matches AWS range: {aws_service} ({aws_region})")
                
                # Check Azure IP
                in_azure, azure_service, azure_region = check_ip_in_azure(ips, azure_data)
                if in_azure:
                    azure_confidence = 100
                    result["provider"] = "Azure"
                    result["service"] = azure_service
                    result["region"] = azure_region
                    result["method"] = "IP Range Match"
                    result["why"] = f"IP {ips} is in official Azure IP ranges for {azure_service} in {azure_region}"
                    evidence_list.append(f"✓ IP matches Azure range: {azure_service} ({azure_region})")
                
            except asyncio.TimeoutError:
                evidence_list.append("⚠ DNS lookup timed out")
            except Exception as e:
                evidence_list.append(f"⚠ DNS lookup failed: {type(e).__name__}")
            
            # CNAME check for both AWS and Azure
            try:
                loop = asyncio.get_event_loop()
                resolver = dns.resolver.Resolver()
                resolver.timeout = DNS_TIMEOUT
                resolver.lifetime = DNS_TIMEOUT
                
                try:
                    answers = await loop.run_in_executor(None, resolver.resolve, domain, 'CNAME')
                    cname = str(answers[0].target).lower()
                    
                    # Check AWS CNAME patterns
                    for pattern in AWS_PATTERNS["dns"]:
                        if pattern in cname:
                            confidence_val = 95
                            aws_confidence = max(aws_confidence, confidence_val)
                            evidence_list.append(f"✓ CNAME points to AWS: {cname}")
                            
                            if aws_confidence >= 95 and result["provider"] == "None":
                                result["provider"] = "AWS"
                                result["method"] = "CNAME Analysis"
                                result["why"] = f"Domain CNAME points to AWS infrastructure: {cname}"
                                
                                # Extract service from CNAME
                                if "cloudfront" in cname:
                                    result["service"] = "CloudFront"
                                elif "elb" in cname or "elasticloadbalancing" in cname:
                                    result["service"] = "ELB"
                                elif "s3" in cname:
                                    result["service"] = "S3"
                    
                    # Check Azure CNAME patterns
                    for pattern in AZURE_PATTERNS["dns"]:
                        if pattern in cname:
                            confidence_val = 95
                            azure_confidence = max(azure_confidence, confidence_val)
                            evidence_list.append(f"✓ CNAME points to Azure: {cname}")
                            
                            if azure_confidence >= 95 and result["provider"] == "None":
                                result["provider"] = "Azure"
                                result["method"] = "CNAME Analysis"
                                result["why"] = f"Domain CNAME points to Azure infrastructure: {cname}"
                                
                                # Extract service from CNAME
                                if "azurewebsites" in cname:
                                    result["service"] = "App Service"
                                elif "azureedge" in cname or "azurefd" in cname:
                                    result["service"] = "Front Door / CDN"
                                elif "blob.core.windows.net" in cname:
                                    result["service"] = "Blob Storage"
                                elif "trafficmanager" in cname:
                                    result["service"] = "Traffic Manager"
                    
                except dns.resolver.NoAnswer:
                    evidence_list.append("ℹ No CNAME record found")
                except dns.resolver.NXDOMAIN:
                    evidence_list.append("⚠ Domain does not exist")
                    result["why"] = "Domain does not exist (NXDOMAIN)"
                except:
                    pass
                    
            except Exception:
                pass
            
            # HTTP Headers check for both AWS and Azure
            if aws_confidence < 90 and azure_confidence < 90:
                try:
                    async with session.get(f"http://{domain}", timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS), allow_redirects=True) as response:
                        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
                        
                        # Check AWS headers
                        for header_key, confidence_val in AWS_PATTERNS["headers"].items():
                            for header, value in headers.items():
                                if header_key in header or header_key in value:
                                    aws_confidence = max(aws_confidence, confidence_val)
                                    evidence_list.append(f"✓ AWS header found: {header}: {value[:50]}")
                                    
                                    if aws_confidence >= 90 and result["provider"] == "None":
                                        result["provider"] = "AWS"
                                        result["method"] = "HTTP Headers"
                                        result["why"] = f"AWS-specific headers detected in HTTP response"
                        
                        # Check Azure headers
                        for header_key, confidence_val in AZURE_PATTERNS["headers"].items():
                            for header, value in headers.items():
                                if header_key in header or header_key in value:
                                    azure_confidence = max(azure_confidence, confidence_val)
                                    evidence_list.append(f"✓ Azure header found: {header}: {value[:50]}")
                                    
                                    if azure_confidence >= 90 and result["provider"] == "None":
                                        result["provider"] = "Azure"
                                        result["method"] = "HTTP Headers"
                                        result["why"] = f"Azure-specific headers detected in HTTP response"
                        
                        # Check response body
                        try:
                            html = await response.text()
                            html_lower = html.lower()
                            
                            # AWS patterns in HTML
                            for pattern in AWS_PATTERNS["html"]:
                                if pattern in html_lower:
                                    aws_confidence = max(aws_confidence, 70)
                                    evidence_list.append(f"✓ AWS reference in HTML: {pattern}")
                            
                            # Azure patterns in HTML
                            for pattern in AZURE_PATTERNS["html"]:
                                if pattern in html_lower:
                                    azure_confidence = max(azure_confidence, 70)
                                    evidence_list.append(f"✓ Azure reference in HTML: {pattern}")
                        except:
                            pass
                            
                except asyncio.TimeoutError:
                    evidence_list.append("⚠ HTTP request timed out")
                except Exception as e:
                    evidence_list.append(f"ℹ HTTP check failed: {type(e).__name__}")
            
            # Determine final provider and confidence
            final_confidence = max(aws_confidence, azure_confidence)
            
            if aws_confidence > azure_confidence:
                result["provider"] = "AWS"
                result["confidence"] = aws_confidence
            elif azure_confidence > aws_confidence:
                result["provider"] = "Azure"
                result["confidence"] = azure_confidence
            else:
                result["confidence"] = 0
            
            # Update status based on confidence
            if result["confidence"] >= 90:
                result["status"] = f"{result['provider']} Confirmed"
            elif result["confidence"] >= 70:
                result["status"] = f"{result['provider']} Detected"
            elif result["confidence"] >= 50:
                result["status"] = f"{result['provider']} Possible"
            else:
                result["status"] = "Not on AWS/Azure"
                result["provider"] = "None"
            
            result["evidence"] = evidence_list
            
        except Exception as e:
            result["why"] = f"Error during analysis: {type(e).__name__}"
            result["evidence"] = evidence_list + [f"⚠ Error: {str(e)}"]
        
        # Cache the result
        cache.set(domain, result)
        
        return result

async def process_batch(domains: List[str], aws_data: Dict, azure_data: Dict) -> List[Dict]:
    """Process domains in parallel with optimized concurrency"""
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
    
    connector = aiohttp.TCPConnector(
        limit=TCP_CONNECTOR_LIMIT,
        ttl_dns_cache=300,
        ssl=ssl.create_default_context(cafile=certifi.where())
    )
    
    timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = [check_domain_fast(session, domain, aws_data, azure_data, semaphore) for domain in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    
    return results

# Load cloud provider data
with st.spinner("Loading cloud provider IP ranges..."):
    aws_data = load_aws_ips()
    azure_data = load_azure_ips()

# Header
st.title("🔍 Cloud Infrastructure Analyzer")
st.markdown("**Detect AWS and Azure hosting with high accuracy** · Fast parallel analysis · Evidence-based detection")

# Stats in columns
col1, col2, col3, col4 = st.columns(4)
col1.metric("AWS IP Ranges", f"{aws_data['count']:,}")
col2.metric("Azure IP Ranges", f"{azure_data['count']:,}")

cache_stats = cache.get_stats()
col3.metric("Cache Entries", f"{cache_stats['valid']:,}")
col4.metric("Cache Hit Rate", f"{(cache_stats['valid']/(cache_stats['total']+1)*100):.0f}%")

st.markdown(f"*AWS data updated: {aws_data['updated']} | Azure data updated: {azure_data['updated']}*")

# Sidebar configuration
with st.sidebar:
    st.header("⚙️ Configuration")
    
    # Performance settings
    with st.expander("Performance Settings", expanded=False):
        st.slider("Max Concurrent Requests", 50, 200, MAX_CONCURRENT_REQUESTS, 10, disabled=True, help="Currently set to 100")
        st.slider("Timeout (seconds)", 3, 10, TIMEOUT_SECONDS, 1, disabled=True, help="Currently set to 5")
        
        st.caption("Higher concurrency = faster processing but more resource intensive")
    
    # Cache management
    with st.expander("Cache Management"):
        if st.button("Clear Cache"):
            cache.clear()
            st.success("Cache cleared!")
            st.rerun()
        
        st.caption(f"Valid entries: {cache_stats['valid']}")
        st.caption(f"Expired entries: {cache_stats['expired']}")
    
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
            result = asyncio.run(process_batch([manual_domain], aws_data, azure_data))
            if result and isinstance(result[0], dict):
                r = result[0]
                
                # Choose card style based on provider
                card_class = "success-card" if r['provider'] == "AWS" else ("azure-card" if r['provider'] == "Azure" else "info-card")
                
                st.markdown(f"""
                <div class="{card_class}">
                    <strong>{r['domain']}</strong><br>
                    Provider: {r['provider']}<br>
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
            results = asyncio.run(process_batch(df["domain"].tolist(), aws_data, azure_data))
            
            # Filter out exceptions
            results = [r for r in results if isinstance(r, dict)]
            
            # Calculate metrics
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            results_df = pd.DataFrame(results)
            aws_count = ((results_df["provider"] == "AWS") & (results_df["confidence"] >= 90)).sum()
            azure_count = ((results_df["provider"] == "Azure") & (results_df["confidence"] >= 90)).sum()
            cache_hits = results_df["cached"].sum() if "cached" in results_df.columns else 0
            avg_time = duration / len(results_df) if len(results_df) > 0 else 0
            
            progress_bar.progress(100)
            status_container.success(f"Analysis complete in {duration:.2f}s")
            
            # Display metrics
            col1, col2, col3, col4, col5, col6 = st.columns(6)
            col1.metric("Total Domains", f"{len(results_df):,}")
            col2.metric("AWS Detected", f"{aws_count:,}")
            col3.metric("Azure Detected", f"{azure_count:,}")
            col4.metric("Cache Hits", f"{cache_hits:,}")
            col5.metric("Total Time", f"{duration:.2f}s")
            col6.metric("Avg per Domain", f"{avg_time:.3f}s")
            
            if cache_hits > 0:
                cache_hit_rate = (cache_hits / len(results_df) * 100)
                st.info(f"⚡ {cache_hit_rate:.1f}% of results loaded from cache (instant)")
            
            # Results table
            st.subheader("Analysis Results")
            
            # Filters
            filter_col1, filter_col2, filter_col3 = st.columns(3)
            with filter_col1:
                provider_filter = st.selectbox("Filter by Provider", ["All", "AWS", "Azure", "None"])
            with filter_col2:
                status_filter = st.selectbox("Filter by Status", ["All", "AWS Confirmed", "Azure Confirmed", "AWS Detected", "Azure Detected", "AWS Possible", "Azure Possible", "Not on AWS/Azure"])
            with filter_col3:
                min_confidence = st.slider("Minimum Confidence", 0, 100, 0)
            
            # Apply filters
            filtered_df = results_df.copy()
            if provider_filter != "All":
                filtered_df = filtered_df[filtered_df["provider"] == provider_filter]
            if status_filter != "All":
                filtered_df = filtered_df[filtered_df["status"] == status_filter]
            filtered_df = filtered_df[filtered_df["confidence"] >= min_confidence]
            
            # Color coding
            def highlight_status(row):
                if row["provider"] == "AWS" and row["confidence"] >= 90:
                    return ['background-color: #d4edda'] * len(row)
                elif row["provider"] == "Azure" and row["confidence"] >= 90:
                    return ['background-color: #cce5ff'] * len(row)
                elif row["confidence"] >= 70:
                    return ['background-color: #fff3cd'] * len(row)
                else:
                    return ['background-color: #f8d7da'] * len(row)
            
            # Reorder columns to show 'provider' and 'why' prominently
            display_columns = ["domain", "provider", "status", "confidence", "why", "service", "region", "ip", "method"]
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
                        st.markdown(f"**Provider:** {domain_data['provider']}")
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
            
            filename_base = f"cloud_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}" if include_timestamp else "cloud_analysis"
            
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
        **AWS Detection Methods**
        
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
        **Azure Detection Methods**
        
        1. IP Range Matching (100%)
           - Checks against official Azure IP ranges
           - Most reliable method
        
        2. CNAME Analysis (85-95%)
           - Detects App Service, Front Door, CDN
           - High accuracy for service detection
        
        3. HTTP Headers (60-95%)
           - Analyzes Azure-specific headers (x-ms, x-azure)
           - Variable confidence based on header type
        
        4. Evidence Tracking
           - Shows exactly what was found
           - Transparent decision making
        """)

st.markdown("---")
st.markdown("""
**Performance Tips**

- Batch size: 100-500 domains optimal
- For 1000+ domains: Results are cached for 24 hours
- Slow network: Cached results help significantly
- Rate limits: 100 concurrent by default

**Understanding "Why" Explanations**

- Each result shows plain English reasoning
- Evidence list shows all checks performed
- Confidence scores are transparent
- Select any domain to see detailed evidence
""")