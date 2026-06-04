from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
import httpx
import ssl
import certifi
import asyncio
import base64
from datetime import datetime

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── API KEYS ──
URLSCAN_SCAN_API    = "https://urlscan.io/api/v1/scan/"
URLSCAN_RESULT_API  = "https://urlscan.io/api/v1/result/"
URLSCAN_API_KEY     = "0197a872-01f3-70dc-a778-719594c68cf1"

VIRUSTOTAL_API_KEY  = "feaa341becafde9059ea920c0839694272997c447556b0cb1417e224588755c1"
VIRUSTOTAL_URL_API  = "https://www.virustotal.com/api/v3/urls"

IPQS_API_KEY        = "YrbVfb0Xme9BL4huJrGqXIzH4I4uRnUm"
IPQS_API_URL        = "https://www.ipqualityscore.com/api/json/url/{key}/{url}"


# ════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════
def format_tls_date(date_str):
    if date_str:
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00")).strftime("%B %d, %Y at %H:%M:%S UTC")
        except:
            return date_str
    return "Unknown"

def make_client():
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    transport   = httpx.AsyncHTTPTransport(verify=ssl_context)
    return httpx.AsyncClient(transport=transport, timeout=60.0)


# ════════════════════════════════════════
# ENGINE 1 — urlscan.io
# ════════════════════════════════════════
async def scan_urlscan(domain: str):
    try:
        async with make_client() as client:
            payload = {"url": domain, "visibility": "public"}
            headers = {"Content-Type": "application/json", "API-Key": URLSCAN_API_KEY}
            scan_resp = await client.post(URLSCAN_SCAN_API, json=payload, headers=headers)
            scan_data = scan_resp.json()

            if "uuid" not in scan_data:
                return None

            result_url = URLSCAN_RESULT_API + scan_data["uuid"]

            for _ in range(12):
                await asyncio.sleep(4)
                result_resp = await client.get(result_url)
                if result_resp.status_code == 200:
                    result_data = result_resp.json()
                    if result_data.get("page"):
                        screenshot_path = result_data.get("screenshotURL") or result_data.get("screenshot")
                        full_screenshot_url = (
                            screenshot_path if screenshot_path and screenshot_path.startswith("http")
                            else f"https://urlscan.io{screenshot_path}" if screenshot_path
                            else None
                        )
                        verdicts = result_data.get("verdicts", {}).get("overall", {})
                        score    = verdicts.get("score", 0)
                        return {
                            "source": "urlscan.io",
                            "Input URL":        result_data.get("task", {}).get("url"),
                            "Resolved URL":     result_data.get("page", {}).get("url"),
                            "IP Address":       result_data.get("page", {}).get("ip"),
                            "City":             result_data.get("page", {}).get("city"),
                            "Country":          result_data.get("page", {}).get("country"),
                            "ASN":              result_data.get("page", {}).get("asn"),
                            "ASN Name":         result_data.get("page", {}).get("asnname"),
                            "Domain":           result_data.get("page", {}).get("domain"),
                            "Server":           result_data.get("page", {}).get("server"),
                            "TLS Issuer":       result_data.get("page", {}).get("tlsIssuer"),
                            "TLS Valid From":   format_tls_date(result_data.get("page", {}).get("tlsValidFrom")),
                            "TLS Valid To":     format_tls_date(result_data.get("page", {}).get("tlsValidTo")) or "Unknown or Self-signed",
                            "Screenshot":       full_screenshot_url,
                            "Verdict (Readable)": {
                                "Score (0-100 Safety Rating)": f"{100 - score} / 100",
                                "Malicious":   verdicts.get("malicious"),
                                "Has Verdicts":verdicts.get("hasVerdicts"),
                                "Categories":  ", ".join(verdicts.get("categories", [])) or "None detected",
                                "Brands":      ", ".join(verdicts.get("brands", [])) or "None detected",
                                "Tags":        ", ".join(verdicts.get("tags", [])) or "None detected",
                            },
                            "Unique Countries": result_data.get("stats", {}).get("uniqCountries"),
                            "Processed At":     result_data.get("meta", {}).get("processed"),
                        }
        return None
    except Exception:
        return None


# ════════════════════════════════════════
# ENGINE 2 — VirusTotal
# ════════════════════════════════════════
async def scan_virustotal(domain: str):
    try:
        async with make_client() as client:
            # Submit URL
            url_id    = base64.urlsafe_b64encode(domain.encode()).decode().strip("=")
            headers   = {"x-apikey": VIRUSTOTAL_API_KEY}
            submit    = await client.post(
                VIRUSTOTAL_URL_API,
                headers=headers,
                data={"url": domain}
            )
            submit_data = submit.json()

            # Use existing analysis ID or fetch by URL id
            analysis_id = (
                submit_data.get("data", {}).get("id")
                or f"u-{url_id}-{{}}"
            )

            # Poll analysis
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            for _ in range(8):
                await asyncio.sleep(5)
                analysis_resp = await client.get(analysis_url, headers=headers)
                if analysis_resp.status_code == 200:
                    adata  = analysis_resp.json()
                    stats  = adata.get("data", {}).get("attributes", {}).get("stats", {})
                    status = adata.get("data", {}).get("attributes", {}).get("status", "")
                    if status == "completed":
                        malicious   = stats.get("malicious", 0)
                        suspicious  = stats.get("suspicious", 0)
                        harmless    = stats.get("harmless", 0)
                        undetected  = stats.get("undetected", 0)
                        total       = malicious + suspicious + harmless + undetected
                        safe_score  = max(0, 100 - int((malicious / max(total, 1)) * 100))

                        # Get URL info
                        url_resp = await client.get(
                            f"https://www.virustotal.com/api/v3/urls/{url_id}",
                            headers=headers
                        )
                        url_attrs = {}
                        if url_resp.status_code == 200:
                            url_attrs = url_resp.json().get("data", {}).get("attributes", {})

                        last_analysis = url_attrs.get("last_analysis_stats", stats)
                        categories    = url_attrs.get("categories", {})
                        cat_str       = ", ".join(set(categories.values())) if categories else "None detected"
                        tags          = url_attrs.get("tags", [])
                        tag_str       = ", ".join(tags) if tags else "None detected"

                        return {
                            "source": "VirusTotal",
                            "Input URL":        domain,
                            "Resolved URL":     url_attrs.get("url", domain),
                            "IP Address":       url_attrs.get("last_serving_ip_address", "N/A"),
                            "City":             "N/A",
                            "Country":          url_attrs.get("country", "N/A"),
                            "ASN":              str(url_attrs.get("asn", "N/A")),
                            "ASN Name":         url_attrs.get("as_owner", "N/A"),
                            "Domain":           url_attrs.get("tld", domain.split("/")[2] if "//" in domain else domain),
                            "Server":           url_attrs.get("last_http_response_headers", {}).get("server", "N/A"),
                            "TLS Issuer":       url_attrs.get("last_https_certificate", {}).get("issuer", {}).get("O", "N/A"),
                            "TLS Valid From":   url_attrs.get("last_https_certificate", {}).get("validity", {}).get("not_before", "N/A"),
                            "TLS Valid To":     url_attrs.get("last_https_certificate", {}).get("validity", {}).get("not_after", "N/A"),
                            "Screenshot":       None,
                            "Verdict (Readable)": {
                                "Score (0-100 Safety Rating)": f"{safe_score} / 100",
                                "Malicious":    malicious > 0,
                                "Has Verdicts": malicious > 0 or suspicious > 0,
                                "Categories":   cat_str,
                                "Brands":       "None detected",
                                "Tags":         tag_str,
                            },
                            "Unique Countries": 1,
                            "Processed At":     datetime.utcnow().isoformat() + "Z",
                            "VT Stats": {
                                "Malicious":  malicious,
                                "Suspicious": suspicious,
                                "Harmless":   harmless,
                                "Undetected": undetected,
                                "Total":      total,
                            }
                        }
        return None
    except Exception:
        return None


# ════════════════════════════════════════
# ENGINE 3 — IPQualityScore
# ════════════════════════════════════════
async def scan_ipqs(domain: str):
    try:
        import urllib.parse
        encoded_url = urllib.parse.quote(domain, safe="")
        api_url     = IPQS_API_URL.format(key=IPQS_API_KEY, url=encoded_url)

        async with make_client() as client:
            resp = await client.get(api_url)
            if resp.status_code != 200:
                return None

            data = resp.json()
            if not data.get("success"):
                return None

            risk_score  = data.get("risk_score", 0)
            safe_score  = max(0, 100 - risk_score)
            is_malicious = (
                data.get("malware", False) or
                data.get("phishing", False) or
                risk_score >= 85
            )
            is_suspicious = risk_score >= 50 and not is_malicious

            tags = []
            if data.get("phishing"):    tags.append("phishing")
            if data.get("malware"):     tags.append("malware")
            if data.get("suspicious"):  tags.append("suspicious")
            if data.get("spamming"):    tags.append("spam")
            if data.get("adult"):       tags.append("adult-content")

            cats = []
            if data.get("phishing"):   cats.append("Phishing")
            if data.get("malware"):    cats.append("Malware")
            if data.get("parking"):    cats.append("Domain Parking")
            if data.get("adult"):      cats.append("Adult")

            domain_name = data.get("domain", domain.split("/")[2] if "//" in domain else domain)

            return {
                "source": "IPQualityScore",
                "Input URL":        domain,
                "Resolved URL":     data.get("final_url", domain),
                "IP Address":       data.get("ip_address", "N/A"),
                "City":             data.get("city", "N/A"),
                "Country":          data.get("country_code", "N/A"),
                "ASN":              str(data.get("ASN", "N/A")),
                "ASN Name":         data.get("ISP", "N/A"),
                "Domain":           domain_name,
                "Server":           data.get("server", "N/A"),
                "TLS Issuer":       data.get("ssl_certificate", {}).get("issuer", "N/A") if isinstance(data.get("ssl_certificate"), dict) else "N/A",
                "TLS Valid From":   "N/A",
                "TLS Valid To":     "N/A",
                "Screenshot":       None,
                "Verdict (Readable)": {
                    "Score (0-100 Safety Rating)": f"{safe_score} / 100",
                    "Malicious":    is_malicious,
                    "Has Verdicts": is_malicious or is_suspicious,
                    "Categories":   ", ".join(cats) if cats else "None detected",
                    "Brands":       "None detected",
                    "Tags":         ", ".join(tags) if tags else "None detected",
                },
                "Unique Countries": 1,
                "Processed At":     datetime.utcnow().isoformat() + "Z",
                "IPQS Details": {
                    "Risk Score":       risk_score,
                    "Phishing":         data.get("phishing", False),
                    "Malware":          data.get("malware", False),
                    "Suspicious":       data.get("suspicious", False),
                    "Spamming":         data.get("spamming", False),
                    "Domain Age Days":  data.get("domain_age", {}).get("days", "N/A"),
                    "DNS Valid":        data.get("dns_valid", False),
                    "HTTPS":            data.get("https", False),
                    "Redirected":       data.get("redirected", False),
                }
            }
    except Exception:
        return None


# ════════════════════════════════════════
# MAIN ENDPOINT — Auto Fallback Chain
# ════════════════════════════════════════
@app.get("/scan")
async def scan_url(domain: str = Query(...)):
    print(f"\n[SCAN] Target: {domain}")

    # ── ENGINE 1: urlscan.io ──
    print("[1/3] Trying urlscan.io...")
    result = await scan_urlscan(domain)
    if result:
        print("[1/3] urlscan.io SUCCESS")
        return result

    # ── ENGINE 2: VirusTotal ──
    print("[2/3] urlscan.io failed. Trying VirusTotal...")
    result = await scan_virustotal(domain)
    if result:
        print("[2/3] VirusTotal SUCCESS")
        return result

    # ── ENGINE 3: IPQualityScore ──
    print("[3/3] VirusTotal failed. Trying IPQualityScore...")
    result = await scan_ipqs(domain)
    if result:
        print("[3/3] IPQualityScore SUCCESS")
        return result

    # ── ALL FAILED ──
    print("[!] All engines failed.")
    return {"error": "All scan engines failed or timed out. Please try again in a moment."}

# ════════════════════════════════════════
# PHONE NUMBER INTELLIGENCE
# ════════════════════════════════════════
import re

@app.get("/phone")
async def analyze_phone(number: str = Query(...)):
    """Analyze phone number using NumVerify (free tier) + heuristics"""
    try:
        # Clean number
        cleaned = re.sub(r'[\s\-\(\)\+]', '', number)
        
        # NumVerify free API (1000 req/month free)
        NUMVERIFY_KEY = "ac556dc46c4d5cccc5033cdbb0a27a85"  # get free at numverify.com
        
        async with make_client() as client:
            resp = await client.get(
                f"http://apilayer.net/api/validate?access_key={NUMVERIFY_KEY}&number={cleaned}&format=1"
            )
            data = resp.json()
            
            # Heuristics
            risk_signals = []
            risk_score = 0
            
            if not data.get("valid"):
                risk_signals.append("Invalid number format")
                risk_score += 40
            
            line_type = data.get("line_type", "unknown")
            if line_type == "voip":
                risk_signals.append("VoIP number — commonly used in scams")
                risk_score += 35
            elif line_type == "tollfree":
                risk_signals.append("Toll-free — verify legitimacy")
                risk_score += 10
            elif line_type == "premium":
                risk_signals.append("Premium rate — potential fraud risk")
                risk_score += 45
            
            country = data.get("country_code", "")
            high_risk_countries = ["NG","GH","PK","IN","PH","VN","RO","UA"]
            if country in high_risk_countries:
                risk_signals.append(f"High-risk origin country: {country}")
                risk_score += 20
            
            # Check if number appears in known scam patterns
            scam_patterns = [
                r'^1900',      # Premium rate
                r'^0900',      # Premium rate EU
                r'(\d)\1{6,}', # Repeated digits
            ]
            for pattern in scam_patterns:
                if re.search(pattern, cleaned):
                    risk_signals.append("Matches known scam number pattern")
                    risk_score += 30
                    break
            
            risk_score = min(100, risk_score)
            verdict = "SAFE" if risk_score < 30 else "SUSPICIOUS" if risk_score < 65 else "MALICIOUS"
            
            return {
                "number": data.get("international_format", number),
                "valid": data.get("valid", False),
                "country": data.get("country_name", "Unknown"),
                "country_code": data.get("country_code", "N/A"),
                "location": data.get("location", "Unknown"),
                "carrier": data.get("carrier", "Unknown"),
                "line_type": line_type,
                "risk_score": risk_score,
                "verdict": verdict,
                "risk_signals": risk_signals,
                "local_format": data.get("local_format", "N/A"),
                "international_format": data.get("international_format", "N/A"),
            }
    except Exception as e:
        return {"error": str(e)}


# ════════════════════════════════════════
# WHOIS / DOMAIN AGE
# ════════════════════════════════════════
@app.get("/whois")
async def whois_lookup(domain: str = Query(...)):
    """Real WHOIS using RDAP (free, no key needed)"""
    try:
        # Extract domain from URL if needed
        if domain.startswith("http"):
            from urllib.parse import urlparse
            domain = urlparse(domain).netloc
        
        async with make_client() as client:
            # Try RDAP first
            rdap_resp = await client.get(f"https://rdap.org/domain/{domain}")
            
            result = {
                "domain": domain,
                "registrar": "Unknown",
                "created": "Unknown",
                "expires": "Unknown",
                "updated": "Unknown",
                "age_days": None,
                "status": [],
                "nameservers": [],
                "registrant_country": "Unknown",
                "is_new_domain": False,
                "risk_flags": []
            }
            
            if rdap_resp.status_code == 200:
                rdap = rdap_resp.json()
                
                # Parse events (creation, expiry dates)
                for event in rdap.get("events", []):
                    action = event.get("eventAction", "")
                    date   = event.get("eventDate", "")
                    if "registration" in action:
                        result["created"] = date
                        try:
                            created_dt = datetime.fromisoformat(date.replace("Z","+00:00"))
                            age = (datetime.now(created_dt.tzinfo) - created_dt).days
                            result["age_days"] = age
                            result["is_new_domain"] = age < 30
                            if age < 30:
                                result["risk_flags"].append("⚠ Domain registered less than 30 days ago")
                            elif age < 90:
                                result["risk_flags"].append("⚠ Domain less than 90 days old")
                        except:
                            pass
                    elif "expiration" in action:
                        result["expires"] = date
                    elif "last changed" in action:
                        result["updated"] = date
                
                # Registrar
                for entity in rdap.get("entities", []):
                    roles = entity.get("roles", [])
                    if "registrar" in roles:
                        vcard = entity.get("vcardArray", [])
                        if vcard and len(vcard) > 1:
                            for item in vcard[1]:
                                if item[0] == "fn":
                                    result["registrar"] = item[3]
                
                # Status & nameservers
                result["status"] = rdap.get("status", [])
                result["nameservers"] = [
                    ns.get("ldhName","") 
                    for ns in rdap.get("nameservers", [])
                ]
                
                # Privacy protection check
                if any("privacy" in str(s).lower() for s in result["status"]):
                    result["risk_flags"].append("ℹ WHOIS privacy protection enabled")
                
                # Suspicious TLD check
                suspicious_tlds = [".xyz",".top",".click",".loan",".work",".gq",".ml",".ga",".cf",".tk"]
                if any(domain.endswith(t) for t in suspicious_tlds):
                    result["risk_flags"].append("⚠ High-risk TLD detected")
            
            return result
    except Exception as e:
        return {"error": str(e)}


# ════════════════════════════════════════
# SSL DEEP INSPECTOR
# ════════════════════════════════════════
@app.get("/ssl")
async def ssl_inspect(domain: str = Query(...)):
    """Deep SSL/TLS inspection"""
    import ssl as ssl_lib
    import socket
    from datetime import timezone
    
    try:
        if domain.startswith("http"):
            from urllib.parse import urlparse
            domain = urlparse(domain).netloc
        
        # Remove port if present
        hostname = domain.split(":")[0]
        port = 443
        
        context = ssl_lib.create_default_context()
        result = {
            "domain": hostname,
            "valid": False,
            "issuer": {},
            "subject": {},
            "version": "Unknown",
            "expires": "Unknown",
            "issued": "Unknown",
            "days_remaining": None,
            "expired": False,
            "self_signed": False,
            "weak_protocol": False,
            "risk_flags": [],
            "san_domains": [],
            "grade": "F"
        }
        
        try:
            conn = context.wrap_socket(
                socket.create_connection((hostname, port), timeout=10),
                server_hostname=hostname
            )
            cert = conn.getpeercert()
            cipher = conn.cipher()
            protocol = conn.version()
            conn.close()
            
            result["valid"] = True
            result["version"] = protocol
            
            # Parse issuer / subject
            issuer  = dict(x[0] for x in cert.get("issuer", []))
            subject = dict(x[0] for x in cert.get("subject", []))
            result["issuer"]  = issuer
            result["subject"] = subject
            
            # Expiry
            not_after  = cert.get("notAfter","")
            not_before = cert.get("notBefore","")
            result["issued"]  = not_before
            result["expires"] = not_after
            
            if not_after:
                exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                now_dt = datetime.now(timezone.utc)
                days   = (exp_dt - now_dt).days
                result["days_remaining"] = days
                result["expired"] = days < 0
                if days < 0:
                    result["risk_flags"].append("🚨 Certificate has EXPIRED")
                elif days < 14:
                    result["risk_flags"].append(f"⚠ Certificate expires in {days} days")
                elif days < 30:
                    result["risk_flags"].append(f"ℹ Certificate expires in {days} days")
            
            # Self-signed check
            if issuer.get("organizationName") == subject.get("organizationName"):
                result["self_signed"] = True
                result["risk_flags"].append("⚠ Self-signed certificate detected")
            
            # Weak protocol check
            if protocol in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                result["weak_protocol"] = True
                result["risk_flags"].append(f"🚨 Weak protocol: {protocol}")
            
            # SAN domains
            san = cert.get("subjectAltName", [])
            result["san_domains"] = [v for t,v in san if t == "DNS"]
            
            # Cipher info
            result["cipher"] = {
                "name": cipher[0] if cipher else "Unknown",
                "protocol": cipher[1] if cipher else "Unknown",
                "bits": cipher[2] if cipher else 0
            }
            
            # Grade
            if result["expired"] or result["self_signed"]:
                result["grade"] = "F"
            elif result["weak_protocol"]:
                result["grade"] = "C"
            elif days and days > 30 and not result["risk_flags"]:
                result["grade"] = "A+"
            elif not result["risk_flags"]:
                result["grade"] = "A"
            else:
                result["grade"] = "B"
                
        except ssl_lib.SSLError as e:
            result["risk_flags"].append(f"🚨 SSL Error: {str(e)}")
        except socket.timeout:
            result["risk_flags"].append("⚠ Connection timed out")
            
        return result
    except Exception as e:
        return {"error": str(e)}


# ════════════════════════════════════════
# THREAT FEED (Live IOCs)
# ════════════════════════════════════════
@app.get("/threatfeed")
async def threat_feed():
    """Pull latest threats from URLhaus"""
    try:
        async with make_client() as client:
            # URLhaus recent URLs (free, no key)
            resp = await client.post(
                "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                data={"limit": 20}
            )
            data = resp.json()
            urls = data.get("urls", [])
            
            threats = []
            for u in urls[:20]:
                threats.append({
                    "url":        u.get("url",""),
                    "threat":     u.get("threat","unknown"),
                    "tags":       u.get("tags") or [],
                    "country":    u.get("country","Unknown"),
                    "date_added": u.get("date_added",""),
                    "status":     u.get("url_status","unknown"),
                    "reporter":   u.get("reporter","anonymous"),
                })
            
            return {
                "source":    "URLhaus (abuse.ch)",
                "count":     len(threats),
                "threats":   threats,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
    except Exception as e:
        return {"error": str(e)}
# ════════════════════════════════════════
# HEALTH CHECK
# ════════════════════════════════════════
@app.get("/health")
async def health():
    return {"status": "online", "engines": ["urlscan.io", "VirusTotal", "IPQualityScore"]}
