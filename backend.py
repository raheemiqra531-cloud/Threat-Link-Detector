# from fastapi import FastAPI, Query
# from fastapi.middleware.cors import CORSMiddleware
# import httpx
# import ssl
# import certifi
# import asyncio
# import json

# app = FastAPI()

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# URLSCAN_SCAN_API = "https://urlscan.io/api/v1/scan/"
# URLSCAN_RESULT_API = "https://urlscan.io/api/v1/result/"
# API_KEY = "0197a872-01f3-70dc-a778-719594c68cf1"

# @app.get("/scan")
# async def scan_url(domain: str = Query(...)):
#     try:
#         ssl_context = ssl.create_default_context(cafile=certifi.where())
#         transport = httpx.AsyncHTTPTransport(verify=ssl_context)
#         async with httpx.AsyncClient(transport=transport, timeout=60.0) as client:
#             payload = {"url": domain, "visibility": "public"}
#             headers = {"Content-Type": "application/json", "API-Key": API_KEY}
#             scan_resp = await client.post(URLSCAN_SCAN_API, json=payload, headers=headers)
#             scan_data = scan_resp.json()

#             if 'uuid' not in scan_data:
#                 return {"error": "Failed to submit scan."}

#             scan_uuid = scan_data["uuid"]
#             result_url = URLSCAN_RESULT_API + scan_uuid

#             # Wait until the result is ready
#             for _ in range(15):
#                 result_resp = await client.get(result_url)
#                 if result_resp.status_code == 200:
#                     result_data = result_resp.json()

#                     if result_data.get("page"):
#                         screenshot_path = result_data.get("screenshotURL") or result_data.get("screenshot")
#                         full_screenshot_url = screenshot_path if screenshot_path and screenshot_path.startswith("http") else f"https://urlscan.io{screenshot_path}" if screenshot_path else None

#                         verdicts = result_data.get("verdicts", {}).get("overall", {})
#                         score = verdicts.get("score", 0)

#                         readable_verdicts = {
#                             "Score (0-100 Safety Rating)": f"{100 - score} / 100",
#                             "Malicious": verdicts.get("malicious"),
#                             "Has Verdicts": verdicts.get("hasVerdicts"),
#                             "Categories": ", ".join(verdicts.get("categories", [])) or "Unknown",
#                             "Brands": ", ".join(verdicts.get("brands", [])) or "Unknown",
#                             "Tags": ", ".join(verdicts.get("tags", [])) or "Unknown"
#                         }

#                         return {
#                             "Input URL": result_data.get("task", {}).get("url"),
#                             "Resolved URL": result_data.get("page", {}).get("url"),
#                             "IP Address": result_data.get("page", {}).get("ip"),
#                             "City": result_data.get("page", {}).get("city"),
#                             "Country": result_data.get("page", {}).get("country"),
#                             "ASN": result_data.get("page", {}).get("asn"),
#                             "ASN Name": result_data.get("page", {}).get("asnname"),
#                             "Domain": result_data.get("page", {}).get("domain"),
#                             "Server": result_data.get("page", {}).get("server"),
#                             "TLS Issuer": result_data.get("page", {}).get("tlsIssuer"),
#                             "TLS Valid From": result_data.get("page", {}).get("tlsValidFrom"),
# "TLS Valid To": result_data.get("page", {}).get("tlsValidTo") or "Unknown or Self-signed",
#                             "Screenshot": full_screenshot_url,
#                             "Verdict (Readable)": readable_verdicts,
#                             "Unique Countries": result_data.get("stats", {}).get("uniqCountries"),
#                             "Processed At": result_data.get("meta", {}).get("processed")
#                         }
#                 await asyncio.sleep(3)

#             return {"error": "Scan result not ready in time."}

#     except Exception as e:
#         return {"error": str(e)}
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
import httpx
import ssl
import certifi
import asyncio
import json
from datetime import datetime

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

URLSCAN_SCAN_API = "https://urlscan.io/api/v1/scan/"
URLSCAN_RESULT_API = "https://urlscan.io/api/v1/result/"
API_KEY = "0197a872-01f3-70dc-a778-719594c68cf1"

def format_tls_date(date_str):
    if date_str:
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00")).strftime("%B %d, %Y at %H:%M:%S UTC")
        except:
            return date_str
    return "Unknown"

@app.get("/scan")
async def scan_url(domain: str = Query(...)):
    try:
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        transport = httpx.AsyncHTTPTransport(verify=ssl_context)
        async with httpx.AsyncClient(transport=transport, timeout=60.0) as client:
            payload = {"url": domain, "visibility": "public"}
            headers = {"Content-Type": "application/json", "API-Key": API_KEY}
            scan_resp = await client.post(URLSCAN_SCAN_API, json=payload, headers=headers)
            scan_data = scan_resp.json()

            if 'uuid' not in scan_data:
                return {"error": "Failed to submit scan."}

            scan_uuid = scan_data["uuid"]
            result_url = URLSCAN_RESULT_API + scan_uuid

            for _ in range(15):
                result_resp = await client.get(result_url)
                if result_resp.status_code == 200:
                    result_data = result_resp.json()

                    if result_data.get("page"):
                        screenshot_path = result_data.get("screenshotURL") or result_data.get("screenshot")
                        full_screenshot_url = screenshot_path if screenshot_path and screenshot_path.startswith("http") else f"https://urlscan.io{screenshot_path}" if screenshot_path else None

                        verdicts = result_data.get("verdicts", {}).get("overall", {})
                        score = verdicts.get("score", 0)

                        readable_verdicts = {
                            "Score (0-100 Safety Rating)": f"{100 - score} / 100",
                            "Malicious": verdicts.get("malicious"),
                            "Has Verdicts": verdicts.get("hasVerdicts"),
                            "Categories": ", ".join(verdicts.get("categories", [])) or "None detected",
                            "Brands": ", ".join(verdicts.get("brands", [])) or "None detected",
                            "Tags": ", ".join(verdicts.get("tags", [])) or "None detected"
                        }

                        return {
                            "Input URL": result_data.get("task", {}).get("url"),
                            "Resolved URL": result_data.get("page", {}).get("url"),
                            "IP Address": result_data.get("page", {}).get("ip"),
                            "City": result_data.get("page", {}).get("city"),
                            "Country": result_data.get("page", {}).get("country"),
                            "ASN": result_data.get("page", {}).get("asn"),
                            "ASN Name": result_data.get("page", {}).get("asnname"),
                            "Domain": result_data.get("page", {}).get("domain"),
                            "Server": result_data.get("page", {}).get("server"),
                            "TLS Issuer": result_data.get("page", {}).get("tlsIssuer"),
                            "TLS Valid From": format_tls_date(result_data.get("page", {}).get("tlsValidFrom")),
                            "TLS Valid To": format_tls_date(result_data.get("page", {}).get("tlsValidTo")) or "Unknown or Self-signed",
                            "Screenshot": full_screenshot_url,
                            "Verdict (Readable)": readable_verdicts,
                            "Unique Countries": result_data.get("stats", {}).get("uniqCountries"),
                            "Processed At": result_data.get("meta", {}).get("processed")
                        }
                await asyncio.sleep(3)

            return {"error": "Scan result not ready in time."}

    except Exception as e:
        return {"error": str(e)}
