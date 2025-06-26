import os
import sys
import json
import csv
from datetime import datetime, timedelta
from mitmproxy.io import FlowReader
import socket
import mimetypes
from json import JSONDecodeError

# Only EXTENSION_NAME needs to be changed if the same directory structure if followed
# EXTENSION_NAME = "Merlin" # "Monica", "Sider", "Perplexity", "Merlin", "Max.AI", "Harpa", "ChatGPT4Google", "TinaMind", "WiseOne", "ChatsNow",  "Max.AI", "Copilot"
EXTENSION_NAME = sys.argv[1] if len(sys.argv) > 1 else "Merlin"
SPACE = "PublicSpaces" # "PrivateSpaces", "PublicSpaces"

# FLOW_DIRECTORY = f"./Flows/Combined/{SPACE}/{EXTENSION_NAME}"
# OUTPUT_CSV = f"./Flows/Combined/{SPACE}/{EXTENSION_NAME}.csv"

FLOW_DIRECTORY = f"./Flows/{EXTENSION_NAME}"
OUTPUT_CSV = f"./Output/{EXTENSION_NAME}.csv"

DISCONNECT_JSON = "disconnect.json"
DDG_JSON = "ddg.json"
with open(DDG_JSON, "r", encoding="utf-8") as f:
    DDG = json.load(f)


def map_third_party(third_party):
    global EXTENSION_NAME, DDG;
    extension_mapping = {"monica": "monica.im", "sider": "sider.ai", "perplexity": "perplexity.ai", "merlin": "getmerlin.in", "max.ai": "max.ai", "harpa": "harpa.ai", "chatgpt4google": "chatgpt4google.com", "tinamind": "tinamind.com", "wiseone": "wiseone.com", 
    "chatsnow": "chatsnow.com", "copilot": "copilot.com"}
        
    extension_domain = extension_mapping.get(EXTENSION_NAME.lower(), None)
    if not extension_domain:
        return None

    extension_owner_url = DDG.get(extension_domain, {}).get("owner", {}).get("url", None)
    third_party_owner_url = DDG.get(third_party, {}).get("owner", {}).get("url", None)

    if ((extension_owner_url is not None) and (third_party_owner_url is not None) and (extension_owner_url == third_party_owner_url)):
        return extension_owner_url
    else:
        return None


# Function to load or generate disconnect mapping
def load_disconnect_mapping(json_path):
    mapping_file = "disconnect_mapping.json"

    # Check if mapping already exists
    if os.path.exists(mapping_file):
        with open(mapping_file, "r", encoding="utf-8") as f:
            return json.load(f)

    # Load disconnect.json and create mapping
    with open(json_path, "r", encoding="utf-8") as f:
        disconnect_data = json.load(f)

    host_to_category = {}
    for category, entries in disconnect_data.get("categories", {}).items():
        for entry in entries:
            for host_dict in entry.values():
                for host_list in host_dict.values():
                    for host in host_list:
                        host_to_category[host] = category

    # Save mapping to file
    with open(mapping_file, "w", encoding="utf-8") as f:
        json.dump(host_to_category, f, indent=4)

    return host_to_category

# Function to parse .flow files and extract data
def parse_flow_files(flow_dir, output_csv):
    global DISCONNECT_JSON;
    disconnect_mapping = load_disconnect_mapping(DISCONNECT_JSON)

    output_rows = []
    headers_list = ["req_header_cookie", "res_header_cookie", "req_header_set-cookie", "res_header_set-cookie", "req_header_referer", "res_header_referer", "res_header_referrer-policy", "req_header_origin", "res_header_origin", "req_header_origin-agent-cluster", "req_header_sec-browsing-topics", "res_header_sec-browsing-topics", "req_header_content-length", "res_header_content-length", "req_header_service-worker-allowed", "res_header_service-worker-allowed", "req_header_service-worker", "res_header_service-worker", "req_header_x-client-type", "res_header_x-client-type", "req_header_x-client-locale", "res_header_x-client-locale", "req_header_x-product-name", "res_header_x-product-name", "req_header_x-client-id", "res_header_x-client-id", "req_header_x-client-data", "res_header_x-client-data", "req_header_x-client-browser", "res_header_x-client-browser", "res_header_x-fb-connection-quality", "res_header_x-fb-debug", "req_header_x-fb-connection-quality", "req_header_x-fb-debug", "req_header_sec-fetch-dest", "res_header_sec-fetch-dest", "req_header_x-browser-year", "res_header_x-browser-year", "req_header_x-browser-copyright", "req_header_x-browser-channel", "res_header_etag", "req_header_etag", "req_header_content-type", "res_header_content-type", "res_header_x-content-type-options", "res_header_content-encoding", "res_header_server", "req_header_server", "req_header_x-servername", "res_header_x-servername", "res_header_x-frame-options", "req_header_x-frame-options", "res_header_via", "req_header_via", "req_header_x-xss-protection", "res_header_x-xss-protection", "req_header_x-cache", "res_header_x-cache", "req_header_cache-control", "res_header_cache-control", "req_header_cf-cache-status", "res_header_cf-cache-status", "res_header_p3p", "res_header_x-msedge-ref", "req_header_x-msedge-ref", "req_header_x-country", "res_header_x-country", "req_header_location", "res_header_location", "req_header_request-context", "req_header_x-robots-tag", "res_header_x-robots-tag", "res_header_x-connection-hash", "req_header_ping-from", "res_header_ping-from", "req_header_ping-to", "res_header_ping-to", "req_header_x-privacy-policy", "res_header_x-privacy-policy", "res_header_purpose", "req_header_x-requestid", "req_header_x-request-id", "res_header_x-request-id", "req_header_x-ms-request-id", "res_header_x-ms-request-id", "req_header_x-cdn-traceid", "res_header_x-cdn-traceid", "req_header_x-transaction-id", "req_header_x-fd-int-roxy-purgeid", "res_header_cross-origin-opener-policy", "res_header_content-security-policy", "res_header_cross-origin-opener-policy-report-only", "res_header_cross-origin-resource-policy", "req_header_content-security-policy-report-only", "req_header_cross-origin-embedder-policy-report-only", "req_header_cross-origin-opener-policy", "req_header_content-security-policy", "req_header_referrer-policy", "req_header_cross-origin-opener-policy-report-only", "req_header_cross-origin-resource-policy", "res_header_cross-origin-embedder-policy-report-only", "res_header_x-ratelimit-remaining", "res_header_x-ratelimit-reset", "res_header_x-ratelimit-limit", "req_header_x-ratelimit-remaining", "req_header_x-ratelimit-reset", "req_header_x-ratelimit-limit", "req_header_x-permitted-cross-domain-policies", "req_header_access-control-request-headers", "req_header_access-control-request-method", "res_header_access-control-allow-origin", "res_header_access-control-allow-credentials", "res_header_access-control-allow-headers", "res_header_access-control-allow-methods", "req_header_access-control-allow-origin", "req_header_access-control-allow-credentials", "req_header_access-control-allow-headers", "req_header_access-control-allow-methods", "req_header_access-control-expose-headers", "req_header_x-connection-hash", "req_header_content-range", "req_header_x-metered-usage", "req_header_x-cloud-trace-context", "req_header_strict-transport-security", "req_header_purpose", "req_header_sec-purpose", "req_header_x-same-domain", "req_header_no-vary-search", "req_header_x-content-type-options", "req_header_x-ms-version", "req_header_surrogate-key", "res_header_surrogate-key", "req_header_surrogate-control", "res_header_surrogate-control"]
    unimp_headers = ["req_header_x-connection-hash", "req_header_x-frame-options", "res_header_x-cache", "req_header_cross-origin-opener-policy-report-only", "req_header_access-control-request-method", "req_header_x-client-locale", "res_header_x-cdn-traceid", "req_header_cross-origin-opener-policy", "res_header_cross-origin-opener-policy-report-only", "res_header_x-browser-year", "req_header_etag", "req_header_x-browser-copyright", "req_header_content-length", "req_header_cross-origin-resource-policy", "req_header_server", "res_header_sec-fetch-dest", "req_header_x-ratelimit-limit", "res_header_surrogate-control", "req_header_surrogate-control", "req_header_access-control-allow-methods", "req_header_location", "req_header_sec-purpose", "res_header_service-worker", "req_header_x-cache", "req_header_x-browser-year", "res_header_x-product-name", "res_header_x-country", "res_header_cross-origin-opener-policy", "req_header_content-security-policy-report-only", "req_header_x-request-id", "req_header_via", "req_header_cache-control", "req_header_access-control-allow-credentials", "req_header_x-metered-usage", "req_header_cf-cache-status", "req_header_no-vary-search", "res_header_x-frame-options", "req_header_x-country", "req_header_access-control-allow-origin", "req_header_x-same-domain", "req_header_x-content-type-options", "req_header_purpose", "req_header_x-fd-int-roxy-purgeid", "req_header_x-cdn-traceid", "res_header_surrogate-key", "res_header_cross-origin-embedder-policy-report-only", "res_header_cross-origin-resource-policy", "req_header_surrogate-key", "req_header_x-servername", "res_header_referrer-policy", "req_header_access-control-request-headers", "req_header_x-client-browser", "res_header_content-length", "req_header_access-control-allow-headers", "res_header_x-client-browser", "req_header_content-range", "req_header_access-control-expose-headers", "req_header_x-cloud-trace-context", "req_header_cross-origin-embedder-policy-report-only", "req_header_x-browser-channel", "req_header_x-transaction-id", "req_header_x-robots-tag", "req_header_content-security-policy", "req_header_x-permitted-cross-domain-policies", "res_header_access-control-allow-credentials", "req_header_referrer-policy", "req_header_strict-transport-security", "req_header_origin-agent-cluster", "res_header_x-client-locale", "res_header_x-client-id", "res_header_x-content-type-options", "res_header_x-xss-protection", "req_header_x-xss-protection", "res_header_purpose"]
    headers_list = [header for header in headers_list if header not in unimp_headers]
    # headers_set = set(headers_list)
    categories_of_interest = [
        "Advertising", 
        "Analytics", 
        "FingerprintingInvasive", 
        "FingerprintingGeneral",
        "Social"
    ]

    # Iterate through .flow files in the directory
    for filename in os.listdir(flow_dir):
        if not filename.startswith(EXTENSION_NAME) or not filename.endswith(".flow"):
            continue

        file_path = os.path.join(flow_dir, filename)
        print(filename)

        with open(file_path, "rb") as file:  # Open in binary mode
            try:
                reader = FlowReader(file)
            except Exception as e:
                # print(f"Skipping invalid or unreadable .flow file: {filename} ({e})")
                continue

            cutoff_time = None

            # Process each flow
            for flow in reader.stream():
                if not hasattr(flow, "request") or not flow.request:
                    continue

                request = flow.request
                response = flow.response
                timestamp = flow.request.timestamp_start

                if timestamp is None:
                    continue

                # Convert timestamp to datetime object
                timestamp_dt = datetime.fromtimestamp(timestamp)
                request_domain = request.host
                request_url = request.url
                method = request.method
                status = response.status_code if response else None
                
                if response:
                    try:
                        if response.content:
                            # Attempt to get content based on encoding
                            response_body = response.content.decode("utf-8", errors="replace")
                            size = len(response.content)
                        else:
                            response_body = ""
                            size = 0
                    except ValueError as e:
                        # Handle invalid content encoding gracefully
                        # print(f"{request_domain} | {request_url}: Skipping response content due to invalid encoding: {e}")
                        response_body = "[Invalid Content-Encoding]"
                        size = 0
                else:
                    response_body = ""
                    size = 0

                if response:
                    try:
                        if response.content:
                            size = len(response.content)
                        else:
                            size = 0
                    except ValueError as e:
                        size = 0
                else:
                    size = 0
                cookies = request.cookies.fields
                
                # payload = parse_payload(request.content, request.headers)
                try:
                    if request.content:
                        try:
                            payload = request.content.decode("utf-8")
                        except UnicodeDecodeError:
                            payload = "[Binary or Non-UTF-8 Content]"
                    else:
                        payload = ""
                except BaseException as e:
                    continue

                request_headers = request.headers
                response_headers = response.headers if response else {}
                disconnect_category = disconnect_mapping.get(request_domain, "Other")
                origin_header = request_headers.get("origin", "")
                context = "Extension" if origin_header.startswith("chrome-extension://") else "Foreground"

                # Considering only Extension, ATS data or data related to LLMs
                if (context == "Extension") or (disconnect_category in categories_of_interest):
                    pass
                elif disconnect_category not in categories_of_interest:
                    # if any(word in payload.lower() or word in response_body.lower() or word in request_url.lower() or word in response_body.lower() or word in cookies for word in ["chatgpt", "openai", EXTENSION_NAME.lower()]):
                    flag = False
                    for word in ["chatgpt", "openai", EXTENSION_NAME.lower()]:
                        if word in request_url.lower():
                            flag = True
                            break;
                    if flag:
                        pass
                    else:
                        continue

                # Collect all unique headers
                content_type = response_headers.get("content-type", "").lower()
                if content_type.startswith("text/html"):
                    response_body = "[HTML File/Code]"
                elif "javascript" in content_type or request_url.endswith(".js"):
                    response_body = "[Javascript File/Code]"
                elif "css" in content_type or request_url.endswith(".css"):
                    response_body = "[CSS File/Code]"
                elif content_type.startswith("image/") or request_url.endswith(".png"):
                    response_body = "[Media/Image]"
                elif content_type.startswith("video/") or request_url.endswith(".mp4"):
                    response_body = "[Media/Video]"

                parent = map_third_party(request_domain)
                row = {
                    "extension": EXTENSION_NAME,
                    "filename": filename,
                    "timestamp": timestamp,
                    "request_url": request_url,
                    "request_domain": parent if parent is not None else request_domain,
                    "method": method,
                    "status": status,
                    "response": "\n".join(line for line in response_body.splitlines() if line.strip()),
                    "payload": payload,
                    "size": size,
                    "cookies": json.dumps(cookies),
                    "disconnect_category": disconnect_category,
                    "context": context,
                    "contacted_party": "first-party" if EXTENSION_NAME.lower() in request_domain or parent is not None else "third-party"
                }

                # Include request and response headers
                for header in headers_list:
                    if "req_header_" in header:
                        row[header] = request_headers.get(header.replace("req_header_", ""), "")
                    elif "res_header_" in header:
                        row[header] = response_headers.get(header.replace("res_header_", ""), "")
                
                output_rows.append(row)

    # Write to CSV
    fieldnames = [
        "extension", "filename", "timestamp", "context", "disconnect_category", 
        "contacted_party", "request_domain", "request_url", "method", "status", 
        "response", "payload", "size", "cookies"
    ] + [header for header in headers_list]
    # + [f"req_header_{header}" for header in headers_set] + [f"res_header_{header}" for header in headers_set]
    
    with open(f"{output_csv}", "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output_rows)


if __name__ == "__main__":
    parse_flow_files(FLOW_DIRECTORY, OUTPUT_CSV)
    print(f"Output saved!")
