import json
import os
from mitmproxy import http
import mitmproxy
import httpx
import requests
import re
import datetime

# --- LLM Configuration ---
ENABLE_LLM_ANALYSIS = True
MY_LLM_API_KEY = os.environ.get("OPENROUTER_API_KEY", "YOUR_OPENROUTER_API_KEY")
MY_LLM_MODEL = "google/gemini-pro" # Or your preferred model (e.g., "anthropic/claude-3-haiku-20240307")

# Define the key for the highest privilege profile in USER_PROFILES
HIGHEST_PRIV_PROFILE_KEY = "account_manager" # This will be used in logic instead of hardcoded names

# NEW: Keywords to identify delete-like operations in the URL path
DELETE_KEYWORDS = ["delete", "remove", "destroy", "disable", "deactivate"]


SYSTEM_PROMPT = """
You are an expert security analyst specializing in authorization and access control. Your task is to analyze web application request data for potential authorization bypasses or permission scheme vulnerabilities. You will be provided with role definitions and comparative data for a specific API request, observed across ALL relevant user profiles. Your analysis should focus on identifying discrepancies that suggest any low-privileged user can perform actions or access data they shouldn't, or if any profile exhibits unexpected behavior given its permissions.

Crucial HTTP Status Codes:
- 2xx: Success
- 401: Unauthorized (Authentication issue)
- 403: Forbidden (Authorization issue - primary expected response for denied access)
- 404: Not Found (Could indicate an object-level authorization issue if a high-priv user sees it and a low-priv user doesn't)

Consider the collective behavior of all provided profiles for the given endpoint against the defined role capabilities.
"""

ROLE_DEFINITIONS = """
Below are the definitions for each role:
Account manager: User can control account settings, user access billing center, and download account reports. User can add and edit campaigns (status, bid, budget) and ads (headline, image & copy).
Viewer: User can view campaigns and ads.
"""
# --- End LLM Configuration ---


# Define user profiles with cookies, headers, and a descriptive label
USER_PROFILES = {
    "account_manager": { # This profile will initiate the original client request
        "label": "Account Manager",
        "cookies": {}, # No cookies needed if this is the initial traffic capture
        "headers": {}
    },
    "viewer": {
        "label": "Viewer",
        "cookies": {"JSESSIONID":"ajax:aaaaaa"},
        "headers": {"Csrf-Token": 'ajax:aaaaaa', "X-Pwnfox-Color": "yellow"},
    }
}

# List of profiles to rotate through. Ensure these keys exist in USER_PROFILES.
PROFILE_ROTATION = list(USER_PROFILES.keys())


# Target domain and path for filtering
TARGET_DOMAIN = "www.target.com"
TARGET_PATH = "/api"

# Upstream HTTP proxy (e.g., Burp Suite)
UPSTREAM_PROXY = "http://127.0.0.1:8080"
CAIDO_PROXY = "http://127.0.0.1:9090"

# Ensure directories for responses and logs exist
os.makedirs("responses", exist_ok=True)
os.makedirs("logs", exist_ok=True)

# Log file paths
CSV_LOG_FILE = "logs/comparison_log.csv"
LLM_LOG_FILE = "logs/llm_analysis_log.jsonl"

# Dictionary to store all response details for comparison
response_data_store = {}

# Set to keep track of endpoints that have been fully logged to the CSV file
logged_endpoints_to_file = set()

# Dictionary to hold original DELETE-like flows that are waiting for replayed responses
# Key: original flow's id, Value: the original http.HTTPFlow object
original_delete_flows_waiting_for_reply = {}


# Initialize the CSV log file with headers
def write_csv_log_header():
    with open(CSV_LOG_FILE, "w", encoding="utf-8") as log:
        header_parts = ["Method", "Endpoint"]
        for role_key in USER_PROFILES.keys():
            header_parts.append(f"{USER_PROFILES[role_key]['label']} Status Code")
            header_parts.append(f"{USER_PROFILES[role_key]['label']} Content Length")
        log.write(",".join(header_parts) + "\n")

write_csv_log_header()


def sanitize_filename(path):
    """Sanitizes a string to be used as a filename."""
    s = re.sub(r'[^a-zA-Z0-9_.-]', '_', path)
    s = s.strip('_')
    return s[:200]

def save_response_to_file(profile, path, response_text):
    """
    Save the response to a file for the given profile and path.
    """
    sanitized_path = sanitize_filename(path)
    filename = f"responses/{profile}_{sanitized_path}.json"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump({"path": path, "response": response_text}, f, indent=4)
    except Exception as e:
        print(f"Error saving response to file {filename}: {e}")

def update_response_data_store(method, endpoint, profile, status_code, response_size):
    """
    Updates the in-memory data store for response details.
    """
    if endpoint not in response_data_store:
        response_data_store[endpoint] = {
            "method": method,
            "profiles": {
                role_key: {"status_code": "", "content_length": ""}
                for role_key in USER_PROFILES.keys()
            }
        }

    response_data_store[endpoint]["profiles"][profile] = {
        "status_code": status_code,
        "content_length": response_size
    }
    print(f"Updated in-memory store for {profile} ({method} {endpoint}) with status {status_code}, size {response_size} bytes.")


# NEW: Helper function to check if a flow is a "delete-like" operation
def is_delete_like_operation(flow: http.HTTPFlow) -> bool:
    """
    Checks if the given flow represents a delete-like operation,
    either by HTTP method or by keywords in the URL path.
    """
    if flow.request.method == "DELETE":
        return True
    
    path_lower = flow.request.path.lower()
    for keyword in DELETE_KEYWORDS:
        if keyword in path_lower:
            return True
    return False


# --- LLM Specific Helper Functions ---

def call_llm_api(model_name: str, messages: list, api_key: str, base_url: str = "https://openrouter.ai/api/v1/chat/completions"):
    """
    Makes a call to the LLM API (e.g., OpenRouter, compatible with OpenAI/Anthropic APIs).
    """
    if not api_key or api_key == "YOUR_OPENROUTER_API_KEY":
        print("LLM API key is not set. Skipping LLM call.")
        return None

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    data = {
        "model": model_name,
        "messages": messages,
        "temperature": 0.0
    }

    try:
        response = requests.post(base_url, headers=headers, json=data)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        if response is not None:
            print(f"LLM API Error Status Code: {response.status_code}")
            print(f"LLM API Error Response Body: {response.text}")
        print(f"Error calling LLM API: {e}")
        return None

def analyze_full_data_point_with_llm(data_point: dict, llm_api_key: str, llm_model_name: str) -> dict:
    """
    Analyzes a single data point (containing all profiles) using the LLM.
    Returns the full LLM analysis result.
    """
    method = data_point['method']
    endpoint = data_point['endpoint']
    profiles_data = data_point['profiles']

    profile_comparison_str = ""
    for role_key, profile_info in profiles_data.items():
        label = profile_info.get("label", role_key)
        status = profile_info.get('status', 'N/A')
        length = profile_info.get('length', 'N/A')
        profile_comparison_str += f"{label}: Status={status}, Length={length}\n"

    user_prompt = f"""
    {ROLE_DEFINITIONS}

    ---

    Analyze the following request data, observed across multiple user profiles. Identify any inconsistencies or potential authorization issues given the defined roles and the observed responses.

    Your output MUST be a JSON object with the following structure:
    ```json
    {{
      "assessment": "string (e.g., Potential Bypass, Looks OK, Investigate, Informational)",
      "severity": "string (e.g., Critical, High, Medium, Low, Info)",
      "reasoning": "string (detailed explanation of why this assessment was made)",
      "recommendation": "string (actionable advice, e.g., 'Manually test this endpoint', 'Review authorization logic')"
    }}
    ```
    Keep your 'reasoning' and 'recommendation' fields concise.
    IMPORTANT: Do NOT wrap the JSON output in markdown code blocks. Just output the raw JSON object.

    Here is the data point to analyze:

    METHOD: {method}
    ENDPOINT: {endpoint}
    {profile_comparison_str.strip()}
    """

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt}
    ]

    llm_response = call_llm_api(llm_model_name, messages, llm_api_key)

    if llm_response and llm_response.get('choices'):
        raw_content = llm_response['choices'][0]['message']['content']
        try:
            match = re.search(r'```json\s*(.*?)\s*```', raw_content, re.DOTALL)
            if match:
                json_string = match.group(1)
            else:
                json_string = raw_content

            analysis = json.loads(json_string)
            return analysis

        except json.JSONDecodeError as e:
            print(f"Error parsing JSON from LLM for {method} {endpoint}: {e}")
            print(f"LLM Raw Content (after markdown attempt): {raw_content}")
            return {
                "assessment": "LLM Parsing Error",
                "severity": "Low",
                "reasoning": f"LLM returned invalid JSON or unparseable format. Raw content: {raw_content}",
                "recommendation": "Review LLM output for formatting issues."
            }
        except Exception as e:
            print(f"Unexpected error processing LLM response for {method} {endpoint}: {e}")
            return {
                "assessment": "Processing Error",
                "severity": "Low",
                "reasoning": f"Unexpected error: {e}",
                "recommendation": "Check script logic."
            }
    else:
        print(f"No valid LLM response for {method} {endpoint}.")
        return {
            "assessment": "No LLM Response",
            "severity": "Low",
            "reasoning": "LLM API call failed or returned no choices.",
            "recommendation": "Check API key, model name, and network connectivity."
        }

def save_llm_analysis_to_file(original_request_data: dict, llm_analysis_result: dict):
    """
    Saves the complete LLM analysis result along with original request data to a JSONL file.
    """
    log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "original_request_context": original_request_data,
        "llm_analysis": llm_analysis_result
    }
    try:
        with open(LLM_LOG_FILE, "a", encoding="utf-8") as f:
            json.dump(log_entry, f, ensure_ascii=False)
            f.write("\n")
        print(f"Full LLM analysis for {original_request_data['method']} {original_request_data['endpoint']} saved to {LLM_LOG_FILE}")
    except Exception as e:
        print(f"Error saving LLM analysis to file {LLM_LOG_FILE}: {e}")

# --- End LLM Specific Helper Functions ---


def request(flow: http.HTTPFlow):
    """
    Intercepts and replays requests with different user profiles.
    For DELETE-like operations, it controls the replay order.
    """
    if flow.is_replay == "request":
        return

    if TARGET_DOMAIN in flow.request.host and flow.request.path.startswith(TARGET_PATH):
        print(f"\n--- Intercepted original request: {flow.request.url} ---")

        original_profile_key = HIGHEST_PRIV_PROFILE_KEY
        flow.request.headers["X-Profile"] = original_profile_key

        if is_delete_like_operation(flow): # <--- NEW: Use the helper function
            # --- Special handling for DELETE-like requests to control order ---
            print(f"INFO: Intercepted DELETE-like request for {flow.request.url}. Controlling replay order.")

            # 1. Kill the original browser flow to prevent premature deletion.
            # Store it so we can reply to the browser later.
            original_delete_flows_waiting_for_reply[flow.id] = flow
            flow.kill()

            # 2. Prepare flows for all profiles.
            flows_to_send_in_order = []
            base_replay_flow = flow.copy() # Copy of the original (now killed) DELETE-like request

            # Add all profiles EXCEPT the highest privilege one first
            for profile_name in PROFILE_ROTATION:
                if profile_name == HIGHEST_PRIV_PROFILE_KEY:
                    continue # Will be added last

                if profile_name in USER_PROFILES:
                    user_data = USER_PROFILES[profile_name]
                    replayed_flow = base_replay_flow.copy()

                    cookie_string = "; ".join([f"{key}={value}" for key, value in user_data["cookies"].items()])
                    replayed_flow.request.headers["Cookie"] = cookie_string

                    for key, value in user_data["headers"].items():
                        replayed_flow.request.headers[key] = value

                    replayed_flow.request.headers["X-Profile"] = profile_name
                    flows_to_send_in_order.append(replayed_flow)
            
            # Add the highest privilege profile's DELETE-like request last
            user_data_hp = USER_PROFILES[HIGHEST_PRIV_PROFILE_KEY]
            replayed_flow_hp = base_replay_flow.copy()
            cookie_string_hp = "; ".join([f"{key}={value}" for key, value in user_data_hp["cookies"].items()])
            replayed_flow_hp.request.headers["Cookie"] = cookie_string_hp
            for key, value in user_data_hp["headers"].items():
                replayed_flow_hp.request.headers[key] = value
            replayed_flow_hp.request.headers["X-Profile"] = HIGHEST_PRIV_PROFILE_KEY
            flows_to_send_in_order.append(replayed_flow_hp)

            # 3. Send all replayed flows. They will be processed by mitmproxy and responses collected.
            for f_to_replay in flows_to_send_in_order:
                mitmproxy.ctx.master.commands.call("replay.client", [f_to_replay])

        else:
            # --- Standard handling for non-DELETE-like requests ---
            base_replay_flow = flow.copy()

            for profile_name in PROFILE_ROTATION:
                if profile_name == original_profile_key:
                    continue

                if profile_name in USER_PROFILES:
                    user_data = USER_PROFILES[profile_name]
                    replayed_flow = base_replay_flow.copy()

                    cookie_string = "; ".join([f"{key}={value}" for key, value in user_data["cookies"].items()])
                    replayed_flow.request.headers["Cookie"] = cookie_string

                    for key, value in user_data["headers"].items():
                        replayed_flow.request.headers[key] = value

                    replayed_flow.request.headers["X-Profile"] = profile_name
                    
                    mitmproxy.ctx.master.commands.call("replay.client", [replayed_flow])

        print(f"--- Finished processing request for {flow.request.url} ---")

def response(flow: http.HTTPFlow):
    """
    Intercepts and logs responses for matching requests.
    Also handles replying to original DELETE-like browser flows.
    """
    # Filter for target domain and path (applies to both original and replayed flows)
    if TARGET_DOMAIN in flow.request.host and flow.request.path.startswith(TARGET_PATH):
        # Prevent redirects from interfering with analysis
        if flow.response.status_code in [301, 302]:
            print(f"Blocking redirect from {flow.request.url} to {flow.response.headers.get('Location')} for profile {flow.request.headers.get('X-Profile', 'UNKNOWN')}")
            flow.response.status_code = 200

        profile_key = flow.request.headers.get("X-Profile")

        # If X-Profile header is missing or unknown, try to guess (only for original flows) or skip
        if not profile_key or profile_key not in USER_PROFILES:
            if flow.is_replay is None: # This is the original browser request
                profile_key = HIGHEST_PRIV_PROFILE_KEY # Assume original is highest priv
            else:
                print(f"Warning: Response received for unknown profile or missing X-Profile header for '{flow.request.url}'. Skipping data store update. Header: {flow.request.headers.get('X-Profile')}")
                return # Skip if we can't identify the profile reliably

        endpoint = flow.request.url
        method = flow.request.method
        status_code = flow.response.status_code
        response_text = flow.response.text
        response_size = len(response_text)

        update_response_data_store(method, endpoint, profile_key, status_code, response_size)

        # NEW: If this is the HIGHEST_PRIV_PROFILE_KEY's replayed DELETE-like response,
        # use it to reply to the original browser flow.
        if is_delete_like_operation(flow) and profile_key == HIGHEST_PRIV_PROFILE_KEY:
            original_flow = original_delete_flows_waiting_for_reply.pop(flow.original_id, None)
            if original_flow:
                original_flow.response = flow.response.copy() # Set the response on the original flow
                original_flow.resume() # Send the response back to the browser


        compare_responses_on_complete(endpoint)


def compare_responses_on_complete(endpoint: str):
    """
    Compares response sizes and statuses for an endpoint once all expected profiles have responded.
    Handles writing the complete row to the CSV log file.
    If ENABLE_LLM_ANALYSIS is True, it performs LLM analysis on all collected profiles.
    """
    if endpoint not in response_data_store:
        return

    endpoint_data = response_data_store[endpoint]
    current_profiles_data = endpoint_data["profiles"]
    
    all_profiles_responded = all(role_key in current_profiles_data and
                                 current_profiles_data[role_key].get("content_length") != "" and
                                 current_profiles_data[role_key].get("status_code") != ""
                                 for role_key in USER_PROFILES.keys())

    if all_profiles_responded:
        # Always log to CSV if all data is present and not yet logged
        if endpoint not in logged_endpoints_to_file:
            try:
                with open(CSV_LOG_FILE, "a", encoding="utf-8") as log:
                    row_values = [endpoint_data["method"], endpoint]
                    for role_key in USER_PROFILES.keys():
                        profile_data = endpoint_data["profiles"].get(role_key, {})
                        row_values.append(str(profile_data.get("status_code", "")))
                        row_values.append(str(profile_data.get("content_length", "")))
                    log.write(",".join(row_values) + "\n")
                logged_endpoints_to_file.add(endpoint)
                print(f"Successfully logged complete data for {endpoint_data['method']} {endpoint} to CSV.")
            except Exception as e:
                print(f"Error appending to log file {CSV_LOG_FILE}: {e}")

        # --- Conditional LLM-Powered Analysis for ALL profiles ---
        if ENABLE_LLM_ANALYSIS:
            print(f"\n*** Starting LLM Analysis for {endpoint_data['method']} {endpoint} (All Profiles) ***")

            llm_data_point = {
                "method": endpoint_data["method"],
                "endpoint": endpoint,
                "profiles": {
                    role_key: {
                        "label": USER_PROFILES[role_key]["label"],
                        "status": int(current_profiles_data[role_key].get("status_code", -1)),
                        "length": int(current_profiles_data[role_key].get("content_length", 0))
                    }
                    for role_key in USER_PROFILES.keys()
                }
            }
            # No high_priv_deleted_resource flag anymore, as we control the order.

            llm_analysis_result = analyze_full_data_point_with_llm(
                llm_data_point, MY_LLM_API_KEY, MY_LLM_MODEL
            )

            save_llm_analysis_to_file(llm_data_point, llm_analysis_result)

            # --- Console Output (Shortened) ---
            MAX_CONSOLE_LEN = 120

            def shorten_text(text, max_len):
                if text is None:
                    return "N/A"
                text = str(text).strip()
                if len(text) > max_len:
                    return text[:max_len-3] + "..."
                return text

            assessment_short = llm_analysis_result.get('assessment', 'N/A')
            severity_short = llm_analysis_result.get('severity', 'N/A')
            reasoning_short = shorten_text(llm_analysis_result.get('reasoning'), MAX_CONSOLE_LEN)
            recommendation_short = shorten_text(llm_analysis_result.get('recommendation'), MAX_CONSOLE_LEN)

            print(f"  Assessment: {assessment_short} (Severity: {severity_short})")
            print(f"  Reasoning: {reasoning_short}")
            print(f"  Recommendation: {recommendation_short}")
            
            print(f"\n--- Finished LLM Analysis for {endpoint_data['method']} {endpoint} (All Profiles) ---\n")

        else:
            print(f"\n--- LLM Analysis Skipped for {endpoint_data['method']} {endpoint} (ENABLE_LLM_ANALYSIS is False) ---\n")


def forward_request_to_burp(request):
    """
    Forwards a request to HTTP PROXY Suite (Caido in this case).
    """
    try:
        if not hasattr(request, "url"):
            print("ERROR: Request object does not have a URL attribute!")
            return

        proxy = {
            "http://": CAIDO_PROXY,
            "https://": CAIDO_PROXY
        }

        headers_dict = {k.decode('utf-8'): v.decode('utf-8') for k, v in request.headers.items()}
        content = request.content if request.content else None

        with httpx.Client(verify=False, proxies=proxy) as client:
            response = client.request(
                method=request.method,
                url=str(request.url),
                headers=headers_dict,
                content=content,
                follow_redirects=False
            )
        print(f"Forwarded to CAIDO: {request.url} -> Response {response.status_code}")
    except Exception as e:
        print(f"Error forwarding request to CAIDO: {e}")
