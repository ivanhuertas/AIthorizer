from flask import Flask, render_template, send_from_directory
import json
import os
import datetime # Import datetime for timestamp

app = Flask(__name__)

# --- Configuration ---
# Ensure these paths match your mitmproxy script's log paths
LOGS_DIR = "logs"
LLM_LOG_FILE = os.path.join(LOGS_DIR, "llm_analysis_log.jsonl")
CSV_LOG_FILE = os.path.join(LOGS_DIR, "comparison_log.csv")

# Create logs directory if it doesn't exist (important if running flask first)
os.makedirs(LOGS_DIR, exist_ok=True)

# --- Helper Functions ---

def load_llm_results():
    """Loads and parses all LLM analysis results from the JSONL log file."""
    results = []
    if not os.path.exists(LLM_LOG_FILE):
        return results

    with open(LLM_LOG_FILE, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            try:
                entry = json.loads(line)
                results.append(entry)
            except json.JSONDecodeError as e:
                print(f"Error parsing JSON line {line_num} from LLM log: {e}\nRaw Line: {line.strip()}")
                # Optionally, add a placeholder entry to indicate a parsing error
                results.append({
                    "timestamp": datetime.datetime.now().isoformat(),
                    "original_request_context": {"method": "N/A", "endpoint": f"Parsing Error Line {line_num}"},
                    "llm_analysis": {
                        "assessment": "LLM Parsing Error",
                        "severity": "Low",
                        "reasoning": f"Failed to parse log line: {e}. Raw content: {line.strip()}",
                        "recommendation": "Check llm_analysis_log.jsonl for malformed JSON."
                    }
                })
    return results

def determine_flags(assessment: str, severity: str) -> tuple[bool, bool]:
    """
    Determines if an LLM analysis result should be flagged as a bug or
    requiring manual inspection.
    """
    is_bug = False
    requires_manual_inspection = False

    # Standardize inputs to lower case for consistent matching
    assessment_lower = assessment.lower()
    severity_lower = severity.lower()

    # Define what constitutes a "bug"
    if severity_lower in ["critical", "high"]:
        is_bug = True
    elif severity_lower == "medium" and "bypass" in assessment_lower:
        is_bug = True
    elif "bypass" in assessment_lower and severity_lower not in ["critical", "high", "medium"]:
        # If the assessment explicitly states "Bypass" but severity is not set high, still flag as bug
        is_bug = True

    # Define what requires "manual inspection"
    if "investigate" in assessment_lower or severity_lower == "medium":
        requires_manual_inspection = True
    
    # Ensure a bug isn't also flagged for manual inspection (bug takes precedence for display)
    if is_bug:
        requires_manual_inspection = False

    return is_bug, requires_manual_inspection

# --- Flask Routes ---

@app.route('/')
def index():
    """Displays all LLM analysis results in a table."""
    all_results = load_llm_results()
    
    processed_results = []
    for result in all_results:
        llm_analysis = result.get('llm_analysis', {})
        req_context = result.get('original_request_context', {})

        # Ensure method and endpoint are extracted, handling potential None
        method = req_context.get('method', 'N/A')
        endpoint = req_context.get('endpoint', 'N/A')

        is_bug, requires_manual_inspection = determine_flags(
            llm_analysis.get('assessment', ''),
            llm_analysis.get('severity', '')
        )

        processed_results.append({
            "timestamp": result.get('timestamp'),
            "method": method,
            "endpoint": endpoint,
            "assessment": llm_analysis.get('assessment'),
            "severity": llm_analysis.get('severity'),
            "reasoning": llm_analysis.get('reasoning'),
            "recommendation": llm_analysis.get('recommendation'),
            "is_bug": is_bug,
            "requires_manual_inspection": requires_manual_inspection,
            "raw_llm_output": json.dumps(llm_analysis, indent=2) # Store raw LLM output for detailed view
        })
    
    # Display newest results first
    processed_results.reverse()

    return render_template('index.html', results=processed_results)

@app.route('/logs/<path:filename>')
def download_log(filename):
    """Allows downloading log files directly from the web server."""
    # Ensure only files from the LOGS_DIR can be served
    return send_from_directory(LOGS_DIR, filename, as_attachment=True)


if __name__ == '__main__':
    print(f"Starting web server. Access at http://127.0.0.1:5000")
    print(f"LLM log file: {LLM_LOG_FILE}")
    print(f"CSV log file: {CSV_LOG_FILE}")
    
    # IMPORTANT: Advise user to delete old log files if they see 'None' in columns
    if os.path.exists(LLM_LOG_FILE) and os.path.getsize(LLM_LOG_FILE) > 0:
        # Check first line for structure to hint if it's an old format
        with open(LLM_LOG_FILE, 'r', encoding='utf-8') as f:
            first_line = f.readline()
            try:
                first_entry = json.loads(first_line)
                if 'original_request_context' not in first_entry or \
                   'method' not in first_entry.get('original_request_context', {}) or \
                   'endpoint' not in first_entry.get('original_request_context', {}):
                    print("\nWARNING: Your 'llm_analysis_log.jsonl' might contain old entries without 'method' and 'endpoint' in context.")
                    print("         If you see 'None' in the Method/Endpoint columns, consider deleting 'logs/llm_analysis_log.jsonl'")
                    print("         and 'logs/comparison_log.csv' to start with fresh logs after running the mitmproxy script.")
            except json.JSONDecodeError:
                print("\nWARNING: Your 'llm_analysis_log.jsonl' might be corrupted or in an old format.")
                print("         Consider deleting 'logs/llm_analysis_log.jsonl' and 'logs/comparison_log.csv' to start fresh.")

    app.run(debug=True, port=5000)
