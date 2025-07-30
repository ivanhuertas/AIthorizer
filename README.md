# Aithorizer - Authorization Testing Tool

Aithorizer is a tool that helps identify authorization vulnerabilities in web applications. It uses a proxy to intercept HTTP requests and replays them with different user profiles to check for authorization bypasses. The tool leverages a Large Language Model (LLM) to analyze the responses and identify potential issues.

## Features

- **Profile-based Testing**: Define different user roles and their corresponding cookies and headers to test for authorization issues.
- **Automated Replay**: Automatically replays requests for all defined profiles.
- **LLM-powered Analysis**: Uses an LLM to analyze response discrepancies and identify potential vulnerabilities.
- **Web Dashboard**: Provides a user-friendly web interface to view the analysis results.
- **CSV Logging**: Logs all comparisons to a CSV file for further analysis.

## How it Works

1.  **Proxy Setup**: The tool runs as a `mitmdump` script, which spawns a proxy. You need to configure your browser to use this proxy.
2.  **Request Interception**: The script intercepts requests to the target domain and path.
3.  **Request Replay**: For each intercepted request, the script replays it with the cookies and headers of each defined user profile.
4.  **Response Comparison**: The script compares the status codes and content lengths of the responses for each profile.
5.  **LLM Analysis**: The response data is sent to an LLM for analysis to identify potential authorization bypasses.
6.  **Logging**: The results of the comparison and the LLM analysis are logged to files.
7.  **Web Dashboard**: A Flask web server displays the LLM analysis results in a web interface.

## Installation

1.  Clone the repository.
2.  Install the required Python libraries:

    ```bash
    pip install -r requirements.txt
    ```

## Configuration

Before running the script, you need to configure the following in `aithorizer.py`:

1.  **`USER_PROFILES`**: Define the user profiles you want to test with. Each profile should have a unique name, a label, and the corresponding cookies and headers.
2.  **`TARGET_DOMAIN`**: Set the target domain you want to test.
3.  **`TARGET_PATH`**: Set the target path you want to test.
4.  **`UPSTREAM_PROXY`**: (Optional) If you want to chain the proxy with another tool like Burp Suite, set the upstream proxy URL.
5.  **`ENABLE_LLM_ANALYSIS`**: Set to `True` to enable LLM analysis.
6.  **`MY_LLM_API_KEY`**: Set your OpenRouter API key as an environment variable or directly in the script.
7.  **`MY_LLM_MODEL`**: Choose the LLM model you want to use.

## Usage

1.  **Run the Aithorizer script**:

    ```bash
    mitmdump -s aithorizer.py -p <PORT> --mode upstream:http://<IP_FOR_UPSTREAMPROXY>:<PORT_FOR_UPSTREAMPROXY> --ssl-insecure
    ```

    -   `<PORT>`: The port where the proxy will run.
    -   `<IP_FOR_UPSTREAMPROXY>:<PORT_FOR_UPSTREAMPROXY>`: (Optional) The address of the upstream proxy.

2.  **Configure your browser**:
    -   Set your browser's proxy to the address and port you specified when running `mitmdump`.

3.  **Browse the application**:
    -   As you browse the target application, the script will automatically test for authorization issues in the background.

4.  **View the results**:
    -   Run the web dashboard to view the LLM analysis results:

        ```bash
        python web_dashboard.py
        ```

    -   Access the dashboard in your browser at `http://127.0.0.1:5000`.

## Log Files

-   `logs/comparison_log.csv`: A CSV file containing the raw comparison data (status codes and content lengths).
-   `logs/llm_analysis_log.jsonl`: A JSONL file containing the detailed LLM analysis results.
-   `responses/`: A directory containing the full response bodies for each request and profile.
