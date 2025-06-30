import os
import zipfile
import requests
import json
import argparse
import datetime
import logging
import re # For regular expressions in offline mode

# --- Configuration ---
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
OPENAI_MODEL = "gpt-4o-mini"

# API Key handling:
# This variable is intentionally left empty. When running in a Google Canvas environment,
# the API key for Google models is often handled automatically. For OpenAI models,
# you typically set an environment variable named OPENAI_API_KEY if running locally,
# or provide it through a secure mechanism in production environments.
API_KEY = ""

DEFAULT_TOKEN_LIMIT = 4000 # Chunking limit for input code to the LLM
# Pricing for gpt-4o-mini (as of my last update - prices can change, verify current rates)
# Prices are per 1 million tokens in USD
INPUT_COST_PER_MILLION_TOKENS = 0.15
OUTPUT_COST_PER_MILLION_TOKENS = 0.60

# --- Global counters for tokens and cost ---
total_input_tokens = 0
total_output_tokens = 0

# --- Helper Functions ---

def estimate_tokens(text):
    """
    Estimates token count by character count (approximate: 1 token ~ 4 characters).
    Used for chunking logic. Actual token usage is reported by the API.
    """
    return len(text) // 4 + (1 if len(text) % 4 != 0 else 0)

def chunk_code(code, max_tokens):
    """
    Chunks the code into smaller pieces to adhere to the LLM's token limit for analysis.
    Chunks are created line by line, ensuring lines are not split mid-way.
    """
    chunks = []
    current_chunk = []
    current_tokens = 0

    lines = code.split('\n')

    for line in lines:
        line_with_newline = line + '\n'
        line_tokens = estimate_tokens(line_with_newline)

        # If adding the next line exceeds the token limit for chunking,
        # and there's content in the current chunk, save it.
        if current_tokens + line_tokens > max_tokens and current_chunk:
            chunks.append("".join(current_chunk))
            current_chunk = []
            current_tokens = 0

        current_chunk.append(line_with_newline)
        current_tokens += line_tokens

    # Add any remaining content as the last chunk
    if current_chunk:
        chunks.append("".join(current_chunk))
    return chunks

def scan_code_offline(file_name, code_content, language):
    """
    Performs a very basic, heuristic-based vulnerability scan locally using regex patterns.
    This is a placeholder for more sophisticated local SAST tools which would typically
    be executed as external processes (e.g., via subprocess module) with their outputs parsed.
    """
    report = []
    issues_found = 0

    report.append(f"### File: {file_name} (Offline Scan - Heuristic-based)\n")
    report.append(f"This scan uses basic pattern matching and is not comprehensive.\n\n")

    # Store vulnerabilities as dictionaries for consistent formatting
    vulnerabilities = []

    if language == "PHP":
        # SQL Injection (mysql_* functions, common vulnerable patterns)
        if re.search(r'mysql_query\(|mysqli_query\([^,]*?\s*\$_(GET|POST|REQUEST|COOKIE)\[|PDO::prepare\("SELECT.+?WHERE.+?\$.+?"\)', code_content, re.IGNORECASE | re.DOTALL):
            vulnerabilities.append({
                "name": "Potential SQL Injection",
                "severity": "High",
                "description": "Direct use of `mysql_query()`, `mysqli_query()`, or parameterized queries without proper binding can lead to SQL injection if user input is not sanitized. Dynamic SQL queries with unsanitized user input are highly vulnerable.",
                "fix": "Always use prepared statements (PDO or MySQLi with parameter binding) for all database interactions. Escape all user-supplied data that goes into SQL queries using functions like `mysqli_real_escape_string()` (though prepared statements are preferred)."
            })
        # Command Injection
        if re.search(r'exec\(|shell_exec\(|passthru\(|system\(|popen\(', code_content):
            vulnerabilities.append({
                "name": "Potential Command Injection",
                "severity": "Critical",
                "description": "Use of system command execution functions like `exec()`, `shell_exec()`, etc., without proper input sanitization can lead to remote code execution.",
                "fix": "Avoid executing external commands with user-controlled input. If absolutely necessary, use `escapeshellarg()` or `escapeshellcmd()` to properly escape arguments, and ideally, use a whitelist approach for commands and arguments."
            })
        # Remote/Local File Inclusion
        if re.search(r'include\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\[|require\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\[', code_content, re.IGNORECASE):
            vulnerabilities.append({
                "name": "Local/Remote File Inclusion (LFI/RFI)",
                "severity": "High",
                "description": "File inclusion functions (`include()`, `require()`) are used with unsanitized user input. This can allow attackers to execute arbitrary code or access sensitive files.",
                "fix": "Implement strict input validation for file paths. Use a whitelist of allowed files/directories, and never concatenate user input directly into file paths. Disable `allow_url_include` in php.ini."
            })
        # Unsafe Use of eval()
        if re.search(r'eval\(', code_content):
            vulnerabilities.append({
                "name": "Unsafe Use of `eval()`",
                "severity": "Critical",
                "description": "`eval()` executes arbitrary strings as PHP code, making it a severe remote code execution vulnerability if input is user-controlled.",
                "fix": "Avoid `eval()` whenever possible. Refactor code to use safer alternatives for dynamic logic, such as configuration files, templating engines, or defined functions."
            })
        # Cross-Site Scripting (XSS) - very basic detection
        if re.search(r'echo\s*\$_(GET|POST|REQUEST|COOKIE)\[.+?\);', code_content, re.IGNORECASE):
            vulnerabilities.append({
                "name": "Potential Reflected Cross-Site Scripting (XSS)",
                "severity": "Medium",
                "description": "Direct echoing of unsanitized user input to the browser can lead to XSS attacks.",
                "fix": "Always sanitize or escape all user-supplied output before displaying it in the browser. Use `htmlspecialchars()` or a robust templating engine that auto-escapes, or a dedicated XSS prevention library."
            })

    elif language == "JavaScript":
        # Cross-Site Scripting (XSS) via DOM manipulation
        if re.search(r'document\.write\(|innerHTML\s*=\s*.+?[^\.]', code_content) and not re.search(r'\.textContent|\.innerText', code_content):
            vulnerabilities.append({
                "name": "Potential Cross-Site Scripting (XSS) via DOM Manipulation",
                "severity": "Medium",
                "description": "Use of `document.write()` or `innerHTML` with unsanitized user input can lead to XSS attacks by injecting malicious scripts into the DOM.",
                "fix": "Prefer `textContent` or `innerText` when only displaying text. If dynamic HTML is required, strictly sanitize all user input using a secure sanitization library before setting `innerHTML`."
            })
        # Unsafe Use of eval()
        if re.search(r'eval\(', code_content):
            vulnerabilities.append({
                "name": "Unsafe Use of `eval()`",
                "severity": "High",
                "description": "`eval()` executes arbitrary JavaScript code from a string, which is a major security risk if the string comes from untrusted sources, leading to arbitrary code execution.",
                "fix": "Avoid `eval()`. Use `JSON.parse()` for parsing JSON strings, and reconsider any need for dynamic code execution where user input could influence the executed code."
            })
        # Insecure Data Storage in Web Storage
        if re.search(r'localStorage\.setItem\(|sessionStorage\.setItem\(', code_content):
            vulnerabilities.append({
                "name": "Sensitive Data Storage in Web Storage",
                "severity": "Low", # Can be High depending on data sensitivity
                "description": "Storing sensitive information (e.g., JWT tokens, user data) directly in `localStorage` or `sessionStorage` can expose it to XSS attacks or malicious browser extensions.",
                "fix": "Avoid storing sensitive data in web storage. Use secure, HttpOnly, and SameSite cookies for session management and sensitive data that needs to persist across page loads (with proper expiry)."
            })
        # Client-side SQL Injection (e.g., in WebSQL/IndexedDB, though less common now)
        if re.search(r'\.executeSql\(.+?\s*\$.+?\s*\)|db\.transaction\(.+\.executeSql\(.+?\s*\$.+?\s*\)', code_content, re.IGNORECASE | re.DOTALL):
            vulnerabilities.append({
                "name": "Potential Client-Side SQL Injection (WebSQL/IndexedDB)",
                "severity": "Medium",
                "description": "Direct concatenation of user input into SQL queries for client-side databases can lead to SQL injection vulnerabilities.",
                "fix": "Use parameterized queries or prepared statements when interacting with client-side databases to separate data from code."
            })
        # Insecure API Key/Credential exposure
        if re.search(r'(API_KEY|API_SECRET|CLIENT_SECRET|Bearer)\s*:\s*["\'](pk|sk)_[a-zA-Z0-9]{20,}', code_content) or \
           re.search(r'(password|passwd|secret|credential)\s*=\s*["\'][a-zA-Z0-9!@#$%\^&*()_+\-=\[\]{}|;:\'",.<>\/?`~]{8,}', code_content):
            vulnerabilities.append({
                "name": "Hardcoded Credentials/API Keys",
                "severity": "High",
                "description": "Sensitive credentials or API keys are hardcoded directly in the client-side JavaScript code, making them easily discoverable by attackers.",
                "fix": "Never hardcode sensitive information in client-side code. Use server-side proxies, environment variables, or secure configuration management to retrieve credentials. Only expose public API keys."
            })

    if not vulnerabilities:
        report.append("No common vulnerabilities detected by basic offline heuristics in this code.\n\n")
    else:
        issues_found = len(vulnerabilities)
        for vul in vulnerabilities:
            report.append(f"- **Vulnerability Name/Type**: {vul['name']}\n")
            report.append(f"  - **Severity**: {vul['severity']}\n")
            report.append(f"  - **Description**: {vul['description']}\n")
            report.append(f"  - **Suggested Fixes**: {vul['fix']}\n\n")

    return "".join(report)

def scan_code_with_openai(file_name, code_content, token_limit, language):
    """
    Scans a single file's content for vulnerabilities using the OpenAI API.
    Updates global token counters and returns a formatted report for the file.
    The 'language' parameter is used to dynamically adjust the prompt.
    """
    global total_input_tokens
    global total_output_tokens

    file_report = []
    code_chunks = chunk_code(code_content, token_limit)
    total_chunks = len(code_chunks)

    logging.info(f"Scanning file: {file_name} ({total_chunks} chunks) using OpenAI API")
    file_report.append(f"### File: {file_name}\n")

    for i, chunk in enumerate(code_chunks):
        # Dynamically adjust the prompt based on the detected language
        prompt_message = (
            f"Analyze the following {language} code chunk from file \"{file_name}\" "
            f"for potential security vulnerabilities and common weaknesses. "
            f"For each vulnerability found, clearly state:\n"
            f"- **Vulnerability Name/Type**\n"
            f"- **Severity (e.g., Critical, High, Medium, Low, Informational)**\n"
            f"- **Description** (brief explanation)\n"
            f"- **Suggested Fixes** (concise and actionable recommendations)\n\n"
            f"If no specific vulnerabilities are found in this chunk, state so explicitly. "
            f"This is chunk {i + 1} of {total_chunks} for file \"{file_name}\".\n\n"
            f"{language} Code:\n```{language.lower()}\n{chunk}\n```\n\n"
            f"Vulnerability Analysis for this chunk:"
        )

        try:
            payload = {
                "model": OPENAI_MODEL,
                "messages": [
                    {"role": "user", "content": prompt_message}
                ],
                "temperature": 0.7,
                "max_tokens": 2000
            }
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {API_KEY}'
            }

            # Fallback to environment variable if API_KEY is not explicitly set in script
            if not API_KEY:
                env_api_key = os.environ.get("OPENAI_API_KEY")
                if env_api_key:
                    headers['Authorization'] = f'Bearer {env_api_key}'
                else:
                    raise ValueError("OPENAI_API_KEY environment variable not set or API_KEY not provided in script. Cannot make API call.")

            response = requests.post(OPENAI_API_URL, headers=headers, json=payload)
            response.raise_for_status()

            result = response.json()

            if result.get('choices') and len(result['choices']) > 0 and \
               result['choices'][0].get('message') and \
               result['choices'][0]['message'].get('content'):
                text = result['choices'][0]['message']['content']
                file_report.append(f"#### Chunk {i + 1}/{total_chunks}\n")
                file_report.append(text + "\n\n")

                if 'usage' in result:
                    total_input_tokens += result['usage'].get('prompt_tokens', 0)
                    total_output_tokens += result['usage'].get('completion_tokens', 0)
            else:
                file_report.append(f"#### Chunk {i + 1}/{total_chunks}\n")
                file_report.append("No clear vulnerability analysis from AI for this chunk.\n\n")
                logging.warning(f"No clear AI response for chunk {i + 1} of {file_name}")

        except requests.exceptions.RequestException as e:
            error_msg = f"Failed to connect to API or API error for chunk {i + 1} of {file_name}: {e}"
            file_report.append(f"#### Chunk {i + 1}/{total_chunks} (Error)\n{error_msg}\n\n")
            logging.error(error_msg)
        except json.JSONDecodeError:
            error_msg = f"Failed to decode JSON response from API for chunk {i + 1} of {file_name}."
            file_report.append(f"#### Chunk {i + 1}/{total_chunks} (Error)\n{error_msg}\n\n")
            logging.error(error_msg)
        except ValueError as e:
            error_msg = f"Configuration Error for chunk {i + 1} of {file_name}: {e}"
            file_report.append(f"#### Chunk {i + 1}/{total_chunks} (Error)\n{error_msg}\n\n")
            logging.error(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error scanning chunk {i + 1} of {file_name}: {e}"
            file_report.append(f"#### Chunk {i + 1}/{total_chunks} (Error)\n{error_msg}\n\n")
            logging.error(error_msg)

    return "".join(file_report)

# --- Main Script Logic ---

def main():
    parser = argparse.ArgumentParser(description="Scan PHP or JavaScript code/ZIP archives for vulnerabilities using OpenAI API or offline mode.")
    parser.add_argument("path", help="Path to a PHP/JS file or a ZIP archive containing PHP/JS files.")
    parser.add_argument("-p", "--project_name", default="code_scan_project",
                        help="A name for the scanning project. Used for output directory.")
    parser.add_argument("--token_limit", type=int, default=DEFAULT_TOKEN_LIMIT,
                        help=f"Maximum token limit per chunk for the LLM (default: {DEFAULT_TOKEN_LIMIT}).")
    parser.add_argument("-j", "--js_mode", action="store_true",
                        help="Enable JavaScript scanning mode. Scans .js files and excludes .min.js files. (Default is PHP mode).")
    parser.add_argument("-o", "--offline_mode", action="store_true",
                        help="Enable offline scanning mode. Uses local, heuristic-based checks instead of OpenAI API.")
    parser.add_argument("-a", "--all_mode", action="store_true",
                        help="Enable all mode. Scans both PHP and JavaScript files (excluding .min.js files). Overrides -j.")
    args = parser.parse_args()

    input_path = args.path
    project_name = args.project_name
    token_limit = args.token_limit
    offline_mode = args.offline_mode
    all_mode = args.all_mode

    # Determine the scanning language and target extensions based on the flags
    scan_languages = []
    target_extensions = []
    exclude_extensions = []

    if all_mode:
        scan_languages.append("PHP")
        scan_languages.append("JavaScript")
        target_extensions.append(".php")
        target_extensions.append(".js")
        exclude_extensions.append(".min.js") # Only applies to JS
    elif args.js_mode:
        scan_languages.append("JavaScript")
        target_extensions.append(".js")
        exclude_extensions.append(".min.js")
    else: # Default to PHP mode
        scan_languages.append("PHP")
        target_extensions.append(".php")

    # Create output directory with timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir_name = f"{project_name}-{timestamp}"
    output_dir_path = os.path.join(os.getcwd(), output_dir_name)

    try:
        os.makedirs(output_dir_path, exist_ok=True)
    except OSError as e:
        print(f"Error: Could not create output directory '{output_dir_path}': {e}")
        return

    # Configure logging to file
    log_file_path = os.path.join(output_dir_path, "scan_log.txt")
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        handlers=[
                            logging.FileHandler(log_file_path),
                            logging.StreamHandler() # Also print to console
                        ])

    scan_mode_str = "OFFLINE (Basic Heuristics)" if offline_mode else f"ONLINE (Using OpenAI Model: {OPENAI_MODEL})"
    logging.info(f"Starting Vulnerability Scan for project: '{project_name}'")
    logging.info(f"Output directory: '{output_dir_path}'")
    logging.info(f"Scanning Mode: {scan_mode_str}")
    if not offline_mode:
        logging.info(f"Chunk Token Limit: {token_limit}")
    logging.info(f"Languages to scan: {', '.join(scan_languages)}")

    if not os.path.exists(input_path):
        logging.error(f"Error: Input path '{input_path}' not found.")
        return

    all_vulnerability_reports = []
    files_scanned = 0

    # Choose the scanning function based on mode
    scanner_function = scan_code_offline if offline_mode else scan_code_with_openai

    def process_file_content(file_path, content, file_lang):
        nonlocal files_scanned
        nonlocal all_vulnerability_reports
        files_scanned += 1
        if offline_mode:
            report_content = scanner_function(file_path, content, file_lang)
        else:
            report_content = scanner_function(file_path, content, token_limit, file_lang)
        all_vulnerability_reports.append(report_content)

    if os.path.isfile(input_path):
        file_extension = os.path.splitext(input_path.lower())[1]
        file_language = None

        if file_extension == ".php" and ("PHP" in scan_languages):
            file_language = "PHP"
        elif file_extension == ".js" and ("JavaScript" in scan_languages) and not input_path.lower().endswith(".min.js"):
            file_language = "JavaScript"

        if file_language:
            try:
                with open(input_path, 'r', encoding='utf-8') as f:
                    code_content = f.read()
                logging.info(f"Processing single {file_language} file: {input_path}")
                process_file_content(input_path, code_content, file_language)
            except Exception as e:
                logging.error(f"Error reading {file_language} file '{input_path}': {e}")
        else:
            logging.warning(f"Skipping single file '{input_path}'. It's not a target language or is excluded.")
    elif input_path.lower().endswith('.zip'):
        logging.info(f"Processing ZIP archive: {input_path}")
        try:
            with zipfile.ZipFile(input_path, 'r') as zf:
                processed_files_in_zip = 0
                for file_info in zf.infolist():
                    file_extension = os.path.splitext(file_info.filename.lower())[1]
                    file_language = None

                    # Determine language and check for exclusions
                    if file_extension == ".php" and ("PHP" in scan_languages):
                        file_language = "PHP"
                    elif file_extension == ".js" and ("JavaScript" in scan_languages) and not file_info.filename.lower().endswith(".min.js"):
                        file_language = "JavaScript"

                    if file_language and not file_info.is_dir():
                        processed_files_in_zip += 1
                        with zf.open(file_info.filename, 'r') as code_file:
                            try:
                                code_content = code_file.read().decode('utf-8')
                                process_file_content(file_info.filename, code_content, file_language)
                            except UnicodeDecodeError:
                                logging.warning(f"Could not decode '{file_info.filename}' from zip. Skipping.")
                            except Exception as e:
                                logging.error(f"Error processing file '{file_info.filename}' in zip: {e}")
                if processed_files_in_zip == 0:
                    logging.warning(f"No target language files found in the ZIP archive (looking for: {', '.join(target_extensions)}).")
        except zipfile.BadZipFile:
            logging.error(f"Error: '{input_path}' is not a valid ZIP file.")
        except Exception as e:
            logging.error(f"Error processing ZIP file '{input_path}': {e}")
    else:
        logging.error(f"Error: Provided path is not a file or unsupported for direct scan. Please provide a .php, .js file, or a .zip archive.")

    # --- Generate final report ---
    report_file_path = os.path.join(output_dir_path, "vulnerability_report.md")
    with open(report_file_path, 'w', encoding='utf-8') as f:
        f.write(f"# Vulnerability Scan Report: {project_name}\n")
        f.write(f"**Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Input Path:** `{input_path}`\n")
        if offline_mode:
            f.write(f"**Scanning Mode:** OFFLINE (Basic Heuristics)\n")
        else:
            f.write(f"**Scanning Mode:** ONLINE\n")
            f.write(f"**OpenAI Model Used:** `{OPENAI_MODEL}`\n")
            f.write(f"**Chunk Token Limit:** {token_limit}\n")

        f.write(f"**Languages Scanned:** {', '.join(scan_languages)}\n")
        f.write(f"**Files Scanned:** {files_scanned}\n\n")

        if all_vulnerability_reports:
            f.write("## Detailed Vulnerabilities Found\n\n")
            f.write("".join(all_vulnerability_reports))
        else:
            f.write("No specific vulnerabilities were identified in the scanned files.\n\n")

        # Calculate and display total tokens and estimated cost
        total_cost = 0
        if not offline_mode:
            total_cost = (total_input_tokens / 1_000_000 * INPUT_COST_PER_MILLION_TOKENS) + \
                         (total_output_tokens / 1_000_000 * OUTPUT_COST_PER_MILLION_TOKENS)

        f.write(f"\n## API Usage Summary\n")
        f.write(f"- Total Input Tokens: {total_input_tokens}\n")
        f.write(f"- Total Output Tokens: {total_output_tokens}\n")
        if offline_mode:
            f.write(f"- Estimated Cost: $0.00 (Offline Mode)\n")
        else:
            f.write(f"- Estimated Cost: ${total_cost:.6f} (using {OPENAI_MODEL} pricing)\n")
            f.write(f"  *Note: Prices are estimates and subject to change by OpenAI.*\n")
            f.write(f"  *API key typically needed for OpenAI models. Set OPENAI_API_KEY environment variable if running locally.*\n")

    logging.info(f"Scan complete. Report saved to: {report_file_path}")
    logging.info(f"Logs saved to: {log_file_path}")

if __name__ == "__main__":
    main()
