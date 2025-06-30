# AI-Powered Code Vulnerability Scanner

This Python script is a versatile tool for identifying potential security vulnerabilities in PHP and JavaScript code. It offers two distinct scanning modes: an **online mode** that leverages the power of OpenAI's `gpt-4o-mini` model for in-depth analysis, and an **offline mode** that uses heuristic-based regular expression patterns for quick, local scans.

The script can process individual code files or entire ZIP archives, making it adaptable to various project structures. It generates a comprehensive vulnerability report in Markdown format, detailing any findings with their severity, a description, and suggested fixes.

## Features

- **Dual Scanning Modes**: Choose between a powerful online scan using OpenAI's AI or a fast, local offline scan.
- **Multi-Language Support**: Capable of scanning both PHP and JavaScript files.
- **Flexible Input**: Analyze single code files (`.php`, `.js`) or entire projects compressed in a `.zip` archive.
- **Detailed Reporting**: Generates a clean, well-structured Markdown report summarizing all identified vulnerabilities.
- **Cost Estimation**: When using the online mode, the script provides an estimated cost of the OpenAI API usage based on token consumption.
- **Configurable**: Allows setting a custom token limit for chunking code sent to the LLM.
- **Exclusion of Minified Files**: Automatically skips `.min.js` files to focus on source code and reduce noise.
- **Logging**: Creates a detailed log file for each scan, aiding in debugging and tracking the script's execution.

## Requirements

- Python 3.6+
- The `requests` library. You can install it using pip:
  ```bash
  pip install requests
  ```

For **online scanning mode**, you will also need:

- An **OpenAI API key**.

## Configuration

### OpenAI API Key

For **online scanning mode**, an OpenAI API key is essential. The script prioritizes fetching the API key from the `OPENAI_API_KEY` environment variable. This is the recommended and most secure method for handling your API key.

#### Setting the Environment Variable

**Linux/macOS:**
```bash
export OPENAI_API_KEY="your_openai_api_key_here"
```

**Windows Command Prompt:**
```dos
set OPENAI_API_KEY="your_openai_api_key_here"
```

You can also place your key directly in the script by modifying the `API_KEY` variable, but this is **not recommended** for security reasons, especially in shared or public environments.

```python
# API Key handling:
# This variable is intentionally left empty. When running in a Google Canvas environment,
# the API key for Google models is often handled automatically. For OpenAI models,
# you typically set an environment variable named OPENAI_API_KEY if running locally,
# or provide it through a secure mechanism in production environments.
API_KEY = "" # Consider setting OPENAI_API_KEY as an environment variable instead.
```

## Usage

The script is executed from the command line and accepts several arguments to customize the scan.

### Basic Syntax

```bash
python <script_name>.py <path> [options]
```

### Arguments

| Argument | Short Form | Description |
|---|---|---|
| `path` | | **(Required)** The path to the file or ZIP archive to be scanned. |
| `--project_name` | `-p` | A name for the project, used for the output directory name. (Default: `code_scan_project`) |
| `--token_limit` | | The maximum token limit per chunk for the LLM in online mode. (Default: `4000`) |
| `--js_mode` | `-j` | Enables JavaScript scanning mode. Scans `.js` files and excludes `.min.js`. |
| `--offline_mode` | `-o` | Enables offline scanning mode, which uses local regex-based checks instead of the OpenAI API. |
| `--all_mode` | `-a` | Scans both PHP and JavaScript files. This overrides the `--js_mode` flag. |

### Examples

**1. Scan a single PHP file (default mode):**
```bash
python your_script.py /path/to/your/file.php
```

**2. Scan a single JavaScript file in online mode:**
```bash
python your_script.py /path/to/your/script.js -j
```

**3. Scan a ZIP archive containing both PHP and JavaScript files:**
```bash
python your_script.py /path/to/project.zip -a
```

**4. Scan a ZIP archive in offline mode for a quick analysis:**
```bash
python your_script.py /path/to/project.zip -a -o
```

**5. Scan a project with a custom project name and token limit:**
```bash
python your_script.py /path/to/project.zip -p "MyWebApp" --token_limit 3500
```

## Output

For each scan, the script creates a new directory named `<project_name>-<timestamp>`. For example: `code_scan_project-20250628_103000`. This directory will contain:

- **`vulnerability_report.md`**: A detailed Markdown report of the findings.
- **`scan_log.txt`**: A log file containing the script's execution details.

### Sample Report Structure

```markdown
# Vulnerability Scan Report: my_project
**Date:** 2025-06-28 10:30:00
**Input Path:** `/path/to/project.zip`
**Scanning Mode:** ONLINE
**OpenAI Model Used:** `gpt-4o-mini`
**Chunk Token Limit:** 4000
**Languages Scanned:** PHP, JavaScript
**Files Scanned:** 15

## Detailed Vulnerabilities Found

### File: /src/user.php

#### Chunk 1/1

- **Vulnerability Name/Type**: Potential SQL Injection
- **Severity**: High
- **Description**: The code appears to be constructing a SQL query by directly concatenating user-supplied input.
- **Suggested Fixes**: Use prepared statements with parameterized queries to prevent SQL injection attacks.

## API Usage Summary
- Total Input Tokens: 12345
- Total Output Tokens: 6789
- Estimated Cost: $0.008451 (using gpt-4o-mini pricing)
  *Note: Prices are estimates and subject to change by OpenAI.*
```

## How It Works

1.  **Argument Parsing**: The script starts by parsing the command-line arguments to determine the input path, scanning mode, and other settings.
2.  **Output Directory Creation**: It creates a unique, timestamped directory to store the results of the scan.
3.  **File Processing**:
    * If the input path is a single file, it reads the content directly.
    * If the input path is a ZIP archive, it extracts and reads the content of each relevant file (`.php` and/or `.js`, excluding `.min.js`).
4.  **Scanning**:
    * **Online Mode**:
        * The code is split into manageable chunks, each within the specified token limit.
        * Each chunk is sent to the OpenAI API with a detailed prompt asking for a vulnerability analysis.
        * The API's response is then appended to the report.
    * **Offline Mode**:
        * The content of each file is scanned against a set of predefined regular expression patterns that match common vulnerability signatures for PHP and JavaScript.
5.  **Report Generation**: The script aggregates the results from all scanned files into a single Markdown report and calculates the total API token usage and estimated cost for online scans.

## Disclaimer

This tool is intended to assist in identifying potential security vulnerabilities and is not a substitute for a thorough manual code review or professional security audit. The offline scanner is heuristic-based and may produce false positives or miss more complex vulnerabilities. The online scanner's effectiveness depends on the AI model's capabilities and may not always be perfectly accurate. Always validate the findings and apply security best practices.
