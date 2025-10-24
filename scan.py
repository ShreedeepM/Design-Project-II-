import os
import requests
import json
import time
import base64
import concurrent.futures

# --- Configuration ---
# Get necessary info from environment variables
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')
REPO_NAME = os.environ.get('GITHUB_REPOSITORY') # e.g., "owner/repo"
COMMIT_SHA = os.environ.get('COMMIT_SHA')
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')

# Gemini API endpoint
GEMINI_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key={GEMINI_API_KEY}"

# GitHub API Headers
GH_HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json",
    "X-GitHub-Api-Version": "2022-11-28"
}

# Max workers for parallel processing
MAX_WORKERS = 10

# --- 1. System Prompt for LLM ---
# This is the core instruction for the LLM.
# It tells the model to act as a security expert.
SECURITY_SYSTEM_PROMPT = """
You are an expert security auditor and a helpful AI assistant.
Your task is to analyze the provided code for potential security vulnerabilities.
Focus on common issues such as:
- SQL Injection
- Cross-Site Scripting (XSS)
- Remote Code Execution (RCE)
- Insecure Deserialization
- Hardcoded secrets or API keys
- Broken Access Control
- Improper Error Handling that leaks sensitive information

For each file, respond in the following format:
- If NO vulnerabilities are found, respond with ONLY the string: "No vulnerabilities found."
- If vulnerabilities ARE found, provide a list in this format:

**File: `{file_name}`**

* **Vulnerability:** {Type of vulnerability}
* **Line:** {Line number}
* **Risk:** {Brief, 1-sentence explanation of the risk}
* **Suggestion:** {Brief, 1-sentence suggestion for fixing}
---
* **Vulnerability:** {Another vulnerability}
* **Line:** ...
* **Risk:** ...
* **Suggestion:** ...
---
"""

def call_gemini_with_backoff(payload, retries=5, delay=5):
    """
    Calls the Gemini API with exponential backoff for rate limiting.
    """
    for i in range(retries):
        try:
            response = requests.post(GEMINI_API_URL, headers={"Content-Type": "application/json"}, json=payload)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429: # Rate limit exceeded
                print(f"Rate limit hit. Retrying in {delay}s...")
                time.sleep(delay)
                delay *= 2 # Exponential backoff
            else:
                print(f"Error calling Gemini API: {response.status_code}")
                print(response.text)
                return None # Failed after non-retryable error
        except requests.exceptions.RequestException as e:
            print(f"Request exception: {e}. Retrying in {delay}s...")
            time.sleep(delay)
            delay *= 2
    
    print("Failed to call Gemini API after all retries.")
    return None

def analyze_code_with_gemini(file_name, code_content):
    """
    Sends code to the Gemini API for analysis.
    """
    if not GEMINI_API_KEY:
        print("Error: GEMINI_API_KEY is not set.")
        return "Error: GEMINI_API_KEY is not configured for this repository."

    payload = {
        "contents": [{
            "parts": [{
                "text": f"Analyze this code from the file `{file_name}`:\n\n```\n{code_content}\n```"
            }]
        }],
        "systemInstruction": {
            "parts": [{
                "text": SECURITY_SYSTEM_PROMPT
            }]
        },
    }

    try:
        result = call_gemini_with_backoff(payload)
        
        if result and result.get('candidates'):
            text = result['candidates'][0]['content']['parts'][0]['text']
            return text
        else:
            print(f"Unexpected API response: {result}")
            return f"Error analyzing {file_name}: Invalid API response."

    except Exception as e:
        print(f"Error during Gemini API call for {file_name}: {e}")
        return f"Error analyzing {file_name}: {e}"

def get_all_repo_files():
    """
    Gets a list of all file paths in the repo.
    """
    url = f"https://api.github.com/repos/{REPO_NAME}/git/trees/{COMMIT_SHA}?recursive=1"
    try:
        response = requests.get(url, headers=GH_HEADERS)
        response.raise_for_status()
        tree = response.json().get('tree', [])
        # Filter for files ('blob') only, ignore directories ('tree')
        file_paths = [item['path'] for item in tree if item['type'] == 'blob']
        return file_paths
    except requests.exceptions.RequestException as e:
        print(f"Error fetching repo tree: {e}")
        return []

def get_file_content(file_path):
    """
    Gets the raw content of a single file from its path.
    """
    url = f"https://api.github.com/repos/{REPO_NAME}/contents/{file_path}?ref={COMMIT_SHA}"
    
    try:
        response = requests.get(url, headers=GH_HEADERS)
        response.raise_for_status()
        data = response.json()
        
        if data.get('encoding') == 'base64' and data.get('content'):
            # Decode the base64 content
            content = base64.b64decode(data['content']).decode('utf-8')
            return content
        else:
            print(f"Could not decode file content for: {file_path}")
            return None
    except requests.exceptions.RequestException as e:
        # Handle file-not-found or other errors
        print(f"Error fetching file content from {url}: {e}")
        return None
    except Exception as e:
        print(f"Error decoding file {file_path}: {e}")
        return None

def post_comment_to_commit(comment_body):
    """
    Posts a final comment to the GitHub commit.
    """
    url = f"https://api.github.com/repos/{REPO_NAME}/commits/{COMMIT_SHA}/comments"
    payload = {"body": comment_body}
    
    try:
        response = requests.post(url, headers=GH_HEADERS, json=payload)
        response.raise_for_status()
        print(f"Successfully posted comment to commit {COMMIT_SHA}.")
    except requests.exceptions.RequestException as e:
        print(f"Error posting comment to commit: {e}")
        print(f"Response body: {response.text}")

def analyze_file_job(file_path):
    """
    A single job for the thread pool: fetch content and analyze.
    """
    # Simple filter for common file types to scan
    if not (file_path.endswith('.py') or file_path.endswith('.js') or 
            file_path.endswith('.go') or file_path.endswith('.java') or
            file_path.endswith('.php') or file_path.endswith('.ts') or
            file_path.endswith('.html') or file_path.endswith('.sh') or
            file_path.endswith('.yml') or file_path.endswith('.yaml') or
            file_path.endswith('.json') or file_path.endswith('.tf')):
        print(f"Skipping file (not a scannable type): {file_path}")
        return None
        
    print(f"Analyzing file: {file_path}...")
    content = get_file_content(file_path)
    
    if content:
        analysis_result = analyze_code_with_gemini(file_path, content)
        
        if "No vulnerabilities found." not in analysis_result:
            return analysis_result # Return the formatted vulnerability string
        else:
            print(f"No vulnerabilities found in {file_path}.")
            return None
    else:
        print(f"Could not fetch content for {file_path}. Skipping.")
        return None

def main():
    """
    Main execution flow.
    """
    if not all([GITHUB_TOKEN, REPO_NAME, COMMIT_SHA, GEMINI_API_KEY]):
        print("Error: Missing one or more environment variables.")
        print(f"REPO_NAME: {REPO_NAME}, COMMIT_SHA: {COMMIT_SHA}")
        print(f"GITHUB_TOKEN: {'SET' if GITHUB_TOKEN else 'NOT SET'}")
        print(f"GEMINI_API_KEY: {'SET' if GEMINI_API_KEY else 'NOT SET'}")
        return

    print(f"Starting parallel security scan for commit {COMMIT_SHA} in {REPO_NAME}...")
    
    file_paths = get_all_repo_files()
    if not file_paths:
        print("No files found or error fetching file tree. Exiting.")
        return

    final_report = f"### 🛡️ LLM Security Scan Results\n\n**Commit:** `{COMMIT_SHA}`\n\n"
    vulnerabilities_found = False
    analysis_results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Create a dictionary to map futures to file paths
        future_to_file = {executor.submit(analyze_file_job, path): path for path in file_paths}
        
        for future in concurrent.futures.as_completed(future_to_file):
            try:
                result = future.result()
                if result:
                    analysis_results.append(result)
                    vulnerabilities_found = True
            except Exception as exc:
                file_path = future_to_file[future]
                print(f'{file_path} generated an exception: {exc}')

    if not vulnerabilities_found:
        final_report += "✅ **All scanned files look good!** No vulnerabilities were detected by the LLM."
    else:
        # Join all the individual vulnerability reports
        final_report += "\n\n".join(analysis_results)
    
    final_report += "\n\n*Disclaimer: This is an AI-generated analysis. Please review all findings manually.*"
    
    post_comment_to_commit(final_report)
    print("Security scan complete.")

if __name__ == "__main__":
    main()

