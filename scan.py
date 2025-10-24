import os
import requests
import json
import time

# --- Configuration ---
# Get necessary info from environment variables
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')
REPO_NAME = os.environ.get('GITHUB_REPOSITORY') # e.g., "owner/repo"
PR_NUMBER = os.environ.get('PR_NUMBER')
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')

# Gemini API endpoint
GEMINI_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key={GEMINI_API_KEY}"

# GitHub API Headers
GH_HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json",
    "X-GitHub-Api-Version": "2022-11-28"
}

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

def get_pr_files():
    """
    Gets the list of changed files from the GitHub PR.
    """
    url = f"https://api.github.com/repos/{REPO_NAME}/pulls/{PR_NUMBER}/files"
    
    try:
        response = requests.get(url, headers=GH_HEADERS)
        response.raise_for_status() # Raise HTTPError for bad responses
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching PR files: {e}")
        return None

def get_file_content(file_info):
    """
    Gets the raw content of a single file.
    """
    url = file_info.get('raw_url')
    if not url:
        print(f"No raw_url for file: {file_info.get('filename')}")
        return None
    
    try:
        response = requests.get(url, headers=GH_HEADERS)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error fetching file content from {url}: {e}")
        return None

def post_comment_to_pr(comment_body):
    """
    Posts a final comment to the GitHub PR.
    """
    url = f"https://api.github.com/repos/{REPO_NAME}/issues/{PR_NUMBER}/comments"
    payload = {"body": comment_body}
    
    try:
        response = requests.post(url, headers=GH_HEADERS, json=payload)
        response.raise_for_status()
        print(f"Successfully posted comment to PR #{PR_NUMBER}.")
    except requests.exceptions.RequestException as e:
        print(f"Error posting comment to PR: {e}")
        print(f"Response body: {response.text}")

def main():
    """
    Main execution flow.
    """
    if not all([GITHUB_TOKEN, REPO_NAME, PR_NUMBER, GEMINI_API_KEY]):
        print("Error: Missing one or more environment variables.")
        print(f"REPO_NAME: {REPO_NAME}, PR_NUMBER: {PR_NUMBER}")
        print(f"GITHUB_TOKEN: {'SET' if GITHUB_TOKEN else 'NOT SET'}")
        print(f"GEMINI_API_KEY: {'SET' if GEMINI_API_KEY else 'NOT SET'}")
        return

    print(f"Starting security scan for PR #{PR_NUMBER} in {REPO_NAME}...")
    
    files = get_pr_files()
    if not files:
        print("No files found or error fetching files. Exiting.")
        return

    final_report = "### 🛡️ LLM Security Scan Results\n\n"
    vulnerabilities_found = False
    
    # We only want to scan new/modified files, not deleted ones
    for file_info in files:
        if file_info['status'] == 'removed':
            continue

        file_name = file_info['filename']
        # Simple filter for common file types to scan
        if not (file_name.endswith('.py') or file_name.endswith('.js') or 
                file_name.endswith('.go') or file_name.endswith('.java') or
                file_name.endswith('.php') or file_name.endswith('.ts') or
                file_name.endswith('.html') or file_name.endswith('.sh')):
            print(f"Skipping file (not a scannable type): {file_name}")
            continue

        print(f"Analyzing file: {file_name}...")
        content = get_file_content(file_info)
        
        if content:
            analysis_result = analyze_code_with_gemini(file_name, content)
            
            if "No vulnerabilities found." not in analysis_result:
                vulnerabilities_found = True
                final_report += analysis_result + "\n"
            else:
                print(f"No vulnerabilities found in {file_name}.")
        else:
            print(f"Could not fetch content for {file_name}. Skipping.")
    
    if not vulnerabilities_found:
        final_report += "✅ **All scanned files look good!** No vulnerabilities were detected by the LLM."
    
    final_report += "\n\n*Disclaimer: This is an AI-generated analysis. Please review all findings manually.*"
    
    post_comment_to_pr(final_report)
    print("Security scan complete.")

if __name__ == "__main__":
    main()
