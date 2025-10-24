import os
import time
import json
import asyncio
from typing import TypedDict, List, Dict, Any
from collections import Counter

# We now import from langchain_core
from langchain_core.runnables import RunnableLambda

import google.generativeai as genai

# --- Configuration ---

# !!! IMPORTANT: You must set your Google AI Studio API key here !!!
# You can also set this as an environment variable `GEMINI_API_KEY`
API_KEY = "AIzaSyAJ3Qkuolmm357RhyRhv5FgEM6BGT5KHds"

# The model to use for analysis
GEMINI_MODEL = "gemini-2.5-flash-preview-09-2025"

# --- NEW SYSTEM PROMPT ---
# This prompt is updated to ask for the specific format you requested.
# It focuses on common, well-known security anti-patterns (SAST).
SYSTEM_PROMPT = """
You are an expert cybersecurity analyst performing a static code analysis.
Your goal is to identify potential security risks and bad practices.

Analyze the following code snippet and identify a list of potential issues.
Focus on common, well-known issues like:
- SQL Injection
- Cross-Site Scripting (XSS)
- Hardcoded secrets or API keys
- Insecure deserialization
- Use of dangerous functions (like 'eval' or 'exec')

For each issue found, provide:
1.  "vulnerability": A brief name for the issue (e.g., "SQL Injection").
2.  "level": A severity rating (Critical, High, Medium, or Low).
3.  "line": The line number where the issue occurs.
4.  "snippet": The exact line of code that is problematic.

Do NOT generate exploits. Only identify and classify the potential risks.
Format your response as a single JSON object with one key: "findings".
"findings" should be a list of objects, where each object contains the four fields above.
If no issues are found, return an empty list: {"findings": []}
"""

# Configure the Gemini client
if API_KEY:
    genai.configure(api_key=API_KEY)
elif os.environ.get("GEMINI_API_KEY"):
    # If script key is empty, try to get from environment
    genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))
else:
    print("Error: API key not found. Set the API_KEY variable or GEMINI_API_KEY environment variable.")
    exit()

model = genai.GenerativeModel(
    GEMINI_MODEL,
    system_instruction=SYSTEM_PROMPT,
    generation_config=genai.GenerationConfig(
        response_mime_type="application/json",
        temperature=0.2, # Lower temperature for more deterministic, factual output
        max_output_tokens=8048
    )
)

# --- "Sub-Agent" (The function our parallel workers will run) ---

async def analyze_code_chunk(file_info: Dict[str, str]) -> Dict[str, Any]:
    """
    This is the "sub-agent." It analyzes a single file's content using Gemini.
    """
    file_path = file_info['path']
    content = file_info['content']
    print(f"[Sub-Agent] Analyzing: {file_path}")

    # Add exponential backoff for API calls
    for attempt in range(3):
        try:
            user_query = f"Here is the code from `{file_path}`:\n\n```\n{content}\n```"
            response = await model.generate_content_async(user_query)
            
            # --- ROBUST CHECK ---
            if not response.candidates:
                raise Exception("No candidates returned from API.")

            candidate = response.candidates[0]
            
            # --- FIXED CHECK ---
            # We check the string .name of the enum, which is more robust
            if candidate.finish_reason.name != "STOP":
                raise Exception(f"Response generation stopped early. Reason: {candidate.finish_reason.name}")
            
            # The AI should return a JSON object, e.g., {"findings": [...]}
            analysis_json = json.loads(response.text)
            return {"path": file_path, "analysis": analysis_json}

        except json.JSONDecodeError as e:
            print(f"[Sub-Agent] JSONDecodeError for {file_path}: {e}")
            return {"path": file_path, "analysis": {"error": f"Failed to decode API JSON response: {e}", "findings": []}}
        
        except Exception as e:
            print(f"[Sub-Agent] Error analyzing {file_path} (Attempt {attempt + 1}): {e}")
            if attempt < 2:
                await asyncio.sleep(2 ** (attempt + 1)) # 2s, 4s
            else:
                return {"path": file_path, "analysis": {"error": f"Failed after 3 attempts: {e}", "findings": []}}
                
    return {"path": file_path, "analysis": {"error": "Unknown error in sub-agent after all retries.", "findings": []}}


# --- Helper Functions (Steps) ---

def find_files(scan_directory: str) -> List[str]:
    """
    Step 1: Find all relevant files in the directory.
    """
    print("[Main Agent] Step 1: Discovering files...")
    file_paths = []
    
    # --- UPDATED EXCLUSION LIST ---
    exclude_files = {"analysis_report.md", "scan.py", "langchain_analyzer.py"}
    exclude_dirs = {".git", ".venv", "node_modules", "__pycache__"}

    for root, dirs, files in os.walk(scan_directory):
        # Exclude specified directories
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        for file in files:
            # Explicitly skip our own report file and this script
            if file in exclude_files:
                continue
                
            if file.endswith(('.py', '.js', '.java', '.go', '.php', '.html', '.sh', '.md', '.txt')):
                file_paths.append(os.path.join(root, file))
    
    print(f"[Main Agent] Found {len(file_paths)} files.")
    return file_paths

def read_files(file_paths: List[str]) -> List[Dict[str, str]]:
    """
    Step 2: Read the content of all found files.
    """
    print(f"[Main Agent] Step 2: Reading {len(file_paths)} files...")
    files_with_content = []
    for file_path in file_paths:
        try:
            if os.path.getsize(file_path) > 50_000:  # 50KB limit
                print(f"[Skipping] File too large: {file_path}")
                continue
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                files_with_content.append({"path": file_path, "content": content})
        except Exception as e:
            print(f"[Skipping] Could not read {file_path}: {e}")
            
    print(f"[Main Agent] Read {len(files_with_content)} files successfully.")
    return files_with_content

# --- NEW REPORT COMPILER ---

def compile_report(analysis_results: List[Dict[str, Any]]) -> str:
    """
    Step 4: This is the "reduce" step.
    Compile all results into the new vulnerability report format.
    """
    print("[Main Agent] Step 4: Compiling final report...")
    
    level_counts = Counter()
    report_body = ""
    
    for result in analysis_results:
        file_path = result['path']
        analysis = result['analysis']

        # Check for errors first
        if "error" in analysis:
            report_body += f"## File: `{file_path}`\n\n"
            report_body += f"**Analysis Error:** {analysis['error']}\n\n"
            report_body += ("-" * 40) + "\n\n"
            continue

        # Get the list of findings
        findings = analysis.get('findings', [])
        
        if not findings:
            continue

        report_body += f"## File: `{file_path}`\n\n"
        
        for finding in findings:
            level = finding.get('level', 'Unknown').capitalize()
            level_counts[level] += 1
            
            report_body += f"Vulnerability: {finding.get('vulnerability', 'N/A')}\n"
            report_body += f"Level: {level}\n"
            report_body += f"Line {finding.get('line', '?')}: `{finding.get('snippet', 'N/A')}`\n\n"
        
        report_body += ("-" * 40) + "\n\n"

    # --- Build the final report with summary at the top ---
    
    report_header = "# Vulnerability Summary\n\n"
    report_header += f"Level Critical: {level_counts['Critical']}\n"
    report_header += f"Level High: {level_counts['High']}\n"
    report_header += f"Level Medium: {level_counts['Medium']}\n"
    report_header += f"Level Low: {level_counts['Low']}\n"
    report_header += ("=" * 40) + "\n\n"
    
    return report_header + report_body

# --- Main Orchestrator ---

async def main():
    """
    Main function to build the chain and run the analysis.
    """
    
    # --- Define the LCEL Chain ---
    
    # 1. The "map" step: A RunnableLambda that points to our async "sub-agent" function.
    #    LangChain's .map() will run this concurrently for every item in the input list.
    analysis_chain = RunnableLambda(analyze_code_chunk)
    
    # 2. The "reduce" step: A RunnableLambda that points to our report compiler.
    report_chain = RunnableLambda(compile_report)
    
    # 3. Combine them:
    #    - The input list of files will go to analysis_chain.map()
    #    - The output list of results will be piped to report_chain
    full_chain = analysis_chain.map() | report_chain

    # --- Run the chain ---
    print("[Main Agent] Workflow starting...")
    start_time = time.time()
    
    # Prepare the input for the chain
    # The script now correctly finds its own name ('langchain_analyzer.py')
    # and adds it to the exclude list.
    script_name = os.path.basename(__file__)
    file_paths = find_files(scan_directory='.')
    
    # A small safeguard to ensure the running script is never analyzed
    file_paths = [p for p in file_paths if os.path.basename(p) not in {script_name, "scan.py"}]

    files_to_analyze = read_files(file_paths)
    
    if not files_to_analyze:
        print("[Main Agent] No files found to analyze. Exiting.")
        return

    print(f"[Main Agent] Step 3: Mapping {len(files_to_analyze)} files to sub-agents...")
    
    # Asynchronously invoke the chain
    report_content = await full_chain.ainvoke(files_to_analyze)
        
    end_time = time.time()
    print(f"\n[Main Agent] Workflow complete in {end_time - start_time:.2f} seconds.")

    # Save the final report
    report_filename = "analysis_report.md"
    
    with open(report_filename, "w", encoding="utf-8") as f:
        f.write(report_content)
        
    print(f"[Main Agent] Report saved to {report_filename}")

if __name__ == "__main__":
    asyncio.run(main())

