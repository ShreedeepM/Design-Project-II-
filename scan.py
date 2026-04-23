import os
import time
import json
import shutil
import asyncio
import subprocess
import urllib.parse
import requests
from typing import List, Dict, Any
from collections import Counter

from langchain_core.runnables import RunnableLambda
from google import genai
from google.genai import types

# --- Configuration ---
API_KEY = os.environ.get('GEMINI_API_KEY') 
# Highly recommended: Get an NVD API key from https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY = os.environ.get('secrets.NVD_API_KEY')
GEMINI_MODEL = "gemini-3.1-flash-lite-preview"

EXT_TO_CODEQL_LANG = {
    '.py': 'python',
    '.js': 'javascript', '.ts': 'javascript', '.jsx': 'javascript', '.tsx': 'javascript',
    '.java': 'java', '.go': 'go',
    '.c': 'cpp', '.cpp': 'cpp', '.h': 'cpp', '.hpp': 'cpp',
    '.cs': 'csharp', '.rb': 'ruby'
}

# --- SYSTEM PROMPT ---
SYSTEM_PROMPT = """
You are an expert cybersecurity analyst performing a static code analysis.
Your goal is to identify potential security risks and bad practices.

Analyze the provided code snippet. You will also be provided with LIVE context
from the National Vulnerability Database (CVEs) related to the framework used.
Use this context to inform your analysis if applicable.

For each issue found, provide:
1.  "vulnerability": A brief name and CWE ID (e.g., "SQL Injection (CWE-89)").
2.  "level": A severity rating (Critical, High, Medium, or Low).
3.  "line": The line number where the issue occurs.
4.  "snippet": The exact line of code that is problematic.
5.  "explanation": A small, clear, crisp explanation of the vulnerability.

Do NOT generate exploits. Format your response as a single JSON object:
{"findings": [{"vulnerability": "...", "level": "...", "line": 1, "snippet": "...", "explanation": "..."}]}
If no issues are found, return: {"findings": []}
"""

if not API_KEY:
    print("Error: GEMINI_API_KEY not found. Please set the environment variable.")
    exit(1)

# Initialize the new Gemini Client
client = genai.Client(api_key=API_KEY)

# --- NVD Live API Integration ---

def query_real_nvd(keyword: str) -> str:
    """Queries the official NVD 2.0 API using the keywordSearch parameter."""
    print(f"[NVD API] Fetching real CVE context for keyword: '{keyword}'...")

    safe_keyword = urllib.parse.quote(keyword)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={safe_keyword}&resultsPerPage=3"

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 403:
            return "NVD API Rate Limited. Skipping live context."

        if response.status_code == 200:
            data = response.json()
            cves = data.get("vulnerabilities", [])

            if not cves:
                return f"No recent NVD records found matching '{keyword}'."

            context_pieces = []
            for cve_item in cves:
                cve_data = cve_item.get("cve", {})
                cve_id = cve_data.get("id", "Unknown CVE")

                descriptions = cve_data.get("descriptions", [])
                desc_text = "No description available."
                for d in descriptions:
                    if d.get("lang") == "en":
                        desc_text = d.get("value")
                        break

                context_pieces.append(f"- {cve_id}: {desc_text}")

            return "\n".join(context_pieces)
        else:
            return f"NVD API Error: HTTP {response.status_code}"

    except requests.exceptions.RequestException as e:
        return f"Failed to connect to NVD API: {e}"

# --- 1. Traditional SAST Integration (CodeQL) ---

def detect_languages(file_paths: List[str]) -> List[str]:
    langs = set()
    for p in file_paths:
        ext = os.path.splitext(p)[1].lower()
        if ext in EXT_TO_CODEQL_LANG:
            langs.add(EXT_TO_CODEQL_LANG[ext])
    return list(langs)

def run_codeql_sast(language: str, source_dir: str = ".") -> List[Dict[str, Any]]:
    print(f"[CodeQL] Starting SAST scan for {language}...")
    db_path = f"./codeql-db-{language}"
    sarif_output = f"codeql_results_{language}.sarif"
    findings = []

    try:
        # Base CodeQL database creation command
        create_cmd = [
            "codeql", "database", "create", db_path,
            f"--language={language}",
            f"--source-root={source_dir}",
            "--overwrite"
        ]

        # --- THE FIX: Fallback Build Commands for Compiled Languages ---
        try:
            # Modern CodeQL supports build-mode=none for most languages including Java and C++
            cmd_none = create_cmd + ["--build-mode=none"]
            subprocess.run(cmd_none, capture_output=True, check=True)
        except subprocess.CalledProcessError:
            # Fallback if build-mode=none is not supported for this language/version
            if language == "cpp":
                create_cmd.append("--command=sh -c 'find . -type f \\( -name \"*.cpp\" -o -name \"*.c\" \\) | xargs g++ -c || true'")
            elif language == "java":
                create_cmd.append("--command=sh -c 'find . -type f -name \"*.java\" | xargs javac || true'")
            elif language == "go":
                create_cmd.append("--command=go build ./...")

            subprocess.run(create_cmd, capture_output=True, check=True)

        # --- Run the Analysis ---
        query_suite = f"codeql/{language}-queries:codeql-suites/{language}-security-extended.qls"
        subprocess.run([
            "codeql", "database", "analyze", db_path,
            query_suite,
            "--format=sarif-latest",
            f"--output={sarif_output}",
            "--download"
        ], capture_output=True, check=True)

        with open(sarif_output, "r", encoding="utf-8") as f:
            sarif_data = json.load(f)

        # --- DEFENSIVE SARIF PARSING ---
        runs = sarif_data.get("runs", []) if isinstance(sarif_data, dict) else (sarif_data if isinstance(sarif_data, list) else [])

        for run in runs:
            if not isinstance(run, dict): continue

            results = run.get("results", [])
            results = results if isinstance(results, list) else []

            for result in results:
                if not isinstance(result, dict): continue

                rule_id = result.get("ruleId", "Unknown Rule")

                message_obj = result.get("message", {})
                message = message_obj.get("text", "No description") if isinstance(message_obj, dict) else str(message_obj)

                locations = result.get("locations", [])
                start_line = 0
                file_path = "Unknown"

                if isinstance(locations, list) and len(locations) > 0:
                    loc = locations[0]
                    if isinstance(loc, dict):
                        phys_loc = loc.get("physicalLocation", {})
                        if isinstance(phys_loc, dict):
                            art_loc = phys_loc.get("artifactLocation", {})
                            if isinstance(art_loc, dict):
                                file_path = urllib.parse.unquote(art_loc.get("uri", "Unknown"))

                            region = phys_loc.get("region", {})
                            if isinstance(region, dict):
                                start_line = region.get("startLine", 0)

                level_raw = result.get("level", "warning")
                level_map = {"error": "High", "warning": "Medium", "note": "Low"}
                mapped_level = level_map.get(level_raw, "Medium") if isinstance(level_raw, str) else "Medium"

                findings.append({
                    "source_tool": "CodeQL",
                    "vulnerability": f"{rule_id}: {message}",
                    "level": mapped_level,
                    "line": start_line,
                    "snippet": "Snippet omitted by SARIF",
                    "file": file_path
                })

    except subprocess.CalledProcessError as e:
        print(f"[CodeQL Error] Exit code: {e.returncode}. Output: {e.stderr.decode('utf-8') if e.stderr else 'None'}")
    except Exception as e:
        print(f"[CodeQL Error] {e}")
    finally:
        if os.path.exists(db_path): shutil.rmtree(db_path)
        if os.path.exists(sarif_output): os.remove(sarif_output)

    return findings

# --- 2. LLM Sub-Agent with LIVE NVD RAG ---

async def extract_technology(content: str) -> str:
    """Uses a tiny LLM call to extract the main technology to query NVD."""
    prompt = "Identify the primary programming language, framework, or library in this code. Respond with EXACTLY ONE WORD (e.g., Django, Flask, Express, SQLite, React). Code snippet:\n\n" + content[:500]
    try:
        # UPDATED SDK CALL
        response = await client.aio.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(temperature=0.0)
        )
        return response.text.strip().replace("\n", "")
    except Exception:
        return "Software"

async def analyze_code_chunk(file_info: Dict[str, str]) -> Dict[str, Any]:
    file_path = file_info['path']
    content = file_info['content']
    print(f"[Sub-Agent] Analyzing: {file_path}")

    keyword = await extract_technology(content)
    rag_context = await asyncio.to_thread(query_real_nvd, keyword)

    if not NVD_API_KEY:
        await asyncio.sleep(2)

    for attempt in range(3):
        try:
            user_query = f"--- LIVE NVD CONTEXT (Keyword: {keyword}) ---\n{rag_context}\n\n--- CODE TO ANALYZE (`{file_path}`) ---\n```\n{content}\n```"

            # UPDATED SDK CALL
            response = await client.aio.models.generate_content(
                model=GEMINI_MODEL,
                contents=user_query,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT,
                    response_mime_type="application/json",
                    temperature=0.1
                )
            )

            if not response.candidates or response.candidates[0].finish_reason.name != "STOP":
                raise Exception("Invalid API response.")

            analysis_json = json.loads(response.text)

            findings = analysis_json.get("findings", [])
            for f in findings:
                f["file"] = file_path
                f["source_tool"] = "LLM SAST (Live NVD RAG)"

            return {"path": file_path, "findings": findings}

        except Exception as e:
            if attempt < 2:
                await asyncio.sleep(2 ** (attempt + 1))
            else:
                return {"path": file_path, "findings": [], "error": str(e)}

    return {"path": file_path, "findings": []}

# --- 3. Consensus Module ---

def run_consensus(codeql_results: List[Dict[str, Any]], llm_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not codeql_results and not llm_results:
        return {"verified": [], "codeql_only": [], "llm_only": []}

    print("[Consensus] Correlating CodeQL SAST and LLM SAST results using AI...")

    consensus_instruction = (
        "You are an expert security analyst. Correlate the provided CodeQL SAST and LLM SAST findings.\n"
        "Identify which vulnerabilities were found by BOTH tools (verified), which were found ONLY by CodeQL, "
        "and which were found ONLY by the LLM.\n"
        "Return a JSON object strictly with the keys: 'verified', 'codeql_only', and 'llm_only'. "
        "Each key must contain a list of the respective vulnerability objects. "
        "IMPORTANT: You must preserve the original object structure for each finding. "
        "Every object MUST include 'file', 'vulnerability', 'level', 'line', 'snippet', and 'explanation' (if present)."
    )

    prompt = f"CodeQL Findings:\n{json.dumps(codeql_results, indent=2)}\n\nLLM Findings:\n{json.dumps(llm_results, indent=2)}\n"

    try:
        # UPDATED SDK CALL (Synchronous)
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=consensus_instruction,
                response_mime_type="application/json",
                temperature=0.1
            )
        )
        return json.loads(response.text)
    except Exception as e:
        print(f"[Consensus Error] {e}")
        return {"verified": [], "codeql_only": codeql_results, "llm_only": llm_results}

# --- Orchestrator & Helpers ---

def find_files(scan_directory: str) -> List[str]:
    file_paths = []
    valid_extensions = tuple(list(EXT_TO_CODEQL_LANG.keys()) + ['.html', '.sh'])
    for root, dirs, files in os.walk(scan_directory):
        dirs[:] = [d for d in dirs if d not in {".git", ".venv", "node_modules", "__pycache__", ".codeql"} and not d.startswith("codeql-db")]
        for file in files:
            if file.endswith(valid_extensions) and file != os.path.basename(__file__):
                file_paths.append(os.path.join(root, file))
    return file_paths

def read_files(file_paths: List[str]) -> List[Dict[str, str]]:
    files_with_content = []
    for file_path in file_paths:
        try:
            if os.path.getsize(file_path) <= 50_000:
                with open(file_path, 'r', encoding='utf-8') as f:
                    files_with_content.append({"path": file_path, "content": f.read()})
        except Exception:
            continue
    return files_with_content

def generate_markdown_report(consensus_data: Dict[str, Any]) -> str:
    print("[Report] Generating Markdown Report...")

    verified = consensus_data.get("verified", [])
    llm_only = consensus_data.get("llm_only", [])
    codeql_only = consensus_data.get("codeql_only", [])

    all_findings = llm_only + codeql_only
    level_counts = Counter(f.get("level", "Unknown").capitalize() for f in all_findings)

    md = "# Comprehensive Vulnerability Report\n\n"
    md += "## Executive Summary\n\n"
    md += f"- **Critical:** {level_counts.get('Critical', 0)}\n"
    md += f"- **High:** {level_counts.get('High', 0)}\n"
    md += f"- **Medium:** {level_counts.get('Medium', 0)}\n"
    md += f"- **Low:** {level_counts.get('Low', 0)}\n\n"

    def format_findings(findings: List[Dict[str, Any]]):
        section = ""
        if not findings:
            return section

        for idx, f in enumerate(findings, 1):
            vuln = f.get('vulnerability', 'N/A')
            level = f.get('level', 'Unknown').capitalize()
            file_path = f.get('file', 'Unknown')
            line = f.get('line', '?')

            section += f"### {idx}. {vuln}\n\n"
            section += f"- **Severity:** {level}\n"
            section += f"- **Location:** `{file_path}` : Line {line}\n"

            snippet = f.get('snippet', '')
            if snippet and snippet != "Snippet omitted by SARIF":
                section += "\n**Vulnerable Code:**\n"
                section += f"```python\n{snippet.strip()}\n```\n\n"
            else:
                section += "\n"
        return section

    md += "## LLM Only Findings\n\n"
    llm_str = format_findings(llm_only)
    if llm_str:
        md += llm_str

    md += "---\n\n## CodeQL Only Findings\n\n"
    cql_str = format_findings(codeql_only)
    if cql_str:
        md += cql_str

    return md.strip() + "\n"

async def main():
    print("=== Starting Vulnerability Scan ===")
    start_time = time.time()

    file_paths = find_files('.')
    if not file_paths:
        print("[Main Agent] No scannable files found. Exiting.")
        return

    detected_langs = detect_languages(file_paths)
    print(f"[Main Agent] Detected CodeQL-supported languages: {detected_langs}")

    codeql_findings_flat = []
    for lang in detected_langs:
        codeql_findings_flat.extend(run_codeql_sast(language=lang, source_dir="."))

    files_to_analyze = read_files(file_paths)
    llm_findings_flat = []

    if files_to_analyze:
        print(f"[Main Agent] Step 3: Mapping {len(files_to_analyze)} files to LLM sub-agents with LIVE NVD RAG...")
        analysis_chain = RunnableLambda(analyze_code_chunk)
        llm_raw_results = await analysis_chain.map().ainvoke(files_to_analyze)
        for res in llm_raw_results:
            llm_findings_flat.extend(res.get("findings", []))

    print(f"[LLM SAST] Found {len(llm_findings_flat)} issues.")

    consensus_results = run_consensus(codeql_findings_flat, llm_findings_flat)
    report_content = generate_markdown_report(consensus_results)

    with open("analysis_report.md", "w", encoding="utf-8") as f:
        f.write(report_content)

    print(f"\n[Main Agent] Workflow complete in {time.time() - start_time:.2f} seconds. Report saved.")

if __name__ == "__main__":
    asyncio.run(main())
