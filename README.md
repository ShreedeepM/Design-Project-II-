# 🚨 Vulnerability Detection in OSS via LLMs

An automated **DevSecOps tool** designed to integrate **Large Language Models (LLMs)** into CI/CD pipelines for **proactive vulnerability detection** in open-source software (OSS).

---

## 🔍 Current Implementation (Proof of Concept)

This project currently functions as an automated **GitHub Action** that triggers on repository pull requests.

### ⚙️ Features

- **Code Ingestion**  
  Extracts relevant source code files from PR changes.

- **LLM Analysis**  
  Routes code segments to the **Google Gemini API** to identify common vulnerability types.

- **Sub-Agent Pool**  
  Parallel LLM workers performing targeted scans for:
  - Known vulnerability patterns  
  - Poor coding practices  
  - Potential zero-day flaws  

- **Automated Reporting**  
  Generates a structured **Markdown report** with:
  - Vulnerability severity levels  
  - Affected code locations  
  - Clear explanations  
  → Automatically posted as a **PR comment**

---

## 🧠 Proposed Architecture (In Development)

A scalable **multi-agent framework** to handle large-scale OSS repositories.

### 🧩 Components

- **Orchestrator Agent**  
  Central controller that:
  - Parses large codebases  
  - Distributes tasks across agents  

- **Knowledge Base Integration**  
  Enhances LLM reasoning using:
  - CVE (Common Vulnerabilities and Exposures)  
  - CWE (Common Weakness Enumeration)  
  - CVSS (Common Vulnerability Scoring System)  

- **Consensus Validation**  
  - Aggregates results from multiple agents  
  - Reduces false positives  
  - Improves reliability of reports  

---

## 🛠️ Technology Stack

- **Language & Orchestration**  
  Python 3.9+, LangChain  

- **AI Provider**  
  Google Gemini API  

- **CI/CD Pipeline**  
  GitHub Actions  

---

## 🚀 Future Enhancements

- Real-time vulnerability scoring  
- Policy drift detection  
- Explainable AI-based security insights  
- Integration with enterprise DevSecOps pipelines  

---

## ⭐ Key Highlights

- ⚡ Fully automated security analysis in CI/CD  
- 🤖 Multi-agent LLM-based architecture  
- 🔍 Detects both known & zero-day vulnerabilities  
- 📊 Structured, developer-friendly reports  
