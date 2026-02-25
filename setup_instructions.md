
#  Setup Instructions

Follow these steps to set up and run the project locally.

## 1. Create a Python Virtual Environment

```bash
python -m venv venv
```

Activate the environment:

* **On macOS/Linux:**

```bash
source venv/bin/activate
```

* **On Windows:**

```bash
venv\Scripts\activate
```

---

## 2. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 3. Set Up Environment Variable

Make sure your **GEMINI_API_KEY** is set in the environment.

* **On macOS/Linux:**

```bash
export GEMINI_API_KEY="your_api_key_here"
```

* **On Windows (Command Prompt):**

```bash
set GEMINI_API_KEY=your_api_key_here
```

---

## 4. Run the Scanner

```bash
python scan.py
```

---

