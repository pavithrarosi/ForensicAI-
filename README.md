# ForensicAI — User-Isolated Forensic Investigation Platform

## New features
- Investigator-specific case isolation using the logged-in local presentation name.
- Delete Case removes the case, its UFDR reports, extracted records, audit entries, uploaded source files, and generated reports.
- Case ownership is checked on all case-level API endpoints.
- Enhanced evidence-grounded assistant searches extracted records and returns matching record IDs/source reports.
- No fabricated forensic records or default counts.
- Existing suspicious-activity PDF generation retained.

## Run
```powershell
cd ".\ForensicAI_FINAL\backend"
if (!(Test-Path ".\.venv\Scripts\python.exe")) { python -m venv .venv; .\.venv\Scripts\python.exe -m pip install -r requirements.txt }
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn main:app --reload
```
Open http://127.0.0.1:8000

The login screen is a presentation/local identity gate, not production authentication. For real deployment, replace it with proper authentication and secure sessions.
