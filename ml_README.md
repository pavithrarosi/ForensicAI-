# ForensicAI ML data workflow

Selected public forensic sources:
- Digital Corpora / NIST CFReDS — Android 10 Cellebrite Extraction
- Digital Corpora / Joshua Hickman — Android 10 Image
- Ashok Kumar Mohan / TCCS-AMRITA — Digital-Forensics v1.0 UMAM-DF

The public forensic collections are reference/test datasets. They do not provide a universal ground-truth label for criminal or suspicious behavior. ForensicAI therefore uses an **unsupervised Isolation Forest anomaly model** rather than inventing labels.

## Train from the Android 10 SMS subset

PowerShell:

```powershell
cd ForensicAI_FINAL
.\scripts\download_public_sources.ps1
python scripts\train_android10_sms.py
```

This creates a model under `data/ml/` from the public `SMS-Messages.xlsx` subset. It is an anomaly model, not a criminality classifier.

## Case model

The website can also train a case-adaptive anomaly model from extracted records after a case contains at least 20 records. This keeps the uploaded UFDR report as the source of truth and never inserts default forensic counts.
