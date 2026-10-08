"""Train the ForensicAI anomaly model from Digital Corpora's Android 10 SMS spreadsheet.

Place SMS-Messages.xlsx in data/datasets/ before running.
This is an unsupervised anomaly model because the public SMS spreadsheet does not provide a
universal suspicious/not-suspicious ground-truth label.
"""
from pathlib import Path
import re, json
from datetime import datetime
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/'data'/'datasets'/'SMS-Messages.xlsx'
OUT=ROOT/'data'/'ml'
OUT.mkdir(parents=True,exist_ok=True)
if not SRC.exists():
    raise SystemExit('Missing data/datasets/SMS-Messages.xlsx')

df=pd.read_excel(SRC)
text=df.astype(str).agg(' '.join,axis=1)

def feat(s):
    low=s.lower()
    return [len(s), len(re.findall(r'https?://',s,re.I)), len(re.findall(r'\b(?:password|urgent|threat|malware|fraud|phishing|unknown|deleted|recovered|suspicious)\b',low)), len(re.findall(r'\b\d{7,15}\b',s))]
X=[feat(s) for s in text]
scaler=StandardScaler(); Xs=scaler.fit_transform(X)
model=IsolationForest(n_estimators=250,random_state=42,contamination='auto')
model.fit(Xs)
joblib.dump({'model':model,'scaler':scaler,'feature_names':['text_length','url_count','review_term_count','phone_like_count']},OUT/'android10_sms_anomaly_model.joblib')
meta={'trained_at':datetime.now().isoformat(timespec='seconds'),'records':len(df),'source':'Digital Corpora Android 10 Image / SMS-Messages.xlsx','source_url':'https://downloads.digitalcorpora.org/corpora/mobile/android_10/Android10-ImageCreation.pdf','algorithm':'IsolationForest','note':'Unsupervised anomaly model; no ground-truth suspicious/not-suspicious label is claimed.'}
(OUT/'android10_sms_model_meta.json').write_text(json.dumps(meta,indent=2),encoding='utf-8')
print(json.dumps(meta,indent=2))
