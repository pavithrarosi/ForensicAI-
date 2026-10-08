
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Header, Depends
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pathlib import Path
from datetime import datetime
from collections import Counter
import hashlib, json, re, uuid, shutil, html, math, os, base64, secrets, hmac

try:
    from pypdf import PdfReader
except Exception:
    PdfReader = None

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import joblib
    SKLEARN_AVAILABLE = True
except Exception:
    SKLEARN_AVAILABLE = False

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False

BASE = Path(__file__).resolve().parent.parent
DATA = BASE / "data"
UPLOADS = DATA / "uploads"
REPORTS = DATA / "reports"
STORE = DATA / "store.json"
FRONTEND = BASE / "frontend"
ML_DIR = DATA / "ml"
MODEL_PATH = ML_DIR / "forensic_anomaly_model.joblib"
ML_META = ML_DIR / "model_meta.json"
DATASET_REGISTRY = DATA / "dataset_sources.json"
ML_DIR.mkdir(parents=True, exist_ok=True)

for p in (UPLOADS, REPORTS):
    p.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="ForensicAI", version="2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

def load():
    if STORE.exists():
        try:
            db=json.loads(STORE.read_text(encoding="utf-8"))
            db.setdefault("users", [])
            db.setdefault("sessions", [])
            db.setdefault("cases", [])
            db.setdefault("reports", [])
            db.setdefault("records", [])
            db.setdefault("audit", [])
            return db
        except Exception: pass
    return {"users": [], "sessions": [], "cases": [], "reports": [], "records": [], "audit": []}

def save(db):
    STORE.write_text(json.dumps(db, indent=2, ensure_ascii=False), encoding="utf-8")


def _password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310000)
    return base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()

def _verify_password(password, stored):
    try:
        salt_b64, digest_b64 = stored.split("$", 1)
        salt = base64.b64decode(salt_b64.encode())
        expected = base64.b64decode(digest_b64.encode())
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310000)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False

def require_user(authorization: str = Header(default="", alias="Authorization")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Please login first")
    token = authorization[7:].strip()
    db = load()
    session = next((x for x in db.get("sessions", []) if x.get("token") == token), None)
    if not session:
        raise HTTPException(401, "Session expired. Please login again")
    user = next((u for u in db.get("users", []) if u.get("user_id") == session.get("user_id")), None)
    if not user:
        raise HTTPException(401, "User account not found")
    return user["user_id"]

class AuthIn(BaseModel):
    username: str
    password: str

@app.post("/api/auth/register")
def register(body: AuthIn):
    username = body.username.strip().lower()
    if len(username) < 3 or len(body.password) < 4:
        raise HTTPException(400, "Username must have 3+ characters and password 4+ characters")
    db = load()
    db.setdefault("users", [])
    db.setdefault("sessions", [])
    if any(u.get("username") == username for u in db["users"]):
        raise HTTPException(409, "Username already exists")
    user = {"user_id":"USR-" + uuid.uuid4().hex[:12].upper(), "username":username, "password_hash":_password_hash(body.password)}
    db["users"].append(user)
    save(db)
    return {"ok":True, "user_id":user["user_id"], "username":user["username"]}

@app.post("/api/auth/login")
def login(body: AuthIn):
    username = body.username.strip().lower()
    db = load()
    user = next((u for u in db.get("users", []) if u.get("username") == username), None)
    if not user or not _verify_password(body.password, user.get("password_hash", "")):
        raise HTTPException(401, "Invalid username or password")
    token = secrets.token_urlsafe(32)
    db.setdefault("sessions", [])
    db["sessions"] = [x for x in db["sessions"] if x.get("user_id") != user["user_id"]]
    db["sessions"].append({"token":token,"user_id":user["user_id"]})
    save(db)
    return {"ok":True,"token":token,"user_id":user["user_id"],"username":user["username"]}

@app.post("/api/auth/logout")
def logout(user: str = Depends(require_user), authorization: str = Header(default="", alias="Authorization")):
    token = authorization[7:].strip() if authorization.startswith("Bearer ") else ""
    db = load()
    db["sessions"] = [x for x in db.get("sessions", []) if x.get("token") != token]
    save(db)
    return {"ok":True}

@app.get("/api/auth/me")
def me(user: str = Depends(require_user)):
    db=load(); u=next(u for u in db.get("users",[]) if u.get("user_id")==user)
    return {"user_id":u["user_id"],"username":u["username"]}

def audit(db, case_id, action, details="", user=""):
    db["audit"].insert(0, {"id": str(uuid.uuid4()), "case_id": case_id, "action": action, "details": details,
                           "timestamp": datetime.now().isoformat(timespec="seconds"), "user": user})
    save(db)

def sha256(path):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for chunk in iter(lambda:f.read(1024*1024), b""): h.update(chunk)
    return h.hexdigest()

def parse_pdf(path):
    if PdfReader is None: raise RuntimeError("pypdf is not installed")
    reader=PdfReader(str(path))
    pages=[]
    for p in reader.pages:
        try: pages.append(p.extract_text() or "")
        except Exception: pages.append("")
    text="\n".join(pages)
    lines=[x.strip() for x in text.splitlines() if x.strip()]
    records=[]
    # Extract line-oriented forensic artifacts conservatively. No demo fallback.
    patterns = [
        ("message", r"(whatsapp|signal|telegram|sms|imessage).*(message|chat|text)"),
        ("call", r"\b(call|incoming|outgoing|missed)\b"),
        ("location", r"(latitude|longitude|gps|location)"),
        ("browser", r"(http://|https://|browser|search query|visited)"),
        ("media", r"(\.jpg|\.jpeg|\.png|\.mp4|\.mov|\.wav|\.mp3)\b"),
        ("application", r"(installed application|application name|version)"),
        ("contact", r"(contact name|phone number|email)")
    ]
    for i,line in enumerate(lines):
        low=line.lower()
        kind="other"
        for k,p in patterns:
            if re.search(p,low): kind=k; break
        records.append({"record_id": f"R{i+1:05d}", "type": kind, "timestamp": "",
                        "summary": line[:500], "raw": line})
    # Capture common metadata fields without inventing values.
    metadata={}
    for key, labels in {
        "case_id":["case id","case number"], "case_name":["case name"],
        "agency":["agency"], "examiner":["examiner","investigator"],
        "device":["device model","model"], "manufacturer":["manufacturer"],
        "os":["operating system","os"], "sha256":["sha-256","sha256"]
    }.items():
        for line in lines:
            for label in labels:
                m=re.match(rf"^\s*{re.escape(label)}\s*[:\-]\s*(.+)$", line, re.I)
                if m: metadata[key]=m.group(1).strip(); break
            if key in metadata: break
    return {"pages":len(reader.pages), "text":text, "records":records, "metadata":metadata}


PUBLIC_DATASETS = [
    {"name":"Android 10 Cellebrite Extraction","source":"Digital Corpora / NIST CFReDS","year":2020,"url":"https://cfreds.nist.gov/all/","purpose":"Android forensic extraction and artifact parsing","status":"reference / importable"},
    {"name":"Android 10 Image","source":"Digital Corpora / Joshua Hickman","year":2020,"url":"https://downloads.digitalcorpora.org/corpora/mobile/android_10/Android10-ImageCreation.pdf","purpose":"Google Pixel 3 Android 10 forensic image; Cellebrite and non-Cellebrite extraction","status":"reference / importable"},
    {"name":"Digital-Forensics v1.0 UMAM-DF Dataset","source":"Ashok Kumar Mohan / TCCS-AMRITA; hosted on GitHub and CFReDS","year":2021,"url":"https://github.com/Amrita-TIFAC-Cyber/Digital-Forensics","purpose":"Mobile, laptop, desktop, pendrive, cloud, messaging/social-media and metadata-forensics experiments","status":"reference / importable"}
]

def record_features(records):
    feats=[]
    for r in records:
        text=(r.get("raw") or r.get("summary") or "")
        low=text.lower()
        feats.append([
            1 if r.get("type")=="message" else 0,
            1 if r.get("type")=="call" else 0,
            1 if r.get("type")=="contact" else 0,
            1 if r.get("type")=="location" else 0,
            1 if r.get("type")=="browser" else 0,
            1 if r.get("type")=="application" else 0,
            1 if r.get("type")=="media" else 0,
            len(text),
            len(re.findall(r"https?://", text, re.I)),
            len(re.findall(r"\b(?:password|threat|malware|suspicious|deleted|recovered|urgent|unknown|fraud|phishing)\b", low)),
            len(re.findall(r"\b\d{7,15}\b", text)),
            len(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)),
        ])
    return feats

def ml_status(db):
    meta={}
    if ML_META.exists():
        try: meta=json.loads(ML_META.read_text(encoding="utf-8"))
        except Exception: meta={}
    return {"available":SKLEARN_AVAILABLE,"trained":MODEL_PATH.exists(),"meta":meta,"feature_names":["is_message","is_call","is_contact","is_location","is_browser","is_application","is_media","text_length","url_count","review_term_count","phone_like_count","ip_like_count"]}

@app.get("/api/ml/datasets")
def ml_datasets():
    return {"datasets":PUBLIC_DATASETS,"note":"These are public forensic reference sources. They do not by themselves provide a universal suspicious/not-suspicious ground-truth label. ForensicAI therefore uses anomaly detection unless an explicitly labeled training table is supplied."}

@app.get("/api/ml/status")
def ml_status_endpoint():
    return ml_status(load())

@app.post("/api/ml/train")
def ml_train(user: str = Depends(require_user)):
    if not SKLEARN_AVAILABLE:
        raise HTTPException(500,"scikit-learn/joblib are not installed")
    db=load()
    rows=db.get("records",[])
    if len(rows)<20:
        raise HTTPException(400,"At least 20 extracted forensic records are required before training the anomaly model. Upload/process UFDR evidence first.")
    X=record_features(rows)
    scaler=StandardScaler()
    Xs=scaler.fit_transform(X)
    model=IsolationForest(n_estimators=200, contamination="auto", random_state=42)
    model.fit(Xs)
    scores=(-model.decision_function(Xs)).tolist()
    meta={"trained_at":datetime.now().isoformat(timespec="seconds"),"records":len(rows),"algorithm":"IsolationForest","training_scope":"case records available in ForensicAI","dataset_references":PUBLIC_DATASETS,"note":"Unsupervised anomaly model. It is not a criminality classifier and has no ground-truth accuracy claim."}
    joblib.dump({"model":model,"scaler":scaler},MODEL_PATH)
    ML_META.write_text(json.dumps(meta,indent=2),encoding="utf-8")
    audit(db,"__ML__","ML_MODEL_TRAINED",f"IsolationForest trained on {len(rows)} extracted records",user)
    return {"ok":True,"meta":meta}

@app.get("/api/cases/{case_id}/ml")
def case_ml(case_id:str, user: str = Depends(require_user)):
    db=load(); get_owned_case(db,case_id,user)
    rows=[r for r in db.get("records",[]) if r.get("case_id")==case_id]
    if not rows: return {"trained":MODEL_PATH.exists(),"scored":False,"records":[]}
    if not MODEL_PATH.exists() or not SKLEARN_AVAILABLE:
        return {"trained":False,"scored":False,"records":[],"message":"Train the anomaly model after extracting evidence."}
    bundle=joblib.load(MODEL_PATH)
    X=record_features(rows)
    Xs=bundle["scaler"].transform(X)
    model=bundle["model"]
    vals=(-model.decision_function(Xs))
    out=[]
    for r,v in zip(rows,vals):
        out.append({"record_id":r.get("record_id"),"report_id":r.get("report_id"),"type":r.get("type"),"summary":r.get("summary"),"anomaly_score":round(float(v),4),"anomalous":bool(model.predict([Xs[len(out)]])[0]==-1)})
    out.sort(key=lambda x:x["anomaly_score"],reverse=True)
    return {"trained":True,"scored":True,"records":out[:500],"model":ml_status(db)["meta"]}

@app.get("/")
def home():
    return FileResponse(FRONTEND/"index.html")

@app.get("/assets/{name}")
def assets(name:str):
    path=FRONTEND/name
    if not path.exists(): raise HTTPException(404)
    return FileResponse(path)

@app.get("/api/health")
def health(): return {"ok":True, "version":"2.0"}


def owned_cases(db, user):
    changed=False
    for c in db["cases"]:
        if not c.get("owner"):
            c["owner"]=user
            changed=True
    if changed: save(db)
    return [c for c in db["cases"] if c.get("owner")==user]

def get_owned_case(db, case_id, user):
    c=next((x for x in db["cases"] if x["case_id"]==case_id and x.get("owner")==user),None)
    if not c: raise HTTPException(404,"Case not found")
    return c

@app.get("/api/cases")
def cases(user: str = Depends(require_user)):
    db=load(); return owned_cases(db,user)

class CaseIn(BaseModel):
    case_id:str
    name:str
    description:str=""
    examiner:str=""
    investigation_date:str=""

@app.post("/api/cases")
def create_case(c:CaseIn, user: str = Depends(require_user)):
    db=load(); owned_cases(db,user)
    # Case names may be identical for different users. The system creates a globally unique Case ID.
    case_id = "CASE-" + uuid.uuid4().hex[:12].upper()
    item={**c.model_dump(), "case_id":case_id, "owner":user, "created_at":datetime.now().isoformat(timespec="seconds")}
    db["cases"].append(item); save(db); audit(db,case_id,"CASE_CREATED",c.name,user)
    return item

@app.get("/api/cases/{case_id}")
def get_case(case_id:str, user: str = Depends(require_user)):
    db=load(); return get_owned_case(db,case_id,user)

@app.get("/api/cases/{case_id}/reports")
def case_reports(case_id:str, user: str = Depends(require_user)):
    db=load(); get_owned_case(db,case_id,user); return [r for r in db["reports"] if r["case_id"]==case_id]

@app.post("/api/cases/{case_id}/reports")
async def upload_report(case_id:str, file:UploadFile=File(...), user: str = Depends(require_user)):
    db=load(); get_owned_case(db,case_id,user)
    rid="RPT-"+uuid.uuid4().hex[:10].upper()
    safe=Path(file.filename or "report.pdf").name
    path=UPLOADS/(rid+"_"+safe)
    with open(path,"wb") as out: shutil.copyfileobj(file.file,out)
    digest=sha256(path)
    report={"report_id":rid,"case_id":case_id,"filename":safe,"sha256":digest,
            "uploaded_at":datetime.now().isoformat(timespec="seconds"),"status":"processing","pages":0}
    try:
        parsed=parse_pdf(path)
        report.update({"status":"processed","pages":parsed["pages"],"metadata":parsed["metadata"]})
        for rec in parsed["records"]:
            rec.update({"case_id":case_id,"report_id":rid})
            db["records"].append(rec)
    except Exception as e:
        report.update({"status":"failed","error":str(e)})
    db["reports"].append(report); save(db); audit(db,case_id,"REPORT_UPLOADED",rid,user)
    return report

@app.get("/api/cases/{case_id}/summary")
def summary(case_id:str, user: str = Depends(require_user)):
    db=load(); get_owned_case(db,case_id,user); rec=[r for r in db["records"] if r["case_id"]==case_id]
    cnt=Counter(r["type"] for r in rec)
    reports=[r for r in db["reports"] if r["case_id"]==case_id]
    return {"case_id":case_id,"reports":len(reports),"records":len(rec),"counts":dict(cnt),
            "processed_reports":sum(r["status"]=="processed" for r in reports),
            "failed_reports":sum(r["status"]=="failed" for r in reports)}

@app.get("/api/cases/{case_id}/records")
def records(case_id:str, q:str="", type:str="", report_id:str="", user: str = Depends(require_user)):
    db=load(); get_owned_case(db,case_id,user); rows=[r for r in db["records"] if r["case_id"]==case_id]
    if type: rows=[r for r in rows if r["type"]==type]
    if report_id: rows=[r for r in rows if r["report_id"]==report_id]
    if q:
        q=q.lower(); rows=[r for r in rows if q in json.dumps(r,ensure_ascii=False).lower()]
    return rows[:2000]

@app.get("/api/cases/{case_id}/timeline")
def timeline(case_id:str, user: str = Depends(require_user)):
    db=load(); get_owned_case(db,case_id,user); return [r for r in db["records"] if r["case_id"]==case_id][:500]

@app.get("/api/cases/{case_id}/audit")
def audit_log(case_id:str, user: str = Depends(require_user)):
    db=load(); get_owned_case(db,case_id,user); return [x for x in load()["audit"] if x["case_id"]==case_id]

class AssistantIn(BaseModel):
    question:str

@app.post("/api/cases/{case_id}/assistant")
def assistant(case_id:str, body:AssistantIn, user: str = Depends(require_user)):
    db=load(); get_owned_case(db,case_id,user)
    rec=[r for r in db["records"] if r["case_id"]==case_id]
    reports=[r for r in db["reports"] if r["case_id"]==case_id]
    q=body.question.strip().lower()
    counts=Counter(r["type"] for r in rec)
    if not reports:
        answer="Please upload a UFDR report first. I can answer questions only after forensic evidence has been uploaded and processed for this case."
        matches=[]
    elif not rec:
        answer="A UFDR report is attached to this case, but no forensic records were extracted from it. Please check the report processing status or upload another supported UFDR report."
        matches=[]
    else:
        words=[w for w in re.findall(r"[a-z0-9_@.+-]+",q) if len(w)>2 and w not in {"what","which","where","when","show","tell","about","this","case","the","are","any","from","with","how","many","does","did","give","list","find"}]
        matches=[r for r in rec if any(w in json.dumps(r,ensure_ascii=False).lower() for w in words)] if words else []
        if any(x in q for x in ["how many","count","number of","total"]):
            if "message" in q: answer=f"This case has {counts.get('message',0)} extracted message records."
            elif "call" in q: answer=f"This case has {counts.get('call',0)} extracted call records."
            elif "contact" in q: answer=f"This case has {counts.get('contact',0)} extracted contact records."
            elif "location" in q or "gps" in q: answer=f"This case has {counts.get('location',0)} extracted location records."
            else: answer=f"This case has {len(rec)} extracted records across {len(set(r['report_id'] for r in rec))} report(s)."
        elif "suspicious" in q or "indicator" in q or "threat" in q:
            hits=suspicious_records(rec); answer=f"I found {len(hits)} rule-based review lead(s) in the extracted records." if hits else "No configured suspicious-activity review terms were found in the extracted records."; matches=hits
        elif matches:
            sample=matches[:8]; answer=f"I found {len(matches)} matching extracted record(s). Here are the closest matches: " + " | ".join(f"{r['record_id']} ({r['type']}): {r.get('summary','')[:180]}" for r in sample)
        else:
            answer=f"The case contains {len(rec)} extracted records. I could not find an evidence record matching that question. Try a specific term, record ID, artifact type, or ask for counts."
    audit(db,case_id,"ASSISTANT_QUERY",body.question,user)
    return {"answer":answer,"grounded_records":len(matches) if rec else 0,"matches":[{"record_id":r["record_id"],"type":r["type"],"report_id":r["report_id"],"summary":r.get("summary","")[:300]} for r in matches[:20]]}

@app.post("/api/cases/{case_id}/generate-report")
def generate_report(case_id:str, user: str = Depends(require_user)):
    db=load(); get_owned_case(db,case_id,user); rec=[r for r in db["records"] if r["case_id"]==case_id]
    payload={"case_id":case_id,"generated_at":datetime.now().isoformat(timespec="seconds"),
             "reports":[r for r in db["reports"] if r["case_id"]==case_id],
             "record_counts":dict(Counter(r["type"] for r in rec)),
             "records":rec}
    out=REPORTS/(case_id+"_investigation_report.json")
    out.write_text(json.dumps(payload,indent=2,ensure_ascii=False),encoding="utf-8")
    audit(db,case_id,"REPORT_GENERATED",out.name,user)
    return FileResponse(out, filename=out.name, media_type="application/json")

@app.delete("/api/cases/{case_id}")
def delete_case(case_id:str, user: str = Depends(require_user)):
    db=load(); case=get_owned_case(db,case_id,user)
    report_ids={r["report_id"] for r in db["reports"] if r["case_id"]==case_id}
    for r in db["reports"]:
        if r["case_id"]==case_id:
            for f in UPLOADS.glob(r["report_id"]+"_*"):
                try: f.unlink()
                except OSError: pass
    db["cases"]=[x for x in db["cases"] if not (x["case_id"]==case_id and x.get("owner")==user)]
    db["reports"]=[x for x in db["reports"] if x["case_id"]!=case_id]
    db["records"]=[x for x in db["records"] if x["case_id"]!=case_id]
    db["audit"]=[x for x in db["audit"] if x["case_id"]!=case_id]
    for f in REPORTS.glob(case_id+"_*"):
        try: f.unlink()
        except OSError: pass
    save(db)
    return {"deleted":True,"case_id":case_id,"reports_deleted":len(report_ids),"case_name":case.get("name","")}

SUSPICIOUS_TERMS = re.compile(
    r"password|threat|suspicious|malware|deleted|recovered|urgent|unknown|hidden|secret|credential|phishing|fraud",
    re.I,
)

def suspicious_records(records):
    return [r for r in records if SUSPICIOUS_TERMS.search((r.get("raw") or "") + " " + (r.get("summary") or ""))]

def _p(text, style):
    return Paragraph(html.escape(str(text or "")).replace("\n", "<br/>"), style)

@app.post("/api/cases/{case_id}/generate-suspicious-pdf")
def generate_suspicious_pdf(case_id:str, user: str = Depends(require_user)):
    if not REPORTLAB_AVAILABLE:
        raise HTTPException(500, "PDF generation is unavailable. Install reportlab and restart the server.")
    db=load()
    case=get_owned_case(db,case_id,user)
    if not case:
        raise HTTPException(404, "Case not found")
    records=[r for r in db["records"] if r["case_id"]==case_id]
    hits=suspicious_records(records)
    reports=[r for r in db["reports"] if r["case_id"]==case_id]
    out=REPORTS/(case_id+"_suspicious_activity_report.pdf")

    styles=getSampleStyleSheet()
    title=ParagraphStyle("ForensicTitle", parent=styles["Title"], alignment=TA_CENTER, fontSize=20, leading=24, spaceAfter=12)
    subtitle=ParagraphStyle("ForensicSubtitle", parent=styles["Normal"], alignment=TA_CENTER, fontSize=10, leading=14, textColor=colors.HexColor("#5c6865"), spaceAfter=18)
    h1=ParagraphStyle("H1", parent=styles["Heading1"], fontSize=14, leading=18, spaceBefore=12, spaceAfter=8)
    h2=ParagraphStyle("H2", parent=styles["Heading2"], fontSize=11, leading=14, spaceBefore=8, spaceAfter=5)
    body=ParagraphStyle("Body", parent=styles["BodyText"], fontSize=9, leading=13, spaceAfter=5)
    small=ParagraphStyle("Small", parent=body, fontSize=7.5, leading=10)
    note=ParagraphStyle("Note", parent=body, textColor=colors.HexColor("#6a3d00"), backColor=colors.HexColor("#fff4df"), borderPadding=7, spaceBefore=6, spaceAfter=10)

    doc=SimpleDocTemplate(str(out), pagesize=A4, rightMargin=38, leftMargin=38, topMargin=42, bottomMargin=42, title=f"{case_id} Suspicious Activity Report")
    story=[]
    story += [_p("FORENSICAI", title), _p("AI-Assisted Digital Forensic Investigation", subtitle), _p("SUSPICIOUS ACTIVITY REVIEW REPORT", h1)]
    story.append(_p("This report is generated only from forensic records extracted from the UFDR report(s) uploaded to this case. The indicators below are rule-based review leads and are not conclusions of criminal activity.", note))

    info=[
        [_p("Case ID", small), _p(case.get("case_id"), small)],
        [_p("Case Name", small), _p(case.get("name"), small)],
        [_p("Examiner", small), _p(case.get("examiner"), small)],
        [_p("Investigation Date", small), _p(case.get("investigation_date"), small)],
        [_p("Generated", small), _p(datetime.now().isoformat(timespec="seconds"), small)],
        [_p("Extracted Records", small), _p(len(records), small)],
        [_p("Review Leads", small), _p(len(hits), small)],
    ]
    t=Table(info, colWidths=[120, 390])
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(0,-1),colors.HexColor("#edf2f0")),("GRID",(0,0),(-1,-1),0.35,colors.HexColor("#cbd5d1")),("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),7),("RIGHTPADDING",(0,0),(-1,-1),7),("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6)]))
    story += [t, Spacer(1,12)]

    story.append(_p("Source UFDR Reports", h1))
    if reports:
        rows=[[_p("Report ID",small),_p("Filename",small),_p("Status",small),_p("SHA-256",small)]]
        for r in reports:
            rows.append([_p(r.get("report_id"),small),_p(r.get("filename"),small),_p(r.get("status"),small),_p(r.get("sha256"),small)])
        rt=Table(rows,colWidths=[85,120,65,240],repeatRows=1)
        rt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1f3a36")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#cbd5d1")),("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),5),("RIGHTPADDING",(0,0),(-1,-1),5),("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5)]))
        story.append(rt)
    else:
        story.append(_p("No UFDR report has been uploaded to this case.", body))

    story.append(_p("Suspicious Activity Review", h1))
    if not records:
        story.append(_p("No forensic data is available. No suspicious-activity assessment was generated.", body))
    elif not hits:
        story.append(_p("No rule-based suspicious indicators were detected in the extracted records reviewed. This does not establish that no suspicious activity occurred; it means that none of the configured review terms were found in the extracted text.", body))
    else:
        counts=Counter(r.get("type","other") for r in hits)
        summary_rows=[[_p("Artifact Type",small),_p("Review Leads",small)]] + [[_p(k,small),_p(v,small)] for k,v in sorted(counts.items())]
        st=Table(summary_rows,colWidths=[260,250],repeatRows=1)
        st.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1f3a36")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#cbd5d1")),("ALIGN",(1,1),(1,-1),"CENTER"),("VALIGN",(0,0),(-1,-1),"TOP")]))
        story += [st, Spacer(1,10)]
        for n,r in enumerate(hits,1):
            story.append(KeepTogether([_p(f"Review Lead {n}: {r.get('record_id','')}", h2),
                _p(f"Artifact type: {r.get('type','other')} | Source report: {r.get('report_id','')} | Timestamp: {r.get('timestamp') or 'Not extracted'}", small),
                _p(r.get('summary') or r.get('raw') or '', body)]))
            story.append(Spacer(1,5))

    story.append(PageBreak())
    story.append(_p("Methodology and Evidence Notes", h1))
    story.append(_p("The suspicious-activity section is produced by scanning extracted UFDR record text for configured review terms such as suspicious, threat, malware, deleted, recovered, urgent, unknown, password, phishing, and fraud. Only records belonging to the selected Case ID are considered. No default or sample forensic records are inserted.", body))
    story.append(_p("These indicators are triage leads for investigator review. They should be validated against the underlying UFDR evidence and the original forensic examination context before being treated as findings.", body))
    story.append(_p("Case/report separation: every included record retains its case_id and report_id so evidence is traceable to its source report.", body))

    doc.build(story)
    audit(db,case_id,"SUSPICIOUS_ACTIVITY_PDF_GENERATED",out.name,user)
    return FileResponse(out, filename=out.name, media_type="application/pdf")

if __name__=="__main__":
    import uvicorn
    uvicorn.run(app,host="127.0.0.1",port=8000)
