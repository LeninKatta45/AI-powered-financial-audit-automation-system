# main.py - COMPLETE MERGED VERSION WITH USER ACCOUNTS & SECURITY
import os
import uuid
from datetime import datetime, timedelta
import json
import asyncio
from typing import List, Dict, Any
import pandas as pd
import io
from requests.exceptions import ConnectionError as RequestsConnectionError
# --- FastAPI and Web Dependencies ---
from fastapi import FastAPI, UploadFile, File, HTTPException, Form, Depends
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from weasyprint import HTML
from jinja2 import Environment, FileSystemLoader, select_autoescape

# --- AI and Data Processing Dependencies ---
from litellm import acompletion
from tenacity import retry, stop_after_attempt, wait_random_exponential

# --- Security, Database & Email Dependencies ---
import razorpay
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from dotenv import load_dotenv
import resend

import models  # REMOVED the dot
from database import SessionLocal, engine # REMOVED the dot

# --- Initial Setup ---
load_dotenv()
models.Base.metadata.create_all(bind=engine)  # This creates the 'users' table if it doesn't exist

# ==================== CONFIGURATION ====================
# Load all necessary environment variables
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_SECRET_KEY = os.getenv("RAZORPAY_SECRET_KEY")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
RESEND_API_KEY = os.getenv("RESEND_API_KEY")
FRONTEND_URL = os.getenv("FRONTEND_URL") 
# Fail fast if critical security variables are missing
if not all([GROQ_API_KEY, RAZORPAY_KEY_ID, RAZORPAY_SECRET_KEY, JWT_SECRET_KEY, RESEND_API_KEY]):
    raise ValueError("FATAL ERROR: One or more required environment variables are not set.")

os.environ["GROQ_API_KEY"] = GROQ_API_KEY
resend.api_key = RESEND_API_KEY
JWT_ALGORITHM = "HS256"

# Initialize Razorpay client
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_SECRET_KEY))

app = FastAPI(title="Envisort - Secure Analysis Engine")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://envisort.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Jinja2 environment
env = Environment(
    loader=FileSystemLoader("templates"), 
    autoescape=select_autoescape(["html"]), 
    enable_async=True
)

# --- Pydantic Models for Request Validation ---
class PaymentVerificationData(BaseModel):
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str

class EmailSchema(BaseModel):
    email: EmailStr

class TokenData(BaseModel):
    token: str

# --- Database Dependency ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Security & Token Functions ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        
        user = db.query(models.User).filter(models.User.email == email).first()
        if user is None:
            raise credentials_exception
        
        # Robust check: does the user in the database have valid access?
        if user.access_valid_until is None or user.access_valid_until < datetime.utcnow():
             raise HTTPException(status_code=403, detail="Your access has expired. Please make a new payment.")

    except JWTError:
        raise credentials_exception
    return user

# ==================== BASIC ENDPOINTS ====================

@app.get("/ping")
async def ping():
    return {"status": "ok", "message": "Envisort is alive"}

# ==================== AUTH & PAYMENT ENDPOINTS ====================

@app.post("/create-order/", tags=["Payment"])
async def create_order(data: EmailSchema, db: Session = Depends(get_db)):
    """Creates a user if they don't exist and a Razorpay order linked to their email."""
    user = db.query(models.User).filter(models.User.email == data.email).first()
    if not user:
        print(f"New user detected: {data.email}. Creating account.")
        user = models.User(email=data.email)
        db.add(user)
        db.commit()
        db.refresh(user)

    try:
        order_data = {
            "amount": 100,
            "currency": "INR",
            "receipt": f"rcpt_{uuid.uuid4().hex}",
            "notes": {"user_email": data.email}
        }
        order = razorpay_client.order.create(data=order_data)
        return {"orderId": order["id"], "keyId": RAZORPAY_KEY_ID, "amount": order_data["amount"]}

    # CATCH THE SPECIFIC NETWORK ERROR FIRST
    except RequestsConnectionError:
        print("!!! NETWORK ERROR: Failed to connect to Razorpay.")
        raise HTTPException(
            status_code=503, # Service Unavailable
            detail="Could not connect to the payment service. Please check your internet connection and try again."
        )
    # Catch any other errors from Razorpay
    except Exception as e:
        print(f"!!! RAZORPAY API ERROR: {e}")
        raise HTTPException(status_code=500, detail=f"An error occurred with the payment provider: {e}")

@app.post("/verify-payment/", tags=["Payment"])
async def verify_payment(data: PaymentVerificationData, db: Session = Depends(get_db)):
    """Verifies payment, grants access in the DB, and issues an immediate access token."""
    try:
        razorpay_client.utility.verify_payment_signature(data.dict())
        
        order = razorpay_client.order.fetch(data.razorpay_order_id)
        user_email = order['notes'].get('user_email')
        if not user_email:
            raise HTTPException(status_code=400, detail="User email not found in order notes.")

        user = db.query(models.User).filter(models.User.email == user_email).first()
        if not user:
            raise HTTPException(status_code=404, detail=f"User with email {user_email} not found.")

        # Grant access for 24 hours
        user.access_valid_until = datetime.utcnow() + timedelta(days=1)
        user.last_payment_id = data.razorpay_payment_id
        db.commit()
        print(f"Access granted for user {user.email} until {user.access_valid_until}")

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Payment verification failed: {e}")

    # Issue an immediate access token valid for the same duration
    access_token = create_access_token(data={"sub": user.email}, expires_delta=timedelta(days=1))
    return {"status": "success", "accessToken": access_token}

@app.post("/request-magic-link/", tags=["Authentication"])
async def request_magic_link(data: EmailSchema, db: Session = Depends(get_db)):
    """If a user has valid access, sends them a single-use login link."""
    user = db.query(models.User).filter(models.User.email == data.email).first()
    if user and user.access_valid_until and user.access_valid_until > datetime.utcnow():
        # Create a short-lived token specifically for login
        login_token = create_access_token(data={"sub": user.email}, expires_delta=timedelta(minutes=15))
        magic_link = f"{FRONTEND_URL}/verify-login?token={login_token}"
        
        try:
            resend.Emails.send({
                "from": "onboarding@resend.dev",  # IMPORTANT: Use a verified sender from your Resend account
                "to": user.email,
                "subject": "Your Envisort Login Link",
                "html": f"<h3>Hello!</h3><p>Click the link below to securely log in to your Envisort account. This link will expire in 15 minutes.</p><a href='{magic_link}' style='display:inline-block;padding:12px 24px;background-color:#2563EB;color:white;text-decoration:none;border-radius:8px;'>Log In to Envisort</a>"
            })
            print(f"Magic link sent to {user.email}")
            print(f"--> Link URL: {magic_link}") 
        except Exception as e:
            print(f"ERROR: Could not send email via Resend: {e}")
            raise HTTPException(status_code=500, detail="Could not send login email. Please try again later.")

    return {"message": "If an account with valid access exists for this email, a login link has been sent."}

@app.post("/complete-login/", tags=["Authentication"])
async def complete_login(data: TokenData, db: Session = Depends(get_db)):
    """Verifies a magic link token and issues a standard access token."""
    try:
        payload = jwt.decode(data.token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid login token.")
        
        user = db.query(models.User).filter(models.User.email == email).first()
        if not (user and user.access_valid_until and user.access_valid_until > datetime.utcnow()):
            raise HTTPException(status_code=403, detail="Access denied or expired for this account.")

        # Issue a new standard access token
        access_token = create_access_token(data={"sub": user.email}, expires_delta=timedelta(days=1))
        return {"accessToken": access_token}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired login token.")

# ==================== DATA ANALYSIS FUNCTIONS ====================

FIELD_DESCRIPTION_MAP = {
    "Invoice_Date": "Date when the invoice was issued",
    "Invoice_Number": "Unique number of the invoice",
    "Vendor_Name": "Name of the vendor",
    "Vendor_GSTIN": "GSTIN of the vendor",
    "Taxable_Value": "Taxable value in the invoice",
    "Total_Invoice_Value": "Total value including tax",
    "Has_PO": "Whether a PO (purchase order) is attached",
    "Payment_Date": "Date when the payment was made",
    "Amount_Paid": "Amount paid to the vendor",
    "TDS_Section": "Section under which TDS was deducted",
    "TDS_Deducted": "Amount of TDS deducted",
}

@retry(stop=stop_after_attempt(3), wait=wait_random_exponential(min=1, max=4))
async def extract_mapping_llm(columns: list, doc_type: str) -> dict:
    prompt = f"You are a data analyst mapping messy Excel headers to standard fields for {doc_type} documents.\nStandard fields and their purposes:\n"
    relevant_fields = []
    if doc_type == "purchase":
        relevant_fields = ["Invoice_Date", "Invoice_Number", "Vendor_Name", "Vendor_GSTIN", "Taxable_Value", "Total_Invoice_Value", "Has_PO"]
    elif doc_type == "tds":
        relevant_fields = ["Payment_Date", "Vendor_Name", "Amount_Paid", "TDS_Section", "TDS_Deducted"]
    elif doc_type == "gstr2b":
        relevant_fields = ["Invoice_Number", "Vendor_GSTIN", "Total_Invoice_Value", "Vendor_Name"]
    
    for field in relevant_fields:
        prompt += f"- {field}: {FIELD_DESCRIPTION_MAP[field]}\n"
    
    prompt += f"\nActual columns needing mapping:\n" + "\n".join([f"- {col}" for col in columns])
    prompt += "\n\nReturn ONLY a JSON dictionary mapping standard fields to the most likely column name. If no good match exists for a field, omit it from the JSON."
    
    response = await acompletion(
        model="groq/llama3-70b-8192",
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"},
        max_tokens=400
    )
    try:
        return json.loads(response.choices[0].message.content)
    except (json.JSONDecodeError, IndexError):
        return {}

async def extract_semantic_fields(df: pd.DataFrame, doc_type: str) -> pd.DataFrame:
    if df.empty:
        return df
    mapping = await extract_mapping_llm(list(df.columns), doc_type)
    reverse_mapping = {v: k for k, v in mapping.items() if v in df.columns}
    return df.rename(columns=reverse_mapping)

def find_duplicate_invoices(df: pd.DataFrame) -> List[Dict[str, Any]]:
    required_cols = ['Vendor_Name', 'Invoice_Number', 'Invoice_Date', 'Total_Invoice_Value']
    if not all(col in df.columns for col in required_cols):
        return []
    
    duplicates_df = df[df.duplicated(subset=['Vendor_Name', 'Invoice_Number', 'Invoice_Date'], keep=False)]
    if duplicates_df.empty:
        return []
    
    grouped = duplicates_df.groupby(['Vendor_Name', 'Invoice_Number', 'Invoice_Date'])
    findings = []
    for _, group in grouped:
        first_invoice = group.iloc[0]
        findings.append({
            "issue_type": "DUPLICATE_INVOICE",
            "invoice_number": first_invoice['Invoice_Number'],
            "vendor": first_invoice['Vendor_Name'],
            "amount": float(first_invoice['Total_Invoice_Value']),
            "count": len(group),
            "details": f"Found {len(group)} instances."
        })
    return findings

def find_invoices_without_po(df: pd.DataFrame) -> List[Dict[str, Any]]:
    if 'Has_PO' not in df.columns:
        return []
    
    no_po_df = df[df['Has_PO'].astype(str).str.upper().isin(['NO', 'N', ''])]
    findings = []
    for _, row in no_po_df.iterrows():
        findings.append({
            "issue_type": "INVOICE_WITHOUT_PO",
            "invoice_number": row['Invoice_Number'],
            "vendor": row['Vendor_Name'],
            "amount": float(row['Total_Invoice_Value']),
            "details": "No Purchase Order linked."
        })
    return findings

def analyze_vendor_data(purchase_df: pd.DataFrame) -> List[Dict[str, Any]]:
    all_findings = []
    all_findings.extend(find_duplicate_invoices(purchase_df))
    all_findings.extend(find_invoices_without_po(purchase_df))
    return all_findings

def analyze_tds_data(tds_df: pd.DataFrame) -> List[Dict[str, Any]]:
    required_cols = ['Amount_Paid', 'TDS_Deducted', 'TDS_Section', 'Vendor_Name']
    if not all(col in tds_df.columns for col in required_cols):
        return []
    
    findings = []
    TDS_RULES = {
        "194C": {"threshold": 30000, "rate": 0.02},
        "194J": {"threshold": 30000, "rate": 0.10},
        "194I": {"threshold": 240000, "rate": 0.10}
    }
    
    df_copy = tds_df.copy()
    df_copy['Amount_Paid'] = pd.to_numeric(df_copy['Amount_Paid'], errors='coerce')
    df_copy['TDS_Deducted'] = pd.to_numeric(df_copy['TDS_Deducted'], errors='coerce').fillna(0)
    df_copy['TDS_Section'] = df_copy['TDS_Section'].astype(str).str.strip().str.upper()
    
    for _, row in df_copy.iterrows():
        section = row['TDS_Section']
        if section not in TDS_RULES:
            continue
            
        rules, amount_paid, tds_deducted = TDS_RULES[section], row['Amount_Paid'], row['TDS_Deducted']
        
        if amount_paid > rules['threshold']:
            expected_tds = amount_paid * rules['rate']
            if tds_deducted == 0:
                findings.append({
                    "issue_type": "TDS_NOT_DEDUCTED",
                    "vendor": row['Vendor_Name'],
                    "amount_paid": amount_paid,
                    "section": section,
                    "expected_tds": round(expected_tds, 2),
                    "tds_deducted": None,
                    "details": f"Expected {expected_tds:.2f}"
                })
            elif abs(tds_deducted - expected_tds) > 1:
                findings.append({
                    "issue_type": "TDS_INCORRECT_DEDUCTION",
                    "vendor": row['Vendor_Name'],
                    "amount_paid": amount_paid,
                    "section": section,
                    "expected_tds": round(expected_tds, 2),
                    "tds_deducted": tds_deducted,
                    "details": f"Shortfall of {(expected_tds - tds_deducted):.2f}"
                })
    return findings

def analyze_gst_data(purchase_df: pd.DataFrame, gstr2b_df: pd.DataFrame) -> List[Dict[str, Any]]:
    required_purchase_cols = ['Invoice_Number', 'Vendor_GSTIN', 'Vendor_Name', 'Total_Invoice_Value']
    required_gstr2b_cols = ['Invoice_Number', 'Vendor_GSTIN', 'Vendor_Name', 'Total_Invoice_Value']
    
    if not all(col in purchase_df.columns for col in required_purchase_cols) or not all(col in gstr2b_df.columns for col in required_gstr2b_cols):
        return []
    
    def standardize(df):
        df = df.copy()
        df['Invoice_Number_Std'] = df['Invoice_Number'].astype(str).str.upper().str.strip()
        df['Vendor_GSTIN_Std'] = df['Vendor_GSTIN'].astype(str).str.upper().str.strip()
        return df
    
    std_purchase, std_2b = standardize(purchase_df), standardize(gstr2b_df)
    
    unclaimed = pd.merge(std_2b, std_purchase, on=['Invoice_Number_Std', 'Vendor_GSTIN_Std'], how='left', indicator=True).query('_merge == "left_only"')
    risky = pd.merge(std_purchase, std_2b, on=['Invoice_Number_Std', 'Vendor_GSTIN_Std'], how='left', indicator=True).query('_merge == "left_only"')
    
    findings = []
    for _, row in unclaimed.iterrows():
        findings.append({
            "issue_type": "UNCLAIMED_ITC",
            "invoice_number": row['Invoice_Number_x'],
            "vendor": row['Vendor_Name_x'],
            "amount": float(row['Total_Invoice_Value_x']),
            "details": "In GSTR-2B, not purchase register."
        })
    
    for _, row in risky.iterrows():
        findings.append({
            "issue_type": "RISKY_ITC",
            "invoice_number": row['Invoice_Number_x'],
            "vendor": row['Vendor_Name_x'],
            "amount": float(row['Total_Invoice_Value_x']),
            "details": "In purchase register, not GSTR-2B."
        })
    
    return findings

def calculate_vendor_totals(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    duplicate_risk = sum(f['amount'] for f in findings if f['issue_type'] == 'DUPLICATE_INVOICE')
    no_po_risk = sum(f['amount'] for f in findings if f['issue_type'] == 'INVOICE_WITHOUT_PO')
    return {
        "total_risk": round(duplicate_risk + no_po_risk, 2),
        "duplicate_payment_risk": round(duplicate_risk, 2),
        "unauthorized_spend_risk": round(no_po_risk, 2),
        "detailed_findings": findings
    }

def calculate_tds_totals(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    total_shortfall = 0
    for f in findings:
        if f['issue_type'] == 'TDS_NOT_DEDUCTED':
            total_shortfall += f.get('expected_tds', 0)
        elif f['issue_type'] == 'TDS_INCORRECT_DEDUCTION':
            total_shortfall += f.get('expected_tds', 0) - (f.get('tds_deducted') or 0)
    
    return {
        "total_liability_risk": round(total_shortfall, 2),
        "detailed_findings": findings
    }

def calculate_gst_totals(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    unclaimed_itc = sum(f['amount'] for f in findings if f['issue_type'] == 'UNCLAIMED_ITC')
    risky_itc = sum(f['amount'] for f in findings if f['issue_type'] == 'RISKY_ITC')
    return {
        "unclaimed_itc_opportunity": round(unclaimed_itc, 2),
        "risky_itc_exposure": round(risky_itc, 2),
        "detailed_findings": findings
    }

@retry(stop=stop_after_attempt(3), wait=wait_random_exponential(min=1, max=4))
async def generate_summary(summary_data: Dict[str, Any], issue_category: str) -> str:
    if not summary_data.get("detailed_findings"):
        return f"No significant issues found."
    
    summary_json = json.dumps(summary_data)
    prompt = f"""As a senior financial auditor, your task is to write a brief, professional summary paragraph for a busy CFO based *only* on the data provided below.
    **CRITICAL INSTRUCTIONS:**
    1.  **Source of Truth:** The financial totals in the provided JSON data are the absolute source of truth. You MUST repeat these numbers exactly as they appear in your summary. For example, if the data shows `{{"risky_itc_exposure": 253700.0, ...}}`, your summary text absolutely must include the number `253,700`. Do not add, remove, or change any digits.
    2.  **Content Focus:** Your paragraph should concisely cover three things:
        *   State the primary financial impact using the pre-calculated totals.
        *   Explain the business risk or opportunity (e.g., "This exposes the company to penalties..." or "This represents a missed opportunity to improve cash flow...").
        *   Provide a high-level, actionable recommendation for the finance team.
    3.  **Format:**
        *   A single, professional paragraph.
        *   Do NOT use bullet points or markdown lists.
        *   Maintain the persona of an experienced auditor addressing a CFO.
    **Category to Summarize:** {issue_category}
    **Data (Source of Truth):**
    {summary_json[:2500]}"""
    
    try:
        response = await acompletion(
            model="groq/llama3-70b-8192",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"Could not generate AI summary: {e}"

# ==================== SECURED REPORT ENDPOINT ====================

@app.post("/generate-report-from-files/", tags=["Report Generation"])
async def generate_report_from_files(
    company_name: str = Form(...),
    purchase_file: UploadFile = File(...),
    tds_file: UploadFile = File(...),
    gstr2b_file: UploadFile = File(...),
    current_user: models.User = Depends(get_current_user)  # Now protected by the robust dependency
):
    print(f"SECURITY CHECK PASSED: Report generation authorized for user: {current_user.email}")
    print(f"[{datetime.now()}] --- NEW REPORT REQUEST ---")
    
    try:
        # --- 1. Process Files ---
        print(f"[{datetime.now()}] STEP 1: Reading uploaded files...")
        p_content, t_content, g_content = await asyncio.gather(
            purchase_file.read(), 
            tds_file.read(), 
            gstr2b_file.read()
        )
        
        # Read files into DataFrames
        p_df = pd.read_csv(io.BytesIO(p_content), dtype=str, keep_default_na=False) if purchase_file.filename.endswith('.csv') else pd.read_excel(io.BytesIO(p_content), engine='openpyxl', dtype=str, keep_default_na=False)
        t_df = pd.read_csv(io.BytesIO(t_content), dtype=str, keep_default_na=False) if tds_file.filename.endswith('.csv') else pd.read_excel(io.BytesIO(t_content), engine='openpyxl', dtype=str, keep_default_na=False)
        g_df = pd.read_csv(io.BytesIO(g_content), dtype=str, keep_default_na=False) if gstr2b_file.filename.endswith('.csv') else pd.read_excel(io.BytesIO(g_content), engine='openpyxl', dtype=str, keep_default_na=False)
        print(f"[{datetime.now()}] STEP 1 SUCCESS: Files read into DataFrames.")

        # --- 2. AI-Powered Column Mapping ---
        print(f"[{datetime.now()}] STEP 2: Starting AI column mapping (this may take a moment)...")
        mapped_purchase_df, mapped_tds_df, mapped_gstr2b_df = await asyncio.gather(
            extract_semantic_fields(p_df, "purchase"),
            extract_semantic_fields(t_df, "tds"),
            extract_semantic_fields(g_df, "gstr2b")
        )
        print(f"[{datetime.now()}] STEP 2 SUCCESS: AI mapping complete.")

        # --- 3. Core Data Analysis ---
        print(f"[{datetime.now()}] STEP 3: Starting core data analysis...")
        vendor_findings = analyze_vendor_data(mapped_purchase_df)
        tds_findings = analyze_tds_data(mapped_tds_df)
        gst_findings = analyze_gst_data(mapped_purchase_df, mapped_gstr2b_df)
        print(f"[{datetime.now()}] STEP 3 SUCCESS: Core analysis complete.")
        
        # --- 4. Calculation & AI Summarization ---
        print(f"[{datetime.now()}] STEP 4: Calculating totals...")
        vendor_summary_data = calculate_vendor_totals(vendor_findings)
        tds_summary_data = calculate_tds_totals(tds_findings)
        gst_summary_data = calculate_gst_totals(gst_findings)
        
        print(f"[{datetime.now()}] STEP 4a: Starting AI summary generation...")
        vendor_summary, tds_summary, gst_summary = await asyncio.gather(
            generate_summary(vendor_summary_data, "Vendor & Payment Risks"),
            generate_summary(tds_summary_data, "TDS Compliance Risks"),
            generate_summary(gst_summary_data, "GST Compliance & ITC Reconciliation")
        )
        print(f"[{datetime.now()}] STEP 4b SUCCESS: AI summaries generated.")
        
        # --- 5. Render PDF Report ---
        print(f"[{datetime.now()}] STEP 5: Rendering final PDF report...")
        try:
            template = env.get_template("report_template.html")
        except Exception:
            raise HTTPException(status_code=500, detail="Could not load report template. Ensure 'templates/report_template.html' exists.")
            
        html_out = await template.render_async(
            company_name=company_name,
            report_date=datetime.now().strftime("%d %B %Y"),
            audit_period="Q2 2024-25",
            vendor_summary=vendor_summary,
            gst_summary=gst_summary,
            tds_summary=tds_summary,
            vendor_findings=vendor_findings,
            gst_findings=gst_findings,
            tds_findings=tds_findings
        )
        
        pdf_bytes = HTML(string=html_out).write_pdf()
        print(f"[{datetime.now()}] STEP 5 SUCCESS: PDF rendered. Sending response.")
        
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{company_name}_Audit_Report.pdf"'}
        )

    except Exception as e:
        print(f"!!! CRITICAL ERROR DURING REPORT GENERATION: {e}")
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {str(e)}")