# main.py - AGENTIC ARCHITECTURE + Existing Features (Sign-up, Login, Payment, Report)
# -----------------------------------------------------------------------------------
# This version adds a multi-agent orchestration layer while preserving existing endpoints.
# New endpoint: POST /generate-report-agentic/  -> Uses autonomous agent team for audits.

import os
import uuid
from datetime import datetime, timedelta, timezone
import json
import asyncio
import numpy as np
from typing import List, Dict, Any, Optional, Union, Literal
import pandas as pd
from sqlalchemy import func
import io
import resend
import re

# --- Dependencies ---
from fastapi import FastAPI, UploadFile, File, HTTPException, Form, Depends
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer
from dotenv import load_dotenv
import razorpay
from weasyprint import HTML
from jinja2 import Environment, FileSystemLoader, select_autoescape
from litellm import acompletion
from tenacity import retry, stop_after_attempt, wait_random_exponential
from contextlib import asynccontextmanager

# --- Local Project Imports ---
import models
from database import SessionLocal, engine
from supabase import create_client, Client

# --- Initial Setup: Load Env & Create DB Tables ---
load_dotenv()

# ==================== CONFIGURATION ====================
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_SECRET_KEY = os.getenv("RAZORPAY_SECRET_KEY")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
FRONTEND_URL = os.getenv("FRONTEND_URL")
RESEND_API_KEY = os.getenv("RESEND_API_KEY")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

if not all([GROQ_API_KEY, RAZORPAY_KEY_ID, RAZORPAY_SECRET_KEY, JWT_SECRET_KEY, FRONTEND_URL, RESEND_API_KEY, SUPABASE_URL, SUPABASE_SERVICE_KEY]):
    raise ValueError("FATAL ERROR: One or more required environment variables are not set.")

os.environ["GROQ_API_KEY"] = GROQ_API_KEY
JWT_ALGORITHM = "HS256"

resend.api_key = RESEND_API_KEY
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_SECRET_KEY))
supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Application startup: Creating database tables if they don't exist...")
    try:
        models.Base.metadata.create_all(bind=engine)
        print("Application startup: Database tables checked/created successfully.")
    except Exception as e:
        print(f"!!! FATAL ERROR during startup: Could not connect to database. {e}")
    yield
    print("Application shutdown.")

app = FastAPI(title="Enviscale - Agentic Audit Engine", lifespan=lifespan)

# ===== Health & CORS =====
@app.get("/health", status_code=200, tags=["Health"])
async def health_check():
    return {"status": "ok", "agents_enabled": True}

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/ping")
async def ping():
    return {"status": "ok", "message": "Enviscale is alive"}

# Initialize Jinja2 environment for PDF templates
env = Environment(loader=FileSystemLoader("templates"), autoescape=select_autoescape(["html"]), enable_async=True)

# --- Pydantic Models for API Validation ---
class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class PaymentVerificationData(BaseModel):
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str

class EmailSchema(BaseModel):
    email: EmailStr

class PasswordResetRequest(BaseModel):
    token: str
    new_password: str

# --- Helper Functions ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        user = db.query(models.User).filter(models.User.email == email).first()
        if user is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: models.User = Depends(get_current_user)):
    if current_user.access_valid_until is None or current_user.access_valid_until < datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="Your access has expired. Please complete the payment to proceed.")
    return current_user

# ==================== AUTHENTICATION ENDPOINTS ====================
@app.post("/signup", tags=["Authentication"])
async def signup(user_data: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user_data.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="An account with this email already exists.")
    hashed_password = get_password_hash(user_data.password)
    new_user = models.User(email=user_data.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    access_token = create_access_token(data={"sub": new_user.email}, expires_delta=timedelta(days=1))
    return {"accessToken": access_token, "email": new_user.email}

@app.post("/login", tags=["Authentication"])
async def login(form_data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == form_data.email).first()
    if not user or not user.hashed_password or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password.")
    access_token = create_access_token(data={"sub": user.email}, expires_delta=timedelta(days=1))
    return {"accessToken": access_token}

@app.post("/request-password-reset", tags=["Authentication"])
async def request_password_reset(data: EmailSchema, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == data.email).first()
    if user:
        reset_token = create_access_token(
            data={"sub": user.email, "purpose": "password_reset"},
            expires_delta=timedelta(minutes=30)
        )
        reset_link = f"{FRONTEND_URL}/reset-password?token={reset_token}"
        try:
            resend.Emails.send({
                "from": "support@enviscale.com",
                "to": user.email,
                "subject": "Your Enviscale Password Reset Request",
                "html": f"""
                    <p>Click the link to reset your password: <a href="{reset_link}">Reset Password</a></p>
                    <p>This link is valid for 30 minutes.</p>
                """
            })
        except Exception as e:
            print(f"!!! CRITICAL ERROR: Could not send password reset email: {e}")
    return {"message": "If an account exists for this email, a password reset link has been sent."}

@app.post("/confirm-password-reset", tags=["Authentication"])
async def confirm_password_reset(data: PasswordResetRequest, db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=400, detail="Invalid or expired reset token.")
    try:
        payload = jwt.decode(data.token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        if payload.get("purpose") != "password_reset":
            raise credentials_exception
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        user = db.query(models.User).filter(models.User.email == email).first()
        if user is None:
            raise credentials_exception
        user.hashed_password = get_password_hash(data.new_password)
        db.commit()
    except JWTError:
        raise credentials_exception
    return {"message": "Password has been updated successfully. Please log in."}

@app.get("/users/me", tags=["Users"])
async def read_users_me(current_user: models.User = Depends(get_current_user)):
    has_active_access = current_user.access_valid_until and current_user.access_valid_until > datetime.now(timezone.utc)
    return {
        "email": current_user.email,
        "has_active_access": bool(has_active_access),
        "access_valid_until": current_user.access_valid_until
    }

# ==================== PAYMENT ENDPOINTS ====================
@app.post("/create-order/", tags=["Payment"])
async def create_order(current_user: models.User = Depends(get_current_user)):
    order_data = {
        "amount": 1180000,
        "currency": "INR",
        "receipt": f"rcpt_{uuid.uuid4().hex}",
        "notes": {"user_id": current_user.id}
    }
    try:
        order = razorpay_client.order.create(data=order_data)
        return {"orderId": order["id"], "keyId": RAZORPAY_KEY_ID, "amount": order_data["amount"]}
    except Exception:
        raise HTTPException(status_code=500, detail="An error occurred with the payment provider.")

@app.post("/verify-payment/", tags=["Payment"])
async def verify_payment(data: PaymentVerificationData, db: Session = Depends(get_db)):
    try:
        razorpay_client.utility.verify_payment_signature(data.dict())
        order = razorpay_client.order.fetch(data.razorpay_order_id)
        user_id = order['notes'].get('user_id')
        if not user_id:
            raise HTTPException(status_code=400, detail="User ID not found in order notes.")
        user = db.query(models.User).filter(models.User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail=f"User with ID {user_id} not found.")
        user.access_valid_until = datetime.now(timezone.utc) + timedelta(days=365)
        user.last_payment_id = data.razorpay_payment_id
        db.commit()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Payment verification failed: {e}")
    return {"status": "success", "message": "Payment successful. Access granted."}

# ==================== DATA ANALYSIS & MAPPING ====================

FIELD_DESCRIPTION_MAP = {
    "Invoice_Date": "Date of invoice", "Invoice_Number": "Unique invoice ID",
    "Vendor_Name": "Supplier name", "Vendor_GSTIN": "Supplier GSTIN",
    "Taxable_Value": "Value before tax", "Total_Invoice_Value": "Value including tax",
    "Has_PO": "Purchase Order exists (Y/N)", "Payment_Date": "Date of payment",
    "Amount_Paid": "Gross amount paid", "TDS_Section": "TDS tax section",
    "TDS_Deducted": "TDS amount deducted", "Return_Period": "GST return month/quarter",
    "ITC_Available": "Input Tax Credit available", "ITC_Claimed": "Input Tax Credit claimed",
    "Tax_Paid_Cash": "GST paid in cash", "Vendor_Code": "Internal vendor ID",
    "Vendor_PAN": "Vendor PAN ID", "Vendor_Address": "Supplier address",
    "Vendor_Bank_Account": "Supplier bank account", "Customer_Name": "Billed customer",
    "Sales_Invoice_Value": "Total sales invoice value"
}

async def read_uploaded_file(file: UploadFile) -> pd.DataFrame:
    content = await file.read()
    if file.filename.endswith('.csv'):
        df = pd.read_csv(io.BytesIO(content), keep_default_na=False)
    else:
        df = pd.read_excel(io.BytesIO(content), engine='openpyxl', keep_default_na=False)
    return df.astype(str)

def is_valid_upload_file(file) -> bool:
    return file and hasattr(file, 'filename') and file.filename

def safe_numeric_conversion(df: pd.DataFrame, columns: List[str]) -> pd.DataFrame:
    df_copy = df.copy()
    for col in columns:
        if col in df_copy.columns:
            s = df_copy[col].astype(str).str.replace(',', '').str.extract(r'(-?\d+\.?\d*)').iloc[:, 0]
            df_copy[col] = pd.to_numeric(s, errors='coerce').fillna(0)
    return df_copy

@retry(stop=stop_after_attempt(3), wait=wait_random_exponential(min=1, max=6))
async def get_unified_mapping_llm(columns: list, doc_type: str, sample_data: pd.DataFrame) -> dict:
    doc_type_fields = {
        "purchase": ["Invoice_Date", "Invoice_Number", "Vendor_Name", "Vendor_GSTIN", "Taxable_Value", "Total_Invoice_Value", "Has_PO"],
        "tds": ["Payment_Date", "Vendor_Name", "Amount_Paid", "TDS_Section", "TDS_Deducted"],
        "gstr2b": ["Invoice_Date", "Invoice_Number", "Vendor_GSTIN", "Total_Invoice_Value", "Vendor_Name"],
        "gstr3b": ["Return_Period", "ITC_Available", "ITC_Claimed", "Tax_Paid_Cash"],
        "vendor_master": ["Vendor_Code", "Vendor_Name", "Vendor_GSTIN", "Vendor_PAN", "Vendor_Address", "Vendor_Bank_Account"],
        "sales_register": ["Invoice_Date", "Invoice_Number", "Customer_Name", "Sales_Invoice_Value"]
    }
    required_fields = doc_type_fields.get(doc_type, [])
    field_descriptions = "\n".join([f"- {field}: {FIELD_DESCRIPTION_MAP[field]}" for field in required_fields])

    prompt = f"""You are an expert data analyst for Indian accounting. Your task is to map columns from an uploaded file to a standard schema and suggest formulas for missing fields.

Document Type: {doc_type}

Standard Fields Required:
{field_descriptions}

Available Columns from User's File:
{json.dumps(columns)}

Sample Data (first 2 rows):
{sample_data.head(2).to_json(orient='records')}

INSTRUCTIONS:
1. Direct Mapping: Map each standard field to the best user column.
2. Formula Generation: If a numeric field cannot be mapped, propose ADD/SUBTRACT formula from available columns.
3. Confidence: 'high' if very sure, else 'low'.

Return ONLY JSON:
{{
  "direct_mappings": {{"Standard_Field": "Actual_Column"}},
  "formulas": {{"Field_To_Calc": {{"columns_to_add": ["c1","c2"], "columns_to_subtract": ["d1"]}}}},
  "confidence": {{"Standard_Field": "high|low"}}
}}"""

    try:
        response = await acompletion(
            model="groq/llama3-70b-8192",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            max_tokens=1000
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        print(f"Unified mapping LLM call failed for doc_type '{doc_type}': {e}")
        return {}

def calculate_field_from_formula(df: pd.DataFrame, field_name: str, formula_info: dict) -> pd.DataFrame:
    try:
        add_cols = [col for col in formula_info.get("columns_to_add", []) if col in df.columns]
        sub_cols = [col for col in formula_info.get("columns_to_subtract", []) if col in df.columns]
        if not add_cols: return df
        calc_df = safe_numeric_conversion(df.copy(), add_cols + sub_cols)
        total_add = calc_df[add_cols].sum(axis=1) if add_cols else 0
        total_sub = calc_df[sub_cols].sum(axis=1) if sub_cols else 0
        df[field_name] = (total_add - total_sub).clip(lower=0)
        return df
    except Exception as e:
        print(f"Warning: Could not calculate {field_name} from formula. Error: {e}")
        return df

async def map_uploaded_file_to_df(file: Optional[UploadFile], doc_type: str) -> pd.DataFrame:
    if not is_valid_upload_file(file):
        return pd.DataFrame()
    try:
        df = await read_uploaded_file(file)
        if df.empty: return pd.DataFrame()

        llm_result = await get_unified_mapping_llm(list(df.columns), doc_type, df)
        confidence = llm_result.get("confidence", {})
        direct_mappings = llm_result.get("direct_mappings", {})
        formulas = llm_result.get("formulas", {})

        final_direct_mappings = {std_field: orig_col for std_field, orig_col in direct_mappings.items() if confidence.get(std_field) == 'high' and orig_col in df.columns}
        reverse_mapping = {v: k for k, v in final_direct_mappings.items()}
        mapped_df = df.rename(columns=reverse_mapping)

        final_formulas = {std_field: formula for std_field, formula in formulas.items() if confidence.get(std_field) == 'high'}
        for field_name, formula_info in final_formulas.items():
            if field_name not in mapped_df.columns:
                mapped_df = calculate_field_from_formula(mapped_df, field_name, formula_info)

        all_mapped_fields = list(final_direct_mappings.keys()) + list(final_formulas.keys())
        final_columns = [col for col in all_mapped_fields if col in mapped_df.columns]
        return mapped_df[final_columns]
    except Exception as e:
        print(f"ERROR: Unhandled exception during file processing for '{doc_type}'. Error: {e}")
        return pd.DataFrame()

# ==================== DATA ENRICHMENT & ANALYSIS ====================
def enrich_gstr2b_data(gstr2b_df: pd.DataFrame, purchase_df: pd.DataFrame) -> pd.DataFrame:
    if gstr2b_df.empty or purchase_df.empty:
        return gstr2b_df
    if 'Vendor_Name' in gstr2b_df.columns and not gstr2b_df['Vendor_Name'].isnull().all():
        return gstr2b_df
    if 'Vendor_GSTIN' not in gstr2b_df.columns or 'Vendor_GSTIN' not in purchase_df.columns or 'Vendor_Name' not in purchase_df.columns:
        return gstr2b_df
    gstin_to_name_map = purchase_df.drop_duplicates(subset=['Vendor_GSTIN']).set_index('Vendor_GSTIN')['Vendor_Name']
    gstr2b_df['Vendor_Name'] = gstr2b_df['Vendor_GSTIN'].map(gstin_to_name_map)
    return gstr2b_df

def analyze_tds_data(tds_df: pd.DataFrame) -> List[Dict[str, Any]]:
    required_cols = ['TDS_Deducted', 'TDS_Section', 'Vendor_Name']
    if not all(col in tds_df.columns for col in required_cols):
        return []
    findings = []
    TDS_RULES = {"194C": 0.02, "194J": 0.10, "194I": 0.10}
    df = tds_df.copy()
    df['TDS_Deducted'] = pd.to_numeric(df['TDS_Deducted'], errors='coerce').fillna(0)
    df['TDS_Section'] = df['TDS_Section'].astype(str).str.strip().str.upper()
    if 'Amount_Paid' not in df.columns:
        for _, row in df.iterrows():
            if row['TDS_Section'] not in TDS_RULES:
                findings.append({
                    "issue_type": "TDS_UNKNOWN_SECTION", "vendor": row['Vendor_Name'],
                    "section": row['TDS_Section'], "tds_deducted": row['TDS_Deducted'],
                    "details": f"TDS deducted under an unrecognized or non-standard section '{row['TDS_Section']}'."
                })
        return findings
    df['Amount_Paid'] = pd.to_numeric(df['Amount_Paid'], errors='coerce').fillna(0)
    for _, row in df.iterrows():
        section = row['TDS_Section']
        rate = TDS_RULES.get(section)
        if not rate: 
            continue
        expected_tds = row['Amount_Paid'] * rate
        if abs(row['TDS_Deducted'] - expected_tds) > 1:
            findings.append({
                "issue_type": "TDS_INCORRECT_DEDUCTION", "vendor": row['Vendor_Name'],
                "amount_paid": row['Amount_Paid'], "section": section,
                "expected_tds": round(expected_tds, 2), "tds_deducted": row['TDS_Deducted'],
                "details": f"Shortfall of {(expected_tds - row['TDS_Deducted']):.2f}"
            })
    return findings

def calculate_vendor_spend_exposure(purchase_df: pd.DataFrame, top_n: int = 10) -> Dict[str, Any]:
    if 'Total_Invoice_Value' not in purchase_df.columns or 'Vendor_Name' not in purchase_df.columns:
        return {"total_spend": 0, "top_vendors": [], "concentration_percentage": 0}
    df = purchase_df.copy()
    df['Total_Invoice_Value'] = pd.to_numeric(df['Total_Invoice_Value'], errors='coerce').fillna(0)
    total_spend = df['Total_Invoice_Value'].sum()
    if total_spend == 0:
        return {"total_spend": 0, "top_vendors": [], "concentration_percentage": 0}
    vendor_spend = df.groupby('Vendor_Name')['Total_Invoice_Value'].sum().sort_values(ascending=False)
    top_vendors = vendor_spend.head(top_n)
    top_spend = top_vendors.sum()
    return {
        "total_spend": round(total_spend, 2),
        "top_vendors": [{"vendor": name, "spend": round(spend, 2)} for name, spend in top_vendors.items()],
        "concentration_percentage": round((top_spend / total_spend) * 100, 2)
    }

def calculate_invoice_quality_score(purchase_df: pd.DataFrame) -> Dict[str, Any]:
    if purchase_df.empty:
        return {"score": 0, "grade": "N/A", "total_invoices": 0, "po_linked": 0}
    total_invoices = len(purchase_df)
    po_linked = 0
    if 'Has_PO' in purchase_df.columns:
        po_linked = purchase_df[purchase_df['Has_PO'].astype(str).str.upper().isin(['YES', 'Y'])].shape[0]
    score = round((po_linked / total_invoices) * 100) if total_invoices > 0 else 0
    grade = "N/A"
    if score >= 95: grade = "A+"
    elif score >= 85: grade = "A"
    elif score >= 70: grade = "B"
    elif score >= 50: grade = "C"
    else: grade = "F"
    return {"score": score, "grade": grade, "total_invoices": total_invoices, "po_linked": po_linked}

def analyze_monthly_spend_trends(purchase_df: pd.DataFrame) -> List[Dict[str, Any]]:
    if 'Invoice_Date' not in purchase_df.columns or 'Total_Invoice_Value' not in purchase_df.columns:
        return []
    df = purchase_df.copy()
    df['Invoice_Date'] = pd.to_datetime(df['Invoice_Date'], errors='coerce')
    df['Total_Invoice_Value'] = pd.to_numeric(df['Total_Invoice_Value'], errors='coerce').fillna(0)
    df = df.dropna(subset=['Invoice_Date'])
    if df.empty: return []
    df['Month'] = df['Invoice_Date'].dt.to_period('M')
    monthly_spend = df.groupby('Month')['Total_Invoice_Value'].sum().reset_index()
    monthly_spend['Month'] = monthly_spend['Month'].astype(str)
    return monthly_spend.to_dict('records')

def analyze_gstr_3b_vs_2b(gstr2b_df: pd.DataFrame, gstr3b_df: pd.DataFrame) -> List[Dict[str, Any]]:
    required_2b_cols = ['Total_Invoice_Value']
    required_3b_cols = ['ITC_Claimed']
    if gstr2b_df.empty or gstr3b_df.empty or \
       not all(col in gstr2b_df.columns for col in required_2b_cols) or \
       not all(col in gstr3b_df.columns for col in required_3b_cols):
        return []
    try:
        itc_available = pd.to_numeric(gstr2b_df['Total_Invoice_Value'], errors='coerce').sum()
        itc_claimed = pd.to_numeric(gstr3b_df['ITC_Claimed'], errors='coerce').sum()
        if itc_claimed > itc_available:
            return [{
                "issue_type": "EXCESS_ITC_CLAIMED", "vendor": "N/A", "invoice_number": "N/A",
                "details": f"ITC claimed in GSTR-3B (₹{itc_claimed:,.2f}) exceeds ITC available in GSTR-2B (₹{itc_available:,.2f}).",
                "amount": round(itc_claimed - itc_available, 2)
            }]
    except Exception as e:
        print(f"Error in GSTR-3B vs 2B analysis: {e}")
    return []

def find_duplicate_invoices(df: pd.DataFrame) -> List[Dict[str, Any]]:
    required_cols = ['Vendor_Name', 'Invoice_Number', 'Invoice_Date', 'Total_Invoice_Value']
    if not all(col in df.columns for col in required_cols):
        return []
    duplicates_df = df[df.duplicated(subset=['Vendor_Name', 'Invoice_Number', 'Invoice_Date'], keep=False)]
    if duplicates_df.empty:
        return []
    findings = []
    for _, group in duplicates_df.groupby(['Vendor_Name', 'Invoice_Number', 'Invoice_Date']):
        first = group.iloc[0]
        findings.append({
            "issue_type": "DUPLICATE_INVOICE", "invoice_number": first['Invoice_Number'],
            "vendor": first['Vendor_Name'], "amount": float(first['Total_Invoice_Value']),
            "count": len(group), "details": f"Found {len(group)} instances."
        })
    return findings

def find_invoices_without_po(df: pd.DataFrame) -> List[Dict[str, Any]]:
    if 'Has_PO' not in df.columns: return []
    no_po_df = df[df['Has_PO'].astype(str).str.upper().isin(['NO', 'N', ''])]
    return [{
        "issue_type": "INVOICE_WITHOUT_PO", "invoice_number": row['Invoice_Number'],
        "vendor": row['Vendor_Name'], "amount": float(row['Total_Invoice_Value']),
        "details": "No Purchase Order linked."
    } for _, row in no_po_df.iterrows()]

def analyze_vendor_data(purchase_df: pd.DataFrame) -> List[Dict[str, Any]]:
    return find_duplicate_invoices(purchase_df) + find_invoices_without_po(purchase_df)

def analyze_gst_data(purchase_df: pd.DataFrame, gstr2b_df: pd.DataFrame) -> List[Dict[str, Any]]:
    req_p = ['Invoice_Number', 'Vendor_GSTIN', 'Total_Invoice_Value', 'Vendor_Name']
    req_2b = ['Invoice_Number', 'Vendor_GSTIN', 'Total_Invoice_Value', 'Vendor_Name']
    if not all(c in purchase_df.columns for c in req_p) or not all(c in gstr2b_df.columns for c in req_2b):
        return []
    def standardize(df):
        df_c = df.copy()
        for col in ['Invoice_Number', 'Vendor_GSTIN']:
            df_c[f"{col}_Std"] = df_c[col].astype(str).str.upper().str.strip()
        return df_c
    std_p, std_2b = standardize(purchase_df), standardize(gstr2b_df)
    merge_cols = ['Invoice_Number_Std', 'Vendor_GSTIN_Std']
    merged = pd.merge(std_p, std_2b, on=merge_cols, how='outer', indicator=True, suffixes=('_p', '_2b'))
    risky = merged[merged['_merge'] == 'left_only']
    unclaimed = merged[merged['_merge'] == 'right_only']
    findings = []
    for _, row in risky.iterrows():
        findings.append({"issue_type": "RISKY_ITC", "invoice_number": row['Invoice_Number_p'], "vendor": row['Vendor_Name_p'], "amount": float(row['Total_Invoice_Value_p']), "details": "In purchase register, not GSTR-2B."})
    for _, row in unclaimed.iterrows():
        findings.append({"issue_type": "UNCLAIMED_ITC", "invoice_number": row['Invoice_Number_2b'], "vendor": row['Vendor_Name_2b'], "amount": float(row['Total_Invoice_Value_2b']), "details": "In GSTR-2B, not purchase register."})
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
    total_shortfall = sum(f.get('expected_tds', 0) - (f.get('tds_deducted') or 0) for f in findings if f['issue_type'] == 'TDS_INCORRECT_DEDUCTION')
    return {"total_liability_risk": round(total_shortfall, 2), "detailed_findings": findings}

def calculate_gst_totals(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    unclaimed_itc = sum(f['amount'] for f in findings if f['issue_type'] == 'UNCLAIMED_ITC')
    risky_itc = sum(f['amount'] for f in findings if f['issue_type'] == 'RISKY_ITC')
    return {
        "unclaimed_itc_opportunity": round(unclaimed_itc, 2),
        "risky_itc_exposure": round(risky_itc, 2),
        "detailed_findings": findings
    }

async def get_admin_user(current_user: models.User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="You do not have permission to access this resource.")
    return current_user

@app.get("/admin/metrics", tags=["Admin"], dependencies=[Depends(get_admin_user)])
async def get_admin_metrics(db: Session = Depends(get_db)):
    total_users = db.query(models.User).count()
    total_audits = db.query(models.Audit).count()
    total_findings = db.query(models.AuditFinding).count()
    active_subscriptions = db.query(models.User).filter(models.User.access_valid_until > datetime.now(timezone.utc)).count()
    return {"total_users": total_users, "total_audits_run": total_audits, "total_findings_identified": total_findings, "active_subscriptions": active_subscriptions}

def analyze_payment_patterns(purchase_df: pd.DataFrame, tds_df: pd.DataFrame) -> Dict[str, Any]:
    default_patterns = {"avg_payment_days": "N/A", "weekend_payments": 0, "late_payments": 0, "bulk_payment_days": 0}
    req_p = ['Invoice_Date', 'Vendor_Name']
    req_t = ['Payment_Date', 'Vendor_Name']
    if purchase_df.empty or tds_df.empty or not all(c in purchase_df.columns for c in req_p) or not all(c in tds_df.columns for c in req_t):
        return default_patterns
    p_df = purchase_df.copy(); t_df = tds_df.copy()
    p_df['Invoice_Date'] = pd.to_datetime(p_df['Invoice_Date'], errors='coerce')
    t_df['Payment_Date'] = pd.to_datetime(t_df['Payment_Date'], errors='coerce')
    p_df.dropna(subset=['Invoice_Date'], inplace=True); t_df.dropna(subset=['Payment_Date'], inplace=True)
    if p_df.empty or t_df.empty: return default_patterns
    merged_df = pd.merge(t_df, p_df, on='Vendor_Name', how='left').dropna(subset=['Invoice_Date'])
    if merged_df.empty: return default_patterns
    merged_df['payment_days'] = (merged_df['Payment_Date'] - merged_df['Invoice_Date']).dt.days
    valid_payments = merged_df[merged_df['payment_days'] >= 0]
    avg_days = int(valid_payments['payment_days'].mean()) if not valid_payments.empty else "N/A"
    weekend_payments = merged_df[merged_df['Payment_Date'].dt.dayofweek.isin([5, 6])].shape[0]
    late_payments = valid_payments[valid_payments['payment_days'] > 30].shape[0]
    bulk_days = t_df.groupby(t_df['Payment_Date'].dt.date).size().pipe(lambda s: s[s >= 10].count())
    return {"avg_payment_days": avg_days, "weekend_payments": weekend_payments, "late_payments": late_payments, "bulk_payment_days": int(bulk_days)}

@retry(stop=stop_after_attempt(3), wait=wait_random_exponential(min=1, max=4))
async def generate_summary(summary_data: Dict[str, Any], issue_category: str) -> str:
    if not summary_data.get("detailed_findings"): 
        return f"No significant issues found for {issue_category}."
    summary_json = json.dumps(summary_data)
    prompt = f"""As a senior financial auditor, write a brief, professional summary paragraph for a CFO based ONLY on the data below.
    CRITICAL: You MUST use the exact financial totals provided in the JSON. For example, if data is `{{"risky_itc_exposure": 253700.0, ...}}`, you MUST include the number `253,700` in your summary.
    Your paragraph should state the financial impact, explain the business risk/opportunity, and give a high-level recommendation.
    Category: {issue_category}
    Data:
    {summary_json[:2000]}"""
    response = await acompletion(
        model="groq/llama3-70b-8192", messages=[{"role": "user", "content": prompt}], max_tokens=250
    )
    return response.choices[0].message.content.strip()

def serialize_analysis(analysis_data: Any) -> Any:
    if isinstance(analysis_data, (np.integer, np.floating)):
        return int(analysis_data) if isinstance(analysis_data, np.integer) else float(analysis_data)
    elif isinstance(analysis_data, dict):
        return {k: serialize_analysis(v) for k, v in analysis_data.items()}
    elif isinstance(analysis_data, (list, tuple)):
        return [serialize_analysis(x) for x in analysis_data]
    return analysis_data

async def generate_strategic_recommendations(full_analysis: dict) -> str:
    prompt = f"""As a senior financial consultant, generate specific strategic recommendations in HTML format based on these audit results. Do not use the word 'HTML'.
    Audit Findings: {json.dumps(full_analysis, indent=2)}
    Requirements: 1. Organize into 3 categories: Process, Vendor, Compliance. 2. Provide 1-2 specific recommendations per category. 3. Format as divs with class 'summary-block'.
    """
    try:
        response = await acompletion(
            model="groq/llama3-70b-8192", messages=[{"role": "user", "content": prompt}], temperature=0.7
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"Failed to generate recommendations: {e}")
        return "<p>Could not generate strategic recommendations.</p>"

# ==================== SECURED REPORT ENDPOINT (LEGACY FLOW) ====================
@app.post("/generate-report/", tags=["Report Generation"])
async def generate_report_from_files(
    company_name: str = Form(...),
    purchase_file: UploadFile = File(...),
    tds_file: UploadFile = File(...),
    gstr2b_file: UploadFile = File(...),
    gstr3b_file: Optional[UploadFile] = File(None),
    vendor_master_file: Optional[UploadFile] = File(None),
    sales_register_file: Optional[UploadFile] = File(None),
    current_user: models.User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    print(f"[{datetime.now()}] --- REPORT REQUEST (LEGACY) for {company_name} ---")
    files_to_process = [
        (purchase_file, "purchase"), (tds_file, "tds"), (gstr2b_file, "gstr2b"),
        (gstr3b_file, "gstr3b"), (vendor_master_file, "vendor_master"), (sales_register_file, "sales_register")
    ]
    mapped_dfs = {doc_type: await map_uploaded_file_to_df(file, doc_type) for file, doc_type in files_to_process}
    mapped_dfs["gstr2b"] = enrich_gstr2b_data(mapped_dfs["gstr2b"], mapped_dfs["purchase"])

    mapped_p_df = mapped_dfs["purchase"]
    mapped_t_df = mapped_dfs["tds"]
    mapped_g2b_df = mapped_dfs["gstr2b"]
    mapped_g3b_df = mapped_dfs["gstr3b"]

    vendor_findings = analyze_vendor_data(mapped_p_df)
    tds_findings = analyze_tds_data(mapped_t_df)
    gst_findings = analyze_gst_data(mapped_p_df, mapped_g2b_df)
    gstr_3b_findings = analyze_gstr_3b_vs_2b(mapped_g2b_df, mapped_g3b_df)
    all_findings = vendor_findings + tds_findings + gst_findings + gstr_3b_findings

    vendor_exposure = calculate_vendor_spend_exposure(mapped_p_df)
    iqs_score = calculate_invoice_quality_score(mapped_p_df)
    spend_trends = analyze_monthly_spend_trends(mapped_p_df)
    payment_patterns = analyze_payment_patterns(mapped_p_df, mapped_t_df)

    # Memory Engine
    existing_audits = db.query(models.Audit.id).filter(models.Audit.user_id == current_user.id, models.Audit.company_name == company_name).all()
    for finding in all_findings:
        fingerprint_parts = [company_name, finding['issue_type'], str(finding.get('vendor', '')), str(finding.get('invoice_number', '')), str(finding.get('amount', ''))]
        finding['fingerprint'] = "-".join(filter(None, fingerprint_parts))
    historical_counts = {}
    if existing_audits:
        audit_ids = [a.id for a in existing_audits]
        historical_results = db.query(models.AuditFinding.fingerprint, func.count(models.AuditFinding.id)).filter(models.AuditFinding.audit_id.in_(audit_ids)).group_by(models.AuditFinding.fingerprint).all()
        historical_counts = dict(historical_results)
    for finding in all_findings:
        count = historical_counts.get(finding['fingerprint'], 0)
        finding['past_occurrences'] = count
        finding['is_repeat'] = count > 0

    new_audit = models.Audit(user_id=current_user.id, company_name=company_name)
    db.add(new_audit)
    db.flush()
    for finding in all_findings:
        db.add(models.AuditFinding(
            audit_id=new_audit.id,
            issue_type=finding['issue_type'],
            details=json.dumps({k: v for k, v in finding.items() if k not in ['is_repeat', 'past_occurrences', 'fingerprint']}),
            fingerprint=finding['fingerprint'],
            is_repeat=finding['is_repeat']
        ))
    db.commit()

    vendor_summary, tds_summary, gst_summary = await asyncio.gather(
        generate_summary(calculate_vendor_totals(vendor_findings), "Vendor & Payment Risks"),
        generate_summary(calculate_tds_totals(tds_findings), "TDS Compliance Risks"),
        generate_summary(calculate_gst_totals(gst_findings + gstr_3b_findings), "GST Compliance")
    )

    full_analysis = serialize_analysis({
        "company_name": company_name,
        "vendor_exposure": vendor_exposure,
        "iqs_score": iqs_score,
        "payment_patterns": payment_patterns,
        "key_findings": {"vendor": vendor_summary, "tds": tds_summary, "gst": gst_summary}
    })
    strategic_recommendations = await generate_strategic_recommendations(full_analysis)

    risk_exposure_values = {
        'critical': sum(f.get('amount', 0) for f in vendor_findings if f['issue_type'] == 'DUPLICATE_INVOICE'),
        'high': sum(f.get('amount', 0) for f in vendor_findings if f['issue_type'] == 'INVOICE_WITHOUT_PO'),
        'medium': sum(f.get('amount', 0) for f in gst_findings if f['issue_type'] == 'RISKY_ITC'),
        'opportunity': sum(f.get('amount', 0) for f in gst_findings if f['issue_type'] == 'UNCLAIMED_ITC')
    }
    total_risk_exposure = sum(risk_exposure_values.values()) - risk_exposure_values['opportunity'] + calculate_tds_totals(tds_findings)['total_liability_risk']

    template = env.get_template("report_template.html")
    render_context = {**full_analysis, "audit_period": "Q2 2024-25", "report_date": datetime.now().strftime("%d %B %Y"),
                      "vendor_findings": vendor_findings, "gst_findings": gst_findings, "tds_findings": tds_findings,
                      "gstr_3b_findings": gstr_3b_findings, "spend_trends": spend_trends,
                      "strategic_recommendations": strategic_recommendations, "risk_exposure": risk_exposure_values,
                      "total_risk_exposure": total_risk_exposure, "now": datetime.now()}

    html_out = await template.render_async(render_context)
    pdf_bytes = HTML(string=html_out).write_pdf()

    report_filename = f"{company_name.replace(' ', '_')}_{new_audit.id}.pdf"
    storage_path = f"user_{current_user.id}/{new_audit.id}/{report_filename}"
    try:
        supabase.storage.from_("audit-artifacts").upload(file=pdf_bytes, path=storage_path)
        new_audit.report_url = supabase.storage.from_("audit-artifacts").get_public_url(storage_path)
        db.commit()
    except Exception as e:
        print(f"Supabase upload failed: {e}")

    return StreamingResponse(io.BytesIO(pdf_bytes), media_type="application/pdf",
                             headers={"Content-Disposition": f'attachment; filename="{report_filename}"'})

# ==================== AGENTIC LAYER ====================

# ---- Agent message & context models ----
class AgentMessage(BaseModel):
    agent: str
    role: Literal["system", "planner", "worker", "critic", "orchestrator", "tool"]
    content: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AgentContext(BaseModel):
    company_name: str
    assumptions: List[str] = []
    objectives: List[str] = []
    artifacts: Dict[str, Any] = {}  # dataframes or JSON serializable results
    findings: List[Dict[str, Any]] = []
    logs: List[AgentMessage] = []

    def log(self, agent: str, role: str, content: str):
        self.logs.append(AgentMessage(agent=agent, role=role, content=content))

# ---- Base agent ----
class BaseAgent:
    name: str = "BaseAgent"
    description: str = "Base agent"

    async def run(self, ctx: AgentContext) -> None:
        raise NotImplementedError

# ---- Ingestion Agent ----
class IngestionAgent(BaseAgent):
    name = "IngestionAgent"
    description = "Validates and loads raw files into dataframes."

    def __init__(self, files: Dict[str, Optional[UploadFile]]):
        self.files = files

    async def run(self, ctx: AgentContext) -> None:
        ctx.log(self.name, "worker", "Starting ingestion for purchase, tds, gstr2b, gstr3b, vendor_master, sales_register.")
        loaded: Dict[str, pd.DataFrame] = {}
        for key, f in self.files.items():
            if f and is_valid_upload_file(f):
                try:
                    loaded[key] = await read_uploaded_file(f)
                    ctx.log(self.name, "tool", f"Loaded '{key}' shape={loaded[key].shape}.")
                except Exception as e:
                    ctx.log(self.name, "tool", f"Failed to read '{key}': {e}")
                    loaded[key] = pd.DataFrame()
            else:
                loaded[key] = pd.DataFrame()
        ctx.artifacts["raw"] = loaded
        ctx.log(self.name, "worker", "Ingestion complete.")

# ---- Schema Mapping Agent ----
class SchemaMappingAgent(BaseAgent):
    name = "SchemaMappingAgent"
    description = "Maps uploaded files to the unified schema using LLM and formulas."

    async def run(self, ctx: AgentContext) -> None:
        raw: Dict[str, pd.DataFrame] = ctx.artifacts.get("raw", {})
        ctx.log(self.name, "worker", "Beginning schema mapping for all documents.")
        mapped: Dict[str, pd.DataFrame] = {}
        # Simulate original map function but now over preloaded dataframes
        async def _map_df(df: pd.DataFrame, doc_type: str) -> pd.DataFrame:
            if df is None or df.empty:
                return pd.DataFrame()
            llm_result = await get_unified_mapping_llm(list(df.columns), doc_type, df)
            confidence = llm_result.get("confidence", {})
            direct_mappings = llm_result.get("direct_mappings", {})
            formulas = llm_result.get("formulas", {})
            final_direct = {s: c for s, c in direct_mappings.items() if confidence.get(s) == 'high' and c in df.columns}
            mapped_df = df.rename(columns={v: k for k, v in final_direct.items()})
            for field_name, formula_info in (formulas or {}).items():
                if confidence.get(field_name) == 'high' and field_name not in mapped_df.columns:
                    mapped_df = calculate_field_from_formula(mapped_df, field_name, formula_info)
            keep_cols = list(final_direct.keys()) + [k for k in (formulas or {}).keys() if confidence.get(k) == 'high']
            keep_cols = [c for c in keep_cols if c in mapped_df.columns]
            return mapped_df[keep_cols] if keep_cols else pd.DataFrame()

        mapped["purchase"] = await _map_df(raw.get("purchase"), "purchase")
        mapped["tds"] = await _map_df(raw.get("tds"), "tds")
        mapped["gstr2b"] = await _map_df(raw.get("gstr2b"), "gstr2b")
        mapped["gstr3b"] = await _map_df(raw.get("gstr3b"), "gstr3b")
        mapped["vendor_master"] = await _map_df(raw.get("vendor_master"), "vendor_master")
        mapped["sales_register"] = await _map_df(raw.get("sales_register"), "sales_register")

        # Enrichment step
        mapped["gstr2b"] = enrich_gstr2b_data(mapped.get("gstr2b", pd.DataFrame()), mapped.get("purchase", pd.DataFrame()))
        for k, v in mapped.items():
            ctx.log(self.name, "tool", f"Mapped '{k}' -> columns={list(v.columns)} rows={len(v)}")
        ctx.artifacts["mapped"] = mapped
        ctx.log(self.name, "worker", "Schema mapping complete.")

# ---- Reconciliation Agent ----
class ReconciliationAgent(BaseAgent):
    name = "ReconciliationAgent"
    description = "Reconciles purchase register with GSTR-2B/3B and flags GST issues."

    async def run(self, ctx: AgentContext) -> None:
        mapped: Dict[str, pd.DataFrame] = ctx.artifacts.get("mapped", {})
        purchase = mapped.get("purchase", pd.DataFrame())
        g2b = mapped.get("gstr2b", pd.DataFrame())
        g3b = mapped.get("gstr3b", pd.DataFrame())

        gst_findings = analyze_gst_data(purchase, g2b)
        gstr_3b_findings = analyze_gstr_3b_vs_2b(g2b, g3b)
        ctx.artifacts["gst_findings"] = gst_findings
        ctx.artifacts["gstr_3b_findings"] = gstr_3b_findings
        ctx.findings.extend(gst_findings + gstr_3b_findings)
        ctx.log(self.name, "worker", f"GST reconciliation produced {len(gst_findings)} 2B findings and {len(gstr_3b_findings)} 3B findings.")

# ---- TDS Agent ----
class TDSAgent(BaseAgent):
    name = "TDSAgent"
    description = "Analyzes TDS deductions vs sections and expectations."

    async def run(self, ctx: AgentContext) -> None:
        mapped: Dict[str, pd.DataFrame] = ctx.artifacts.get("mapped", {})
        tds_df = mapped.get("tds", pd.DataFrame())
        tds_findings = analyze_tds_data(tds_df)
        ctx.artifacts["tds_findings"] = tds_findings
        ctx.findings.extend(tds_findings)
        ctx.log(self.name, "worker", f"TDS analysis produced {len(tds_findings)} findings.")

# ---- Vendor Risk Agent ----
class VendorRiskAgent(BaseAgent):
    name = "VendorRiskAgent"
    description = "Finds duplicate invoices, missing POs, spend exposure, quality score, trends."

    async def run(self, ctx: AgentContext) -> None:
        mapped: Dict[str, pd.DataFrame] = ctx.artifacts.get("mapped", {})
        purchase = mapped.get("purchase", pd.DataFrame())
        tds_df = mapped.get("tds", pd.DataFrame())

        vendor_findings = analyze_vendor_data(purchase)
        exposure = calculate_vendor_spend_exposure(purchase)
        iqs = calculate_invoice_quality_score(purchase)
        trends = analyze_monthly_spend_trends(purchase)
        pay_patterns = analyze_payment_patterns(purchase, tds_df)

        ctx.artifacts["vendor_findings"] = vendor_findings
        ctx.artifacts["vendor_exposure"] = exposure
        ctx.artifacts["iqs_score"] = iqs
        ctx.artifacts["spend_trends"] = trends
        ctx.artifacts["payment_patterns"] = pay_patterns
        ctx.findings.extend(vendor_findings)

        ctx.log(self.name, "worker", f"Vendor analysis: {len(vendor_findings)} findings, total spend={exposure.get('total_spend',0)}.")

# ---- Summary Agent ----
class SummaryAgent(BaseAgent):
    name = "SummaryAgent"
    description = "Synthesizes findings into CFO-ready summaries and recommendations."

    async def run(self, ctx: AgentContext) -> None:
        vendor_findings = ctx.artifacts.get("vendor_findings", [])
        tds_findings = ctx.artifacts.get("tds_findings", [])
        gst_findings = ctx.artifacts.get("gst_findings", [])
        gstr3b = ctx.artifacts.get("gstr_3b_findings", [])

        vendor_summary, tds_summary, gst_summary = await asyncio.gather(
            generate_summary(calculate_vendor_totals(vendor_findings), "Vendor & Payment Risks"),
            generate_summary(calculate_tds_totals(tds_findings), "TDS Compliance Risks"),
            generate_summary(calculate_gst_totals(gst_findings + gstr3b), "GST Compliance"),
        )

        key_findings = {"vendor": vendor_summary, "tds": tds_summary, "gst": gst_summary}
        ctx.artifacts["key_findings"] = key_findings

        full_analysis = serialize_analysis({
            "company_name": ctx.company_name,
            "vendor_exposure": ctx.artifacts.get("vendor_exposure"),
            "iqs_score": ctx.artifacts.get("iqs_score"),
            "payment_patterns": ctx.artifacts.get("payment_patterns"),
            "key_findings": key_findings
        })
        recommendations = await generate_strategic_recommendations(full_analysis)
        ctx.artifacts["strategic_recommendations"] = recommendations

        # quick risk aggregation
        risk_exposure_values = {
            'critical': sum(f.get('amount', 0) for f in vendor_findings if f['issue_type'] == 'DUPLICATE_INVOICE'),
            'high': sum(f.get('amount', 0) for f in vendor_findings if f['issue_type'] == 'INVOICE_WITHOUT_PO'),
            'medium': sum(f.get('amount', 0) for f in gst_findings if f['issue_type'] == 'RISKY_ITC'),
            'opportunity': sum(f.get('amount', 0) for f in gst_findings if f['issue_type'] == 'UNCLAIMED_ITC')
        }
        total_risk_exposure = sum(risk_exposure_values.values()) - risk_exposure_values['opportunity'] + calculate_tds_totals(tds_findings)['total_liability_risk']
        ctx.artifacts["risk_exposure"] = risk_exposure_values
        ctx.artifacts["total_risk_exposure"] = total_risk_exposure

        ctx.log(self.name, "worker", "Summaries and recommendations generated.")

# ---- Orchestrator ----
class AgentOrchestrator:
    def __init__(self, agents: List[BaseAgent]):
        self.agents = agents

    async def run(self, ctx: AgentContext):
        ctx.log("Orchestrator", "planner", "Kickoff: objectives set and team initialized.")
        for agent in self.agents:
            ctx.log("Orchestrator", "planner", f"Dispatching {agent.name}.")
            await agent.run(ctx)
            ctx.log("Orchestrator", "critic", f"{agent.name} completed.")
        ctx.log("Orchestrator", "orchestrator", "All agents finished.")

# ==================== AGENTIC REPORT ENDPOINT ====================
@app.post("/generate-report-agentic/", tags=["Report Generation"])
async def generate_report_agentic(
    company_name: str = Form(...),
    purchase_file: UploadFile = File(...),
    tds_file: UploadFile = File(...),
    gstr2b_file: UploadFile = File(...),
    gstr3b_file: Optional[UploadFile] = File(None),
    vendor_master_file: Optional[UploadFile] = File(None),
    sales_register_file: Optional[UploadFile] = File(None),
    current_user: models.User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    print(f"[{datetime.now()}] --- REPORT REQUEST (AGENTIC) for {company_name} ---")

    # 1) Build context & agent team
    ctx = AgentContext(
        company_name=company_name,
        assumptions=["Uploaded files are company-level registers for the same audit period."],
        objectives=[
            "Map raw files to unified schema",
            "Enrich vendor info across datasets",
            "Reconcile purchase vs GSTR-2B/3B",
            "Analyze TDS correctness",
            "Assess vendor/payment risks",
            "Summarize and recommend"
        ]
    )
    files = {
        "purchase": purchase_file, "tds": tds_file, "gstr2b": gstr2b_file, "gstr3b": gstr3b_file,
        "vendor_master": vendor_master_file, "sales_register": sales_register_file
    }
    team = [
        IngestionAgent(files),
        SchemaMappingAgent(),
        ReconciliationAgent(),
        TDSAgent(),
        VendorRiskAgent(),
        SummaryAgent(),
    ]
    orchestrator = AgentOrchestrator(team)

    # 2) Run the agents sequentially (autonomous pipeline)
    await orchestrator.run(ctx)

    # 3) Persist findings (Memory Engine parity)
    all_findings = ctx.findings
    existing_audits = db.query(models.Audit.id).filter(models.Audit.user_id == current_user.id, models.Audit.company_name == company_name).all()
    for finding in all_findings:
        fingerprint_parts = [company_name, finding.get('issue_type', ''), str(finding.get('vendor', '')), str(finding.get('invoice_number', '')), str(finding.get('amount', ''))]
        finding['fingerprint'] = "-".join(filter(None, fingerprint_parts))
    historical_counts = {}
    if existing_audits:
        audit_ids = [a.id for a in existing_audits]
        historical_results = db.query(models.AuditFinding.fingerprint, func.count(models.AuditFinding.id)).filter(models.AuditFinding.audit_id.in_(audit_ids)).group_by(models.AuditFinding.fingerprint).all()
        historical_counts = dict(historical_results)
    for finding in all_findings:
        count = historical_counts.get(finding['fingerprint'], 0)
        finding['past_occurrences'] = count
        finding['is_repeat'] = count > 0

    new_audit = models.Audit(user_id=current_user.id, company_name=company_name)
    # Store a compact agent log preview (cap to 30 entries to keep DB small)
    compact_log = [{"t": m.timestamp.isoformat(), "agent": m.agent, "role": m.role, "content": (m.content[:300] + ("..." if len(m.content) > 300 else ""))} for m in ctx.logs[-30:]]
    new_audit.agent_log = json.dumps(compact_log)
    db.add(new_audit)
    db.flush()

    for finding in all_findings:
        db.add(models.AuditFinding(
            audit_id=new_audit.id,
            issue_type=finding.get('issue_type', 'UNKNOWN'),
            details=json.dumps({k: v for k, v in finding.items() if k not in ['is_repeat', 'past_occurrences', 'fingerprint']}),
            fingerprint=finding.get('fingerprint', ''),
            is_repeat=bool(finding.get('is_repeat', False))
        ))
    db.commit()

    # 4) Render report using agent artifacts
    vendor_findings = ctx.artifacts.get("vendor_findings", [])
    gst_findings = ctx.artifacts.get("gst_findings", [])
    tds_findings = ctx.artifacts.get("tds_findings", [])
    gstr_3b_findings = ctx.artifacts.get("gstr_3b_findings", [])
    vendor_exposure = ctx.artifacts.get("vendor_exposure")
    iqs_score = ctx.artifacts.get("iqs_score")
    spend_trends = ctx.artifacts.get("spend_trends", [])
    payment_patterns = ctx.artifacts.get("payment_patterns", {})
    key_findings = ctx.artifacts.get("key_findings", {})
    recommendations = ctx.artifacts.get("strategic_recommendations", "")
    risk_exposure_values = ctx.artifacts.get("risk_exposure", {})
    total_risk_exposure = ctx.artifacts.get("total_risk_exposure", 0)

    full_analysis = serialize_analysis({
        "company_name": company_name,
        "vendor_exposure": vendor_exposure,
        "iqs_score": iqs_score,
        "payment_patterns": payment_patterns,
        "key_findings": key_findings
    })

    template = env.get_template("report_template.html")
    render_context = {
        **full_analysis,
        "audit_period": "Q2 2024-25",
        "report_date": datetime.now().strftime("%d %B %Y"),
        "vendor_findings": vendor_findings,
        "gst_findings": gst_findings,
        "tds_findings": tds_findings,
        "gstr_3b_findings": gstr_3b_findings,
        "spend_trends": spend_trends,
        "strategic_recommendations": recommendations,
        "risk_exposure": risk_exposure_values,
        "total_risk_exposure": total_risk_exposure,
        "now": datetime.now(),
        "agents_enabled": True
    }

    html_out = await template.render_async(render_context)
    pdf_bytes = HTML(string=html_out).write_pdf()

    report_filename = f"{company_name.replace(' ', '_')}_{new_audit.id}_AGENTIC.pdf"
    storage_path = f"user_{current_user.id}/{new_audit.id}/{report_filename}"
    try:
        # Supabase Python client often accepts bytes; previous code used same pattern so keep it consistent
        supabase.storage.from_("audit-artifacts").upload(file=pdf_bytes, path=storage_path)
        # get_public_url returns a dict or string depending on client version; using same pattern as legacy flow
        new_audit.report_url = supabase.storage.from_("audit-artifacts").get_public_url(storage_path)
        db.commit()
    except Exception as e:
        # don't fail the entire request if storage fails; log and continue
        print(f"Supabase upload failed (agentic): {e}")

    # Return the PDF to the caller (same StreamingResponse pattern as legacy)
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{report_filename}"'}
    )

# ==================== DASHBOARD API ENDPOINTS ====================

class AuditHistoryItem(BaseModel):
    id: int
    company_name: str
    timestamp: datetime
    report_url: Optional[str]

class FindingDetailItem(BaseModel):
    id: int
    audit_id: int
    issue_type: str
    details: Dict[str, Any]
    fingerprint: str
    is_repeat: bool
    timestamp: datetime

@app.get("/audits/", response_model=List[AuditHistoryItem], tags=["Dashboard"])
async def get_audit_history(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return (
        db.query(models.Audit)
        .filter(models.Audit.user_id == current_user.id)
        .order_by(models.Audit.timestamp.desc())
        .all()
    )

@app.get("/audits/{audit_id}/findings/", response_model=List[FindingDetailItem], tags=["Dashboard"])
async def get_audit_findings(
    audit_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    audit = (
        db.query(models.Audit)
        .filter(models.Audit.id == audit_id, models.Audit.user_id == current_user.id)
        .first()
    )
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found or you don't have permission.")
    
    findings = (
        db.query(models.AuditFinding)
        .filter(models.AuditFinding.audit_id == audit_id)
        .order_by(models.AuditFinding.timestamp.desc())
        .all()
    )

    results = []
    for f in findings:
        try:
            details = json.loads(f.details)
        except json.JSONDecodeError:
            details = {"error": "Could not parse details JSON."}
        results.append(
            FindingDetailItem(
                id=f.id,
                audit_id=f.audit_id,
                issue_type=f.issue_type,
                details=details,
                fingerprint=f.fingerprint,
                is_repeat=f.is_repeat,
                timestamp=f.timestamp
            )
        )
    return results


@app.get("/audits/{audit_id}/export-excel/", tags=["Dashboard"])
async def export_findings_to_excel(
    audit_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    audit = (
        db.query(models.Audit)
        .filter(models.Audit.id == audit_id, models.Audit.user_id == current_user.id)
        .first()
    )
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found or you don't have permission.")
    
    findings_query = db.query(models.AuditFinding).filter(models.AuditFinding.audit_id == audit_id).all()
    if not findings_query:
        raise HTTPException(status_code=404, detail="No findings found for this audit.")

    data_to_export = []
    for f in findings_query:
        try:
            details = json.loads(f.details)
        except json.JSONDecodeError:
            details = {"error": "Could not parse details JSON."}
        data_to_export.append({
            "finding_id": f.id,
            "issue_type": f.issue_type,
            "is_repeat_issue": f.is_repeat,
            "timestamp": f.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            **details
        })
    
    df = pd.DataFrame(data_to_export)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="Audit_Findings")
    output.seek(0)
    
    return StreamingResponse(
        output,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f"attachment; filename=Enviscale_Audit_{audit_id}_Findings.xlsx"
        }
    )
