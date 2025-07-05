# main.py - FINAL ARCHITECTURE with Sign-up, Login, and Payment Flow
# main.py - FINAL ARCHITECTURE with Sign-up, Login, and Payment Flow

import os
import uuid
from datetime import datetime, timedelta
import json
import asyncio
from typing import List, Dict, Any
import pandas as pd
import io
import resend
# --- Dependencies ---
from fastapi import FastAPI, UploadFile, File, HTTPException, Form, Depends
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
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

# --- Initial Setup: Load Env & Create DB Tables ---
load_dotenv()


# ==================== CONFIGURATION ====================
# Load all necessary environment variables
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_SECRET_KEY = os.getenv("RAZORPAY_SECRET_KEY")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
FRONTEND_URL = os.getenv("FRONTEND_URL")
RESEND_API_KEY=os.getenv("RESEND_API_KEY")
# Fail fast if critical security variables are missing
if not all([GROQ_API_KEY, RAZORPAY_KEY_ID, RAZORPAY_SECRET_KEY, JWT_SECRET_KEY,FRONTEND_URL,RESEND_API_KEY]):
    raise ValueError("FATAL ERROR: One or more required environment variables are not set.")

os.environ["GROQ_API_KEY"] = GROQ_API_KEY
JWT_ALGORITHM = "HS256"

resend.api_key = RESEND_API_KEY
# Password Hashing Context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Initialize Razorpay client with the corrected variable name
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_SECRET_KEY))

@asynccontextmanager
async def lifespan(app: FastAPI):
    # This code runs on startup
    print("Application startup: Creating database tables if they don't exist...")
    try:
        models.Base.metadata.create_all(bind=engine)
        print("Application startup: Database tables checked/created successfully.")
    except Exception as e:
        print(f"!!! FATAL ERROR during startup: Could not connect to database. {e}")
    
    yield
    # This code runs on shutdown (optional)
    print("Application shutdown.")

app = FastAPI(title="Enviscale - Secure Analysis Engine", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL], # Replace with your final frontend URL
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


# This model is used by /request-password-reset
class EmailSchema(BaseModel):
    email: EmailStr    

# --- Add this new Pydantic model at the top with the others ---
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
    expire = datetime.utcnow() + expires_delta
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
    """A dependency that checks if the user from the token has active access."""
    if current_user.access_valid_until is None or current_user.access_valid_until < datetime.utcnow():
        raise HTTPException(status_code=403, detail="Your access has expired. Please complete the payment to proceed.")
    return current_user



# ==================== AUTHENTICATION ENDPOINTS ====================

@app.post("/signup", tags=["Authentication"])
async def signup(user_data: UserCreate, db: Session = Depends(get_db)):
    """Registers a new user."""
    print(f"\n--- SIGNUP REQUEST RECEIVED for {user_data.email} ---")
    
    try:
        # Step 1: Check if user exists
        print("[Signup] STEP 1: Checking database for existing user...")
        db_user = db.query(models.User).filter(models.User.email == user_data.email).first()
        print("[Signup] STEP 1 SUCCESS: Database check complete.")
        
        if db_user:
            print(f"[Signup] ERROR: User {user_data.email} already exists.")
            raise HTTPException(status_code=400, detail="An account with this email already exists.")
        
        # Step 2: Hash the password
        print("[Signup] STEP 2: Hashing password...")
        hashed_password = get_password_hash(user_data.password)
        print("[Signup] STEP 2 SUCCESS: Password hashed.")
        
        # Step 3: Create the new user object
        print("[Signup] STEP 3: Creating new user object in memory...")
        new_user = models.User(email=user_data.email, hashed_password=hashed_password)
        print("[Signup] STEP 3 SUCCESS: User object created.")
        
        # Step 4: Add to database session and commit
        print("[Signup] STEP 4: Adding user to DB session and committing...")
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        print(f"[Signup] STEP 4 SUCCESS: User {new_user.email} committed to database with ID {new_user.id}.")
        
        # Step 5: Create access token
        print("[Signup] STEP 5: Creating access token...")
        access_token = create_access_token(data={"sub": new_user.email}, expires_delta=timedelta(days=1))
        print("[Signup] STEP 5 SUCCESS: Access token created.")
        
        print("--- SIGNUP PROCESS COMPLETED SUCCESSFULLY ---")
        return {"accessToken": access_token, "email": new_user.email}

    except Exception as e:
        # This will catch any unexpected crash and report it
        print(f"!!! CRITICAL ERROR DURING SIGNUP: {e}")
        # Rollback the transaction if something failed, especially after adding to session
        db.rollback()
        raise HTTPException(status_code=500, detail=f"An internal server error occurred during signup: {str(e)}")

@app.post("/login", tags=["Authentication"])
async def login(form_data: UserLogin, db: Session = Depends(get_db)):
    """Logs in an existing user."""
    user = db.query(models.User).filter(models.User.email == form_data.email).first()
    if not user or not user.hashed_password or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password.")

    access_token = create_access_token(data={"sub": user.email}, expires_delta=timedelta(days=1))
    return {"accessToken": access_token}


@app.post("/request-password-reset", tags=["Authentication"])
async def request_password_reset(data: EmailSchema, db: Session = Depends(get_db)):
    """If a user exists, sends them a password reset link."""
    print(f"\n--- PASSWORD RESET REQUEST for {data.email} ---")
    
    user = db.query(models.User).filter(models.User.email == data.email).first()
    
    # This conditional block is the core logic.
    # It ensures we only attempt to send an email if a user actually exists.
    if user:
        print(f"SUCCESS: Found user in DB with ID: {user.id}")
        
        # Create a short-lived token specifically for password reset
        reset_token = create_access_token(
            data={"sub": user.email, "purpose": "password_reset"}, 
            expires_delta=timedelta(minutes=30)
        )
        
        # Construct the full link using your environment variable
        reset_link = f"{FRONTEND_URL}/reset-password?token={reset_token}"
        
        # ===== THIS IS THE REAL EMAIL SENDING LOGIC =====
        try:
            print(f"Attempting to send password reset email to {user.email}...")
            
            # The actual API call to Resend
            resend.Emails.send({
                "from": "support@enviscale.com",  # IMPORTANT: Use a verified domain you own
                "to": user.email,
                "subject": "Your Enviscale Password Reset Request",
                "html": f"""
                    <div style="font-family: Arial, sans-serif; line-height: 1.6;">
                        <h2>Enviscale Password Reset</h2>
                        <p>Hello,</p>
                        <p>We received a request to reset the password for your account. Please click the link below to set a new password. This link is only valid for 30 minutes.</p>
                        <p style="margin: 20px 0;">
                            <a href="{reset_link}" style="display: inline-block; padding: 12px 24px; background-color: #2563EB; color: white; text-decoration: none; border-radius: 8px;">
                                Reset Your Password
                            </a>
                        </p>
                        <p>If you did not request a password reset, please ignore this email or contact support if you have concerns.</p>
                        <p>Thank you,<br>The Enviscale Team</p>
                    </div>
                """
            })
            
            print(f"SUCCESS: Password reset email sent to {user.email}.")
            
        except Exception as e:
            # If email sending fails, log the error but do not expose it to the user.
            # This prevents revealing whether an email address is registered or not.
            print(f"!!! CRITICAL ERROR: Could not send password reset email: {e}")
            # Do not raise an HTTPException here for security reasons.
        # ===============================================
            
    else:
        # If no user was found, we just print a log for our own debugging.
        # We do NOT tell the frontend that the user doesn't exist.
        print(f"INFO: No user found for email: {data.email}. No email will be sent.")

    # Always return the same generic message to prevent email enumeration attacks.
    return {"message": "If an account exists for this email, a password reset link has been sent."}


@app.post("/confirm-password-reset", tags=["Authentication"])
async def confirm_password_reset(data: PasswordResetRequest, db: Session = Depends(get_db)):
    """Verifies reset token and updates the user's password."""
    credentials_exception = HTTPException(status_code=400, detail="Invalid or expired reset token.")
    try:
        payload = jwt.decode(data.token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        
        # Check that the token was specifically for a password reset
        if payload.get("purpose") != "password_reset":
            raise credentials_exception
            
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        
        user = db.query(models.User).filter(models.User.email == email).first()
        if user is None:
            raise credentials_exception

        # Update the password
        user.hashed_password = get_password_hash(data.new_password)
        db.commit()

    except JWTError:
        raise credentials_exception
        
    return {"message": "Password has been updated successfully. Please log in."}    


@app.get("/users/me", tags=["Users"])
async def read_users_me(current_user: models.User = Depends(get_current_user)):
    """
    Returns the current logged-in user's details, including their access status.
    """
    has_active_access = False
    if current_user.access_valid_until and current_user.access_valid_until > datetime.utcnow():
        has_active_access = True
    
    return {
        "email": current_user.email,
        "has_active_access": has_active_access,
        "access_valid_until": current_user.access_valid_until
    }


# ==================== PAYMENT ENDPOINTS ====================

@app.post("/create-order/", tags=["Payment"])
async def create_order(current_user: models.User = Depends(get_current_user)):
    """Creates a Razorpay order for the currently logged-in user."""
    order_data = {
        "amount": 100,
        "currency": "INR",
        "receipt": f"rcpt_{uuid.uuid4().hex}",
        "notes": {"user_id": current_user.id} # Link order to user ID for robust tracking
    }
    try:
        order = razorpay_client.order.create(data=order_data)
        return {"orderId": order["id"], "keyId": RAZORPAY_KEY_ID, "amount": order_data["amount"]}
    except Exception as e:
        print(f"!!! RAZORPAY API ERROR: {e}")
        raise HTTPException(status_code=500, detail=f"An error occurred with the payment provider.")


@app.post("/verify-payment/", tags=["Payment"])
async def verify_payment(data: PaymentVerificationData, db: Session = Depends(get_db)):
    """Verifies payment and grants access in the DB."""
    try:
        razorpay_client.utility.verify_payment_signature(data.dict())
        
        order = razorpay_client.order.fetch(data.razorpay_order_id)
        user_id = order['notes'].get('user_id')
        if not user_id:
            raise HTTPException(status_code=400, detail="User ID not found in order notes.")

        user = db.query(models.User).filter(models.User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail=f"User with ID {user_id} not found.")

        # Grant access for 1 year (as an example for a full subscription)
        user.access_valid_until = datetime.utcnow() + timedelta(days=365)
        user.last_payment_id = data.razorpay_payment_id
        db.commit()
        print(f"Access granted for user {user.email} until {user.access_valid_until}")

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Payment verification failed: {e}")

    return {"status": "success", "message": "Payment successful. Access granted."}


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
    current_user: models.User = Depends(get_current_active_user)  # Now protected by the robust dependency
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