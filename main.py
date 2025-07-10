# main.py - FINAL ARCHITECTURE with Sign-up, Login, and Payment Flow
# main.py - FINAL ARCHITECTURE with Sign-up, Login, and Payment Flow

import os
import uuid
from datetime import datetime, timedelta, timezone
import json
import asyncio
from typing import List, Dict, Any,Optional
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
from supabase import create_client, Client

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
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
# Fail fast if critical security variables are missing
if not all([GROQ_API_KEY, RAZORPAY_KEY_ID, RAZORPAY_SECRET_KEY, JWT_SECRET_KEY,FRONTEND_URL,RESEND_API_KEY,SUPABASE_URL, SUPABASE_SERVICE_KEY]):
    raise ValueError("FATAL ERROR: One or more required environment variables are not set.")

os.environ["GROQ_API_KEY"] = GROQ_API_KEY
JWT_ALGORITHM = "HS256"

resend.api_key = RESEND_API_KEY
# Password Hashing Context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Initialize Razorpay client with the corrected variable name
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_SECRET_KEY))
supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

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
# ===== ADD THIS NEW HEALTH CHECK ENDPOINT =====
@app.get("/health", status_code=200, tags=["Health"])
async def health_check():
    """A simple endpoint for Render's health check."""
    return {"status": "ok"}
# ===============================
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
    """A dependency that checks if the user from the token has active access."""
    if current_user.access_valid_until is None or current_user.access_valid_until < datetime.now(timezone.utc):
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
    if current_user.access_valid_until and current_user.access_valid_until > datetime.now(timezone.utc):
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
        "amount": 1180000,
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
        user.access_valid_until = datetime.now(timezone.utc) + timedelta(days=365)
        user.last_payment_id = data.razorpay_payment_id
        db.commit()
        print(f"Access granted for user {user.email} until {user.access_valid_until}")

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Payment verification failed: {e}")

    return {"status": "success", "message": "Payment successful. Access granted."}


# ==================== DATA ANALYSIS FUNCTIONS ====================

FIELD_DESCRIPTION_MAP = {
    # Purchase Register Fields
    "Invoice_Date": "Date when the invoice was issued",
    "Invoice_Number": "Unique number of the invoice",
    "Vendor_Name": "Name of the vendor",
    "Vendor_GSTIN": "GSTIN of the vendor",
    "Taxable_Value": "Taxable value in the invoice",
    "Total_Invoice_Value": "Total value including tax",
    "Has_PO": "Whether a PO (purchase order) is attached",
    
    # TDS Ledger Fields
    "Payment_Date": "Date when the payment was made",
    "Amount_Paid": "Amount paid to the vendor",
    "TDS_Section": "Section under which TDS was deducted",
    "TDS_Deducted": "Amount of TDS deducted",

    # GSTR-2B Fields (some overlap with Purchase)
    # Re-using existing descriptions for Invoice_Number, Vendor_GSTIN, etc.

    # --- NEW FIELDS FOR NEW FILES ---
    # GSTR-3B Fields
    "Return_Period": "The month/quarter for the GSTR-3B filing (e.g., 'Apr-2024')",
    "ITC_Available": "Total Input Tax Credit available as per books or 2B",
    "ITC_Claimed": "Input Tax Credit actually claimed in the GSTR-3B return for that period",
    "Tax_Paid_Cash": "GST liability paid through cash ledger",

    # Vendor Master Fields
    "Vendor_Code": "Internal unique code for the vendor",
    "Vendor_PAN": "Permanent Account Number (PAN) of the vendor",
    "Vendor_Address": "Registered address of the vendor",
    "Vendor_Bank_Account": "Bank account number of the vendor",

    # Sales Register Fields
    "Customer_Name": "Name of the customer who was billed",
    "Sales_Invoice_Value": "Total value of the sales invoice"
}


@retry(stop=stop_after_attempt(3), wait=wait_random_exponential(min=1, max=4))
async def extract_mapping_llm(columns: list, doc_type: str) -> dict:
    """
    Uses an LLM to map messy column headers to a standard, predefined schema
    based on the document type.
    """
    prompt = f"You are a data analyst mapping messy Excel headers to standard fields for {doc_type} documents.\nStandard fields and their purposes:\n"
    
    relevant_fields = []
    # Define the required fields for each document type
    if doc_type == "purchase":
        relevant_fields = ["Invoice_Date", "Invoice_Number", "Vendor_Name", "Vendor_GSTIN", "Taxable_Value", "Total_Invoice_Value", "Has_PO"]
    elif doc_type == "tds":
        relevant_fields = ["Payment_Date", "Vendor_Name", "Amount_Paid", "TDS_Section", "TDS_Deducted"]
    elif doc_type == "gstr2b":
        # Note: GSTR2B often shares fields with Purchase Register
        relevant_fields = ["Invoice_Date", "Invoice_Number", "Vendor_GSTIN", "Total_Invoice_Value", "Vendor_Name"]
    elif doc_type == "gstr3b":
        relevant_fields = ["Return_Period", "ITC_Available", "ITC_Claimed", "Tax_Paid_Cash"]
    elif doc_type == "vendor_master":
        relevant_fields = ["Vendor_Code", "Vendor_Name", "Vendor_GSTIN", "Vendor_PAN", "Vendor_Address", "Vendor_Bank_Account"]
    elif doc_type == "sales_register":
        relevant_fields = ["Invoice_Date", "Invoice_Number", "Customer_Name", "Sales_Invoice_Value"]
    
    # Build the prompt with field descriptions
    for field in relevant_fields:
        prompt += f"- {field}: {FIELD_DESCRIPTION_MAP.get(field, 'No description')}\n"
    
    prompt += f"\nHere are the actual, messy column names from the uploaded file that need mapping:\n" + "\n".join([f"- {col}" for col in columns])
    prompt += "\n\nYour task is to return ONLY a JSON dictionary that maps the standard fields (the keys) to the most likely column name from the uploaded file (the values). If you cannot find a confident match for a standard field, OMIT it entirely from the final JSON. Do not guess."
    
    try:
        response = await acompletion(
            model="groq/llama3-70b-8192",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            max_tokens=500  # Increased slightly for potentially larger schemas
        )
        return json.loads(response.choices[0].message.content)
    except (json.JSONDecodeError, IndexError, Exception) as e:
        print(f"LLM mapping failed for doc_type '{doc_type}': {e}")
        return {}

async def extract_semantic_fields(df: pd.DataFrame, doc_type: str) -> pd.DataFrame:
    if df.empty:
        return df
    mapping = await extract_mapping_llm(list(df.columns), doc_type)
    reverse_mapping = {v: k for k, v in mapping.items() if v in df.columns}
    return df.rename(columns=reverse_mapping)


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

# In main.py

def calculate_invoice_quality_score(purchase_df: pd.DataFrame) -> Dict[str, Any]:
    if purchase_df.empty: 
        return {"score": 0, "grade": "N/A", "total_invoices": 0, "po_linked": 0}
    
    total_invoices = len(purchase_df)
    po_linked = 0
    if 'Has_PO' in purchase_df.columns:
        po_linked = purchase_df[purchase_df['Has_PO'].astype(str).str.upper().isin(['YES', 'Y'])].shape[0]

    score = round((po_linked / total_invoices) * 100) if total_invoices > 0 else 0

    # --- NEW: Grading Logic ---
    grade = "N/A"
    if score >= 95:
        grade = "A+"
    elif score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 50:
        grade = "C"
    else:
        grade = "F"
    
    return {
        "score": score, 
        "grade": grade, # The new grade
        "total_invoices": total_invoices, 
        "po_linked": po_linked
    }

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
    """A high-level comparison of ITC claimed vs. available."""
    findings = []
    # --- FIX: Add defensive checks for required columns ---
    required_2b_cols = ['Total_Invoice_Value']
    required_3b_cols = ['ITC_Claimed']

    if gstr2b_df.empty or gstr3b_df.empty or \
       not all(col in gstr2b_df.columns for col in required_2b_cols) or \
       not all(col in gstr3b_df.columns for col in required_3b_cols):
        return [] # Return early if data or columns are missing

    try:
        # --- FIX: Use .get() with a default or ensure numeric conversion ---
        itc_available = pd.to_numeric(gstr2b_df['Total_Invoice_Value'], errors='coerce').sum()
        itc_claimed = pd.to_numeric(gstr3b_df['ITC_Claimed'], errors='coerce').sum()

        if itc_claimed > itc_available:
            findings.append({
                "issue_type": "EXCESS_ITC_CLAIMED",
                "vendor": "N/A", # Add placeholder for fingerprinting
                "invoice_number": "N/A", # Add placeholder
                "details": f"ITC claimed in GSTR-3B (₹{itc_claimed:,.2f}) exceeds ITC available in GSTR-2B (₹{itc_available:,.2f}).",
                "amount": round(itc_claimed - itc_available, 2)
            })
    except Exception as e:
        print(f"Error in GSTR-3B vs 2B analysis: {e}")
        # Don't crash the app, just log the error and continue
    return findings






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

async def read_optional_file(file: Optional[UploadFile]) -> pd.DataFrame:
    """Safely reads an optional uploaded file into a DataFrame."""
    if not file or not file.filename:
        return pd.DataFrame()
    content = await file.read()
    if not content:
        return pd.DataFrame()
    try:
        if file.filename.endswith('.csv'):
            return pd.read_csv(io.BytesIO(content), dtype=str, keep_default_na=False)
        else:
            return pd.read_excel(io.BytesIO(content), engine='openpyxl', dtype=str, keep_default_na=False)
    except Exception as e:
        print(f"Warning: Could not read file {file.filename}. Error: {e}")
        return pd.DataFrame()



# In main.py
async def get_admin_user(current_user: models.User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="You do not have permission to access this resource.")
    return current_user

# In main.py
@app.get("/admin/metrics", tags=["Admin"], dependencies=[Depends(get_admin_user)])
async def get_admin_metrics(db: Session = Depends(get_db)):
    total_users = db.query(models.User).count()
    total_audits = db.query(models.Audit).count()
    total_findings = db.query(models.AuditFinding).count()
    
    # More advanced: users with active subscriptions
    active_subscriptions = db.query(models.User).filter(
        models.User.access_valid_until > datetime.now(timezone.utc)
    ).count()

    return {
        "total_users": total_users,
        "total_audits_run": total_audits,
        "total_findings_identified": total_findings,
        "active_subscriptions": active_subscriptions
    }
# In main.py, with the other analysis functions

def analyze_payment_patterns(purchase_df: pd.DataFrame, tds_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Analyzes payment cycles, weekend payments, and other patterns.
    This requires merging purchase data (for invoice dates) with payment data (for payment dates).
    """
    # Define default return structure
    default_patterns = {
        "avg_payment_days": "N/A",
        "weekend_payments": 0,
        "late_payments": 0,
        "bulk_payment_days": 0,
    }

    # --- Defensive Checks ---
    required_purchase_cols = ['Invoice_Date', 'Vendor_Name', 'Invoice_Number']
    required_tds_cols = ['Payment_Date', 'Vendor_Name', 'Amount_Paid']
    if purchase_df.empty or tds_df.empty or \
       not all(col in purchase_df.columns for col in required_purchase_cols) or \
       not all(col in tds_df.columns for col in required_tds_cols):
        return default_patterns

    # --- Data Preparation ---
    p_df = purchase_df.copy()
    t_df = tds_df.copy()

    # Convert dates, coercing errors to NaT (Not a Time)
    p_df['Invoice_Date'] = pd.to_datetime(p_df['Invoice_Date'], errors='coerce')
    t_df['Payment_Date'] = pd.to_datetime(t_df['Payment_Date'], errors='coerce')
    
    # Drop rows where dates could not be parsed
    p_df.dropna(subset=['Invoice_Date'], inplace=True)
    t_df.dropna(subset=['Payment_Date'], inplace=True)

    if p_df.empty or t_df.empty:
        return default_patterns
        
    # --- Merge DataFrames ---
    # A simple merge on Vendor_Name is a good heuristic. A more advanced version
    # could try to match on Invoice_Number if available in both.
    # We use a left merge to keep all payments and find their corresponding invoice date.
    merged_df = pd.merge(t_df, p_df, on='Vendor_Name', how='left', suffixes=('_payment', '_invoice'))
    
    # Drop rows where no matching invoice date was found
    merged_df.dropna(subset=['Invoice_Date'], inplace=True)

    if merged_df.empty:
        return default_patterns

    # --- Calculations ---

    # 1. Average Payment Days
    merged_df['payment_days'] = (merged_df['Payment_Date'] - merged_df['Invoice_Date']).dt.days
    # Filter out negative days which indicate bad data (payment before invoice)
    valid_payments = merged_df[merged_df['payment_days'] >= 0]
    avg_days = int(valid_payments['payment_days'].mean()) if not valid_payments.empty else "N/A"

    # 2. Weekend Payments
    # Day 5 is Saturday, Day 6 is Sunday
    weekend_payments_count = merged_df[merged_df['Payment_Date'].dt.dayofweek.isin([5, 6])].shape[0]

    # 3. Late Payments (payments taking > 30 days)
    late_payments_count = valid_payments[valid_payments['payment_days'] > 30].shape[0]

    # 4. Bulk Payment Days
    payment_counts_per_day = t_df.groupby(t_df['Payment_Date'].dt.date).size()
    bulk_days_count = payment_counts_per_day[payment_counts_per_day >= 10].count()

    return {
        "avg_payment_days": avg_days,
        "weekend_payments": weekend_payments_count,
        "late_payments": late_payments_count,
        "bulk_payment_days": int(bulk_days_count),
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

# --- Initialize Supabase Client ---
supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

# ==================== SECURED REPORT ENDPOINT ====================

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
    print(f"[{datetime.now()}] --- NEW ENHANCED REPORT REQUEST for {company_name} ---")
    
    # --- Step 1: Read all files safely ---
    p_df, t_df, g2b_df, g3b_df, vm_df, sr_df = await asyncio.gather(
        read_optional_file(purchase_file),
        read_optional_file(tds_file),
        read_optional_file(gstr2b_file),
        read_optional_file(gstr3b_file),
        read_optional_file(vendor_master_file),
        read_optional_file(sales_register_file),
    )
    
    # --- Step 2: AI Column Mapping (UPDATED) ---
    print(f"[{datetime.now()}] STEP 2: Starting AI column mapping for all files...")
    mapped_p_df, mapped_t_df, mapped_g2b_df, mapped_g3b_df, mapped_vm_df, mapped_sr_df = await asyncio.gather(
        extract_semantic_fields(p_df, "purchase"),
        extract_semantic_fields(t_df, "tds"),
        extract_semantic_fields(g2b_df, "gstr2b"),
        extract_semantic_fields(g3b_df, "gstr3b"),
        extract_semantic_fields(vm_df, "vendor_master"),
        extract_semantic_fields(sr_df, "sales_register")
    )
    print(f"[{datetime.now()}] STEP 2 SUCCESS: AI mapping complete.")

    # --- Step 3: Core & Strategic Analysis ---
    all_findings = []
    
    # Core Compliance Analysis
    vendor_findings = analyze_vendor_data(mapped_p_df)
    tds_findings = analyze_tds_data(mapped_t_df)
    gst_findings = analyze_gst_data(mapped_p_df, mapped_g2b_df)
    gstr_3b_findings = analyze_gstr_3b_vs_2b(mapped_g2b_df, mapped_g3b_df)
    all_findings.extend(vendor_findings)
    all_findings.extend(tds_findings)
    all_findings.extend(gst_findings)
    all_findings.extend(gstr_3b_findings)

    # Strategic Intelligence Analysis
    vendor_exposure = calculate_vendor_spend_exposure(mapped_p_df)
    iqs_score = calculate_invoice_quality_score(mapped_p_df)
    spend_trends = analyze_monthly_spend_trends(mapped_p_df)

    # --- ADD THE NEW ANALYSIS CALL HERE ---
    payment_patterns = analyze_payment_patterns(mapped_p_df, mapped_t_df)
    
    # --- Step 4: "Memory Lite" Engine ---
    new_audit = models.Audit(user_id=current_user.id, company_name=company_name)
    db.add(new_audit)
    db.commit()
    db.refresh(new_audit)
    audit_id = new_audit.id

    
    for finding in all_findings:
        fingerprint_keys = ['vendor', 'invoice_number', 'section', 'amount']
        fingerprint_str = f"{finding['issue_type']}-" + "-".join([str(finding.get(k, '')) for k in fingerprint_keys])
        
        # --- THE CORRECTED QUERY ---
        # We now JOIN through the Audit table to check the user_id
        past_findings_count = db.query(models.AuditFinding).join(models.Audit).filter(
            models.Audit.user_id == current_user.id,
            models.AuditFinding.fingerprint == fingerprint_str
        ).count()
        
        is_repeat = past_findings_count > 0
        finding['is_repeat'] = is_repeat
        finding['past_occurrences'] = past_findings_count

        # --- THE CORRECTED OBJECT CREATION (matches your new models.py) ---
        db_finding = models.AuditFinding(
            audit_id=audit_id,
            # user_id is correctly removed
            issue_type=finding['issue_type'],
            details=json.dumps({k: v for k, v in finding.items() if k not in ['is_repeat', 'past_occurrences']}),
            fingerprint=fingerprint_str,
            is_repeat=is_repeat
        )
        db.add(db_finding)

    db.commit()


    # --- Step 4.5: Calculate Totals & Generate AI Summaries ---
    print(f"[{datetime.now()}] STEP 4.5: Calculating totals for AI summary...")
    vendor_summary_data = calculate_vendor_totals(vendor_findings)
    tds_summary_data = calculate_tds_totals(tds_findings)
    # Combine all GST-related findings for a comprehensive summary
    all_gst_findings = gst_findings + gstr_3b_findings
    gst_summary_data = calculate_gst_totals(all_gst_findings)
    
    print(f"[{datetime.now()}] STEP 4.5a: Starting AI summary generation...")
    vendor_summary, tds_summary, gst_summary = await asyncio.gather(
        generate_summary(vendor_summary_data, "Vendor & Payment Risks"),
        generate_summary(tds_summary_data, "TDS Compliance Risks"),
        generate_summary(gst_summary_data, "GST Compliance & ITC Reconciliation")
    )
    print(f"[{datetime.now()}] STEP 4.5b SUCCESS: AI summaries generated.")

    # --- Step 5: Render PDF Report ---
    # Now this line will work because the variables are defined
   
    # --- Step 5: Render PDF Report ---
    template = env.get_template("report_template.html")
    html_out = await template.render_async(
        company_name=company_name,
        report_date=datetime.now().strftime("%d %B %Y"),
        audit_period="Q2 2024-25", # You can make this dynamic later
        
        # Pass all the findings
        vendor_findings=vendor_findings,
        gst_findings=gst_findings,
        tds_findings=tds_findings,
        gstr_3b_findings=gstr_3b_findings,
        
        # Pass strategic intelligence data
        iqs_score=iqs_score,
        vendor_exposure=vendor_exposure,
        spend_trends=spend_trends,
        
        # --- PASS THE NEW PAYMENT PATTERNS DATA ---
        payment_patterns=payment_patterns,

        # AI Summaries (if you generate them)
        vendor_summary=vendor_summary, # Assuming you generate these
        gst_summary=gst_summary,
        tds_summary=tds_summary,
    )
    
    pdf_bytes = HTML(string=html_out).write_pdf()
    
    # --- Step 6: Store Artifacts ---
    report_filename = f"{company_name.replace(' ', '_')}_{audit_id}.pdf"
    storage_path = f"user_{current_user.id}/{audit_id}/{report_filename}"
    
    try:
        supabase.storage.from_("audit-artifacts").upload(file=pdf_bytes, path=storage_path)
        report_url = supabase.storage.from_("audit-artifacts").get_public_url(storage_path)
        new_audit.report_url = report_url
        db.commit()
    except Exception as e:
        print(f"Supabase upload failed: {e}")

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{report_filename}"'}
    )


# ==================== NEW DASHBOARD API ENDPOINTS ====================

class AuditHistoryItem(BaseModel):
    id: int
    company_name: str
    timestamp: datetime
    report_url: Optional[str]

# In the Pydantic models section
class FindingDetailItem(BaseModel):
    id: int # <-- FIX: Add the ID field
    issue_type: str
    details: Dict[str, Any]
    is_repeat: bool
    timestamp: datetime

@app.get("/audits/", response_model=List[AuditHistoryItem], tags=["Dashboard"])
async def get_audit_history(current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Fetches a list of all past audits for the current user."""
    audits = db.query(models.Audit).filter(models.Audit.user_id == current_user.id).order_by(models.Audit.timestamp.desc()).all()
    return audits

# In /audits/{audit_id}/findings/ endpoint
@app.get("/audits/{audit_id}/findings/", response_model=List[FindingDetailItem], tags=["Dashboard"])
async def get_audit_findings(
    audit_id: int, 
    current_user: models.User = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    """Fetches all findings associated with a specific audit run, verifying the audit belongs to the current user."""
    # First verify the audit belongs to the current user
    audit = db.query(models.Audit).filter(
        models.Audit.id == audit_id,
        models.Audit.user_id == current_user.id
    ).first()

    if not audit:
        raise HTTPException(
            status_code=404, 
            detail="Audit not found or you don't have permission to access it."
        )

    # Now fetch findings for this audit
    findings = db.query(models.AuditFinding).filter(
        models.AuditFinding.audit_id == audit_id
    ).order_by(models.AuditFinding.timestamp.desc()).all()

    # Transform findings into response model
    return [
        FindingDetailItem(
            id=finding.id,
            issue_type=finding.issue_type,
            details=json.loads(finding.details),
            is_repeat=finding.is_repeat,
            timestamp=finding.timestamp
        )
        for finding in findings
    ]


@app.get("/audits/{audit_id}/export-excel/", tags=["Dashboard"])
async def export_findings_to_excel(audit_id: int, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Exports all findings from an audit to an Excel file."""
    findings_query = db.query(models.AuditFinding).filter(
        models.AuditFinding.audit_id == audit_id, 
        models.AuditFinding.user_id == current_user.id
    ).all()

    if not findings_query:
        raise HTTPException(status_code=404, detail="No findings found for this audit.")

    # Process findings for Excel export
    data_to_export = []
    for f in findings_query:
        details = json.loads(f.details)
        details['issue_type'] = f.issue_type
        details['is_repeat_issue'] = f.is_repeat
        details['first_seen'] = f.timestamp.strftime("%Y-%m-%d")
        data_to_export.append(details)
    
    df = pd.DataFrame(data_to_export)
    
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Audit_Findings')
    
    output.seek(0)
    
    return StreamingResponse(
        output,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename=Enviscale_Audit_{audit_id}_Findings.xlsx"}
    )
