# main.py
import os
import pandas as pd
import io
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any
import json
import asyncio

# --- FastAPI and Web Dependencies ---
from fastapi import FastAPI, UploadFile, File, HTTPException, Form, Depends
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from weasyprint import HTML
from jinja2 import Environment, FileSystemLoader, select_autoescape

# --- AI and Data Processing Dependencies ---
from litellm import acompletion
from tenacity import retry, stop_after_attempt, wait_random_exponential

# [SECURITY] Import new dependencies for payment & token security
import razorpay
from pydantic import BaseModel
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer

# ==================== CONFIGURATION ====================

# [SECURITY] Load all necessary environment variables for Razorpay & JWT
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_SECRET_KEY = os.getenv("RAZORPAY_SECRET_KEY")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = "HS256"

# [SECURITY] Fail fast if critical security variables are missing
if not all([GROQ_API_KEY, RAZORPAY_KEY_ID, RAZORPAY_SECRET_KEY, JWT_SECRET_KEY]):
    raise ValueError("FATAL ERROR: One or more required environment variables (GROQ, RAZORPAY, JWT) are not set.")

os.environ["GROQ_API_KEY"] = GROQ_API_KEY

app = FastAPI(title="Envisort - Automated Analysis Engine") # Renamed for consistency
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict this to your frontend URL: ["https://envisort.vercel.app"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# [SECURITY] Initialize Razorpay client instance
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_SECRET_KEY))

# [SECURITY] Pydantic models for request body validation
class PaymentVerificationData(BaseModel):
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str

# [SECURITY] OAuth2 scheme to extract token from Authorization header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token") # tokenUrl isn't used, but required

# [SECURITY] Dependency function to verify JWT and protect endpoints
async def get_current_user_from_token(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        payment_id: str = payload.get("sub")
        if payment_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return {"payment_id": payment_id}

@app.get("/ping")
async def ping():
    return {"status": "ok", "message": "Envisort is alive"}
    
env = Environment(loader=FileSystemLoader("templates"), autoescape=select_autoescape(["html"]), enable_async=True)

# ==================== NEW SECURITY ENDPOINTS ====================

@app.post("/create-order/", tags=["Payment"])
async def create_order():
    """
    Creates a Razorpay order. The frontend calls this before showing the payment modal.
    """
    try:
        order_data = {
            "amount": 1180000,  # Amount in paise (11,800 INR)
            "currency": "INR",
            "receipt": f"rcpt_{uuid.uuid4().hex}",
        }
        
        order = razorpay_client.order.create(data=order_data)
        
        return {"orderId": order["id"], "keyId": RAZORPAY_KEY_ID}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating Razorpay order: {e}")

@app.post("/verify-payment/", tags=["Payment"])
async def verify_payment(data: PaymentVerificationData):
    """
    Verifies a payment after the user completes it on the frontend.
    If successful, returns a secure JWT access token.
    """
    try:
        # This function cryptographically verifies the payment signature
        razorpay_client.utility.verify_payment_signature({
            'razorpay_order_id': data.razorpay_order_id,
            'razorpay_payment_id': data.razorpay_payment_id,
            'razorpay_signature': data.razorpay_signature
        })
    except Exception as e:
        raise HTTPException(status_code=400, detail="Payment verification failed: Invalid signature.")

    # Payment is verified. Now, create a secure access token (JWT).
    to_encode = {
        "sub": data.razorpay_payment_id, # Subject of the token
        "exp": datetime.utcnow() + timedelta(hours=1) # Token is valid for 1 hour
    }
    access_token = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    
    return {"status": "success", "accessToken": access_token}


# ==================== AI MAPPING & CORE LOGIC (UNCHANGED) ====================

# All your existing functions from FIELD_DESCRIPTION_MAP to generate_summary
# remain exactly the same. No changes needed here.
# ... (all your existing functions) ...

FIELD_DESCRIPTION_MAP = {
    "Invoice_Date": "Date when the invoice was issued", "Invoice_Number": "Unique number of the invoice",
    "Vendor_Name": "Name of the vendor", "Vendor_GSTIN": "GSTIN of the vendor",
    "Taxable_Value": "Taxable value in the invoice", "Total_Invoice_Value": "Total value including tax",
    "Has_PO": "Whether a PO (purchase order) is attached", "Payment_Date": "Date when the payment was made",
    "Amount_Paid": "Amount paid to the vendor", "TDS_Section": "Section under which TDS was deducted",
    "TDS_Deducted": "Amount of TDS deducted",
}

@retry(stop=stop_after_attempt(3), wait=wait_random_exponential(min=1, max=4))
async def extract_mapping_llm(columns: list, doc_type: str) -> dict:
    prompt = f"You are a data analyst mapping messy Excel headers to standard fields for {doc_type} documents.\nStandard fields and their purposes:\n"
    relevant_fields = []
    if doc_type == "purchase": relevant_fields = ["Invoice_Date", "Invoice_Number", "Vendor_Name", "Vendor_GSTIN", "Taxable_Value", "Total_Invoice_Value", "Has_PO"]
    elif doc_type == "tds": relevant_fields = ["Payment_Date", "Vendor_Name", "Amount_Paid", "TDS_Section", "TDS_Deducted"]
    elif doc_type == "gstr2b": relevant_fields = ["Invoice_Number", "Vendor_GSTIN", "Total_Invoice_Value", "Vendor_Name"]
    for field in relevant_fields: prompt += f"- {field}: {FIELD_DESCRIPTION_MAP[field]}\n"
    prompt += f"\nActual columns needing mapping:\n" + "\n".join([f"- {col}" for col in columns])
    prompt += "\n\nReturn ONLY a JSON dictionary mapping standard fields to the most likely column name. If no good match exists for a field, omit it from the JSON."
    response = await acompletion(model="groq/llama3-70b-8192", messages=[{"role": "user", "content": prompt}], response_format={"type": "json_object"}, max_tokens=400)
    try: return json.loads(response.choices[0].message.content)
    except (json.JSONDecodeError, IndexError): return {}

async def extract_semantic_fields(df: pd.DataFrame, doc_type: str) -> pd.DataFrame:
    if df.empty: return df
    mapping = await extract_mapping_llm(list(df.columns), doc_type)
    reverse_mapping = {v: k for k, v in mapping.items() if v in df.columns}
    return df.rename(columns=reverse_mapping)

def find_duplicate_invoices(df: pd.DataFrame) -> List[Dict[str, Any]]:
    required_cols = ['Vendor_Name', 'Invoice_Number', 'Invoice_Date', 'Total_Invoice_Value'];
    if not all(col in df.columns for col in required_cols): return []
    duplicates_df = df[df.duplicated(subset=['Vendor_Name', 'Invoice_Number', 'Invoice_Date'], keep=False)];
    if duplicates_df.empty: return []
    grouped = duplicates_df.groupby(['Vendor_Name', 'Invoice_Number', 'Invoice_Date']);
    findings = []
    for _, group in grouped: first_invoice = group.iloc[0]; findings.append({"issue_type": "DUPLICATE_INVOICE", "invoice_number": first_invoice['Invoice_Number'], "vendor": first_invoice['Vendor_Name'], "amount": float(first_invoice['Total_Invoice_Value']), "count": len(group), "details": f"Found {len(group)} instances."})
    return findings
def find_invoices_without_po(df: pd.DataFrame) -> List[Dict[str, Any]]:
    if 'Has_PO' not in df.columns: return []
    no_po_df = df[df['Has_PO'].astype(str).str.upper().isin(['NO', 'N', ''])];
    findings = []
    for _, row in no_po_df.iterrows(): findings.append({"issue_type": "INVOICE_WITHOUT_PO", "invoice_number": row['Invoice_Number'], "vendor": row['Vendor_Name'], "amount": float(row['Total_Invoice_Value']), "details": "No Purchase Order linked."})
    return findings
def analyze_vendor_data(purchase_df: pd.DataFrame) -> List[Dict[str, Any]]:
    all_findings = []; all_findings.extend(find_duplicate_invoices(purchase_df)); all_findings.extend(find_invoices_without_po(purchase_df)); return all_findings
def analyze_tds_data(tds_df: pd.DataFrame) -> List[Dict[str, Any]]:
    required_cols = ['Amount_Paid', 'TDS_Deducted', 'TDS_Section', 'Vendor_Name'];
    if not all(col in tds_df.columns for col in required_cols): return []
    findings = []; TDS_RULES = {"194C": {"threshold": 30000, "rate": 0.02}, "194J": {"threshold": 30000, "rate": 0.10}, "194I": {"threshold": 240000, "rate": 0.10}};
    df_copy = tds_df.copy(); df_copy['Amount_Paid'] = pd.to_numeric(df_copy['Amount_Paid'], errors='coerce'); df_copy['TDS_Deducted'] = pd.to_numeric(df_copy['TDS_Deducted'], errors='coerce').fillna(0); df_copy['TDS_Section'] = df_copy['TDS_Section'].astype(str).str.strip().str.upper()
    for _, row in df_copy.iterrows():
        section = row['TDS_Section'];
        if section not in TDS_RULES: continue
        rules, amount_paid, tds_deducted = TDS_RULES[section], row['Amount_Paid'], row['TDS_Deducted']
        if amount_paid > rules['threshold']:
            expected_tds = amount_paid * rules['rate']
            if tds_deducted == 0: findings.append({"issue_type": "TDS_NOT_DEDUCTED", "vendor": row['Vendor_Name'], "amount_paid": amount_paid, "section": section, "expected_tds": round(expected_tds, 2), "tds_deducted": None, "details": f"Expected {expected_tds:.2f}"})
            elif abs(tds_deducted - expected_tds) > 1: findings.append({"issue_type": "TDS_INCORRECT_DEDUCTION", "vendor": row['Vendor_Name'], "amount_paid": amount_paid, "section": section, "expected_tds": round(expected_tds, 2), "tds_deducted": tds_deducted, "details": f"Shortfall of {(expected_tds - tds_deducted):.2f}"})
    return findings
def analyze_gst_data(purchase_df: pd.DataFrame, gstr2b_df: pd.DataFrame) -> List[Dict[str, Any]]:
    required_purchase_cols = ['Invoice_Number', 'Vendor_GSTIN', 'Vendor_Name', 'Total_Invoice_Value']; required_gstr2b_cols = ['Invoice_Number', 'Vendor_GSTIN', 'Vendor_Name', 'Total_Invoice_Value']
    if not all(col in purchase_df.columns for col in required_purchase_cols) or not all(col in gstr2b_df.columns for col in required_gstr2b_cols): return []
    def standardize(df): df = df.copy(); df['Invoice_Number_Std'] = df['Invoice_Number'].astype(str).str.upper().str.strip(); df['Vendor_GSTIN_Std'] = df['Vendor_GSTIN'].astype(str).str.upper().str.strip(); return df
    std_purchase, std_2b = standardize(purchase_df), standardize(gstr2b_df)
    unclaimed = pd.merge(std_2b, std_purchase, on=['Invoice_Number_Std', 'Vendor_GSTIN_Std'], how='left', indicator=True).query('_merge == "left_only"')
    risky = pd.merge(std_purchase, std_2b, on=['Invoice_Number_Std', 'Vendor_GSTIN_Std'], how='left', indicator=True).query('_merge == "left_only"')
    findings = [];
    for _, row in unclaimed.iterrows(): findings.append({"issue_type": "UNCLAIMED_ITC", "invoice_number": row['Invoice_Number_x'], "vendor": row['Vendor_Name_x'], "amount": float(row['Total_Invoice_Value_x']), "details": "In GSTR-2B, not purchase register."})
    for _, row in risky.iterrows(): findings.append({"issue_type": "RISKY_ITC", "invoice_number": row['Invoice_Number_x'], "vendor": row['Vendor_Name_x'], "amount": float(row['Total_Invoice_Value_x']), "details": "In purchase register, not GSTR-2B."})
    return findings
def calculate_vendor_totals(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    duplicate_risk = sum(f['amount'] for f in findings if f['issue_type'] == 'DUPLICATE_INVOICE'); no_po_risk = sum(f['amount'] for f in findings if f['issue_type'] == 'INVOICE_WITHOUT_PO')
    return {"total_risk": round(duplicate_risk + no_po_risk, 2), "duplicate_payment_risk": round(duplicate_risk, 2), "unauthorized_spend_risk": round(no_po_risk, 2), "detailed_findings": findings}
def calculate_tds_totals(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    total_shortfall = 0;
    for f in findings:
        if f['issue_type'] == 'TDS_NOT_DEDUCTED': total_shortfall += f.get('expected_tds', 0)
        elif f['issue_type'] == 'TDS_INCORRECT_DEDUCTION': total_shortfall += f.get('expected_tds', 0) - (f.get('tds_deducted') or 0)
    return {"total_liability_risk": round(total_shortfall, 2), "detailed_findings": findings}
def calculate_gst_totals(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    unclaimed_itc = sum(f['amount'] for f in findings if f['issue_type'] == 'UNCLAIMED_ITC'); risky_itc = sum(f['amount'] for f in findings if f['issue_type'] == 'RISKY_ITC')
    return {"unclaimed_itc_opportunity": round(unclaimed_itc, 2), "risky_itc_exposure": round(risky_itc, 2), "detailed_findings": findings}
@retry(stop=stop_after_attempt(3), wait=wait_random_exponential(min=1, max=4))
async def generate_summary(summary_data: Dict[str, Any], issue_category: str) -> str:
    if not summary_data.get("detailed_findings"): return f"No significant issues found."
    summary_json = json.dumps(summary_data);
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
    try: response = await acompletion(model="groq/llama3-70b-8192", messages=[{"role": "user", "content": prompt}], max_tokens=300); return response.choices[0].message.content.strip()
    except Exception as e: return f"Could not generate AI summary: {e}"

# ==================== SECURED FASTAPI ENDPOINT ====================

@app.post("/generate-report-from-files/", tags=["Report Generation"])
async def generate_report_from_files(
    company_name: str = Form(...),
    purchase_file: UploadFile = File(...),
    tds_file: UploadFile = File(...),
    gstr2b_file: UploadFile = File(...),
    # [SECURITY] This dependency protects the endpoint. It will raise a 401 error if the token is invalid/missing.
    current_user: dict = Depends(get_current_user_from_token)
):
    # --- 1. Process Files ---
    # The code below will ONLY run if the token is valid, thanks to the Depends() above.
    try:
        p_content, t_content, g_content = await asyncio.gather(purchase_file.read(), tds_file.read(), gstr2b_file.read())
        p_df = pd.read_csv(io.BytesIO(p_content), dtype=str, keep_default_na=False) if purchase_file.filename.endswith('.csv') else pd.read_excel(io.BytesIO(p_content), engine='openpyxl', dtype=str, keep_default_na=False)
        t_df = pd.read_csv(io.BytesIO(t_content), dtype=str, keep_default_na=False) if tds_file.filename.endswith('.csv') else pd.read_excel(io.BytesIO(t_content), engine='openpyxl', dtype=str, keep_default_na=False)
        g_df = pd.read_csv(io.BytesIO(g_content), dtype=str, keep_default_na=False) if gstr2b_file.filename.endswith('.csv') else pd.read_excel(io.BytesIO(g_content), engine='openpyxl', dtype=str, keep_default_na=False)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reading one of the files: {e}")

    # --- 2. AI-Powered Column Mapping ---
    try:
        mapped_purchase_df, mapped_tds_df, mapped_gstr2b_df = await asyncio.gather(
            extract_semantic_fields(p_df, "purchase"),
            extract_semantic_fields(t_df, "tds"),
            extract_semantic_fields(g_df, "gstr2b")
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred during AI column mapping: {e}")

    # --- 3. Analysis -> Calculation -> Summarization ---
    vendor_findings = analyze_vendor_data(mapped_purchase_df)
    tds_findings = analyze_tds_data(mapped_tds_df)
    gst_findings = analyze_gst_data(mapped_purchase_df, mapped_gstr2b_df)
    
    vendor_summary_data = calculate_vendor_totals(vendor_findings)
    tds_summary_data = calculate_tds_totals(tds_findings)
    gst_summary_data = calculate_gst_totals(gst_findings)
    
    vendor_summary, tds_summary, gst_summary = await asyncio.gather(
        generate_summary(vendor_summary_data, "Vendor & Payment Risks"),
        generate_summary(tds_summary_data, "TDS Compliance Risks"),
        generate_summary(gst_summary_data, "GST Compliance & ITC Reconciliation")
    )
    
    # --- 4. Render PDF Report ---
    try:
        template = env.get_template("report_template.html")
    except Exception:
        raise HTTPException(status_code=500, detail="Could not load report template. Ensure 'templates/report_template.html' exists.")
        
    html_out = await template.render_async(
        company_name=company_name, report_date=datetime.now().strftime("%d %B %Y"), audit_period="Q2 2024-25",
        vendor_summary=vendor_summary, gst_summary=gst_summary, tds_summary=tds_summary,
        vendor_findings=vendor_findings, gst_findings=gst_findings, tds_findings=tds_findings
    )
    pdf_bytes = HTML(string=html_out).write_pdf()

    return StreamingResponse(io.BytesIO(pdf_bytes), media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{company_name}_Audit_Report.pdf"'})