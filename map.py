from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import JSONResponse
from typing import Optional, List, Dict, Union
import pandas as pd
import io
import json
from pydantic import BaseModel
import asyncio
from tenacity import retry, stop_after_attempt, wait_random_exponential
from litellm import acompletion
import re
import numpy as np

import os

from dotenv import load_dotenv
load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

app = FastAPI()

os.environ["GROQ_API_KEY"] = GROQ_API_KEY

# ==================== MODELS AND CONSTANTS ====================
class FileMappingResult(BaseModel):
    file_type: str
    original_columns: List[str]
    mapped_columns: List[str]
    sample_data: List[Dict]
    engineered_columns: Optional[List[str]] = None
    mapping_logic: Optional[Dict] = None

class ProcessFilesResponse(BaseModel):
    success: bool
    message: str
    results: List[FileMappingResult]

# Complete field description map for all 6 file types
FIELD_DESCRIPTION_MAP = {
    # Purchase Register Fields
    "Invoice_Date": "Date when the invoice was issued",
    "Invoice_Number": "Unique number of the invoice",
    "Vendor_Name": "Name of the vendor",
    "Vendor_GSTIN": "GSTIN of the vendor",
    "Taxable_Value": "Taxable value in the invoice (excluding taxes)",
    "Total_Invoice_Value": "Total value including all taxes and charges",
    "Has_PO": "Whether a PO (purchase order) is attached",
    
    # TDS Ledger Fields
    "Payment_Date": "Date when the payment was made",
    "Amount_Paid": "Amount paid to the vendor",
    "TDS_Section": "Section under which TDS was deducted",
    "TDS_Deducted": "Amount of TDS deducted",

    # GSTR-2B Fields
    "Invoice_Date": "Date when the invoice was issued",
    "Invoice_Number": "Unique number of the invoice",
    "Vendor_GSTIN": "GSTIN of the vendor",
    "Total_Invoice_Value": "Total value including all taxes",
    "Vendor_Name": "Name of the vendor",

    # GSTR-3B Fields
    "Return_Period": "The month/quarter for the GSTR-3B filing",
    "ITC_Available": "Total Input Tax Credit available",
    "ITC_Claimed": "Input Tax Credit actually claimed",
    "Tax_Paid_Cash": "GST liability paid through cash ledger",

    # Vendor Master Fields
    "Vendor_Code": "Internal unique code for the vendor",
    "Vendor_PAN": "Permanent Account Number of the vendor",
    "Vendor_Address": "Registered address of the vendor",
    "Vendor_Bank_Account": "Bank account number of the vendor",

    # Sales Register Fields
    "Customer_Name": "Name of the customer who was billed",
    "Sales_Invoice_Value": "Total value of the sales invoice including tax"
}

# ==================== ENHANCED HELPER FUNCTIONS ====================
async def read_uploaded_file(file: UploadFile) -> pd.DataFrame:
    """Reads uploaded file into DataFrame"""
    if not file.filename:
        raise ValueError("No filename provided")
    
    content = await file.read()
    if not content:
        raise ValueError("Empty file content")
    
    try:
        if file.filename.endswith('.csv'):
            df = pd.read_csv(io.BytesIO(content), keep_default_na=False)
        else:
            df = pd.read_excel(io.BytesIO(content), engine='openpyxl', keep_default_na=False)
        
        # Convert all columns to string first for consistency
        df = df.astype(str)
        return df
    except Exception as e:
        raise ValueError(f"Could not read file: {str(e)}")

def is_valid_upload_file(file) -> bool:
    """Check if the file is a valid UploadFile object"""
    return (file is not None and 
            not isinstance(file, str) and
            hasattr(file, 'filename') and 
            hasattr(file, 'file') and 
            file.filename and 
            file.filename.strip() != "" and
            file.filename != "string")

def safe_numeric_conversion(df: pd.DataFrame, columns: List[str]) -> pd.DataFrame:
    """Safely convert columns to numeric, handling various formats"""
    df_copy = df.copy()
    
    for col in columns:
        if col in df_copy.columns:
            try:
                # Remove common non-numeric characters
                df_copy[col] = df_copy[col].astype(str).str.replace(',', '')
                df_copy[col] = df_copy[col].str.replace('₹', '')
                df_copy[col] = df_copy[col].str.replace('Rs.', '')
                df_copy[col] = df_copy[col].str.replace('Rs', '')
                df_copy[col] = df_copy[col].str.replace('INR', '')
                df_copy[col] = df_copy[col].str.replace('(', '-')
                df_copy[col] = df_copy[col].str.replace(')', '')
                df_copy[col] = df_copy[col].str.strip()
                
                # Convert to numeric
                df_copy[col] = pd.to_numeric(df_copy[col], errors='coerce').fillna(0)
            except Exception as e:
                print(f"Warning: Could not convert {col} to numeric: {e}")
                df_copy[col] = 0
    
    return df_copy

@retry(stop=stop_after_attempt(3), wait=wait_random_exponential(min=1, max=4))
async def direct_column_mapping(columns: list, doc_type: str, sample_data: pd.DataFrame = None) -> dict:
    """
    Stage 1: Context-aware direct column mapping - considers ALL columns together for intelligent mapping
    """
    
    # Define relevant fields for each document type with business context
    doc_type_contexts = {
        "purchase": {
            "fields": ["Invoice_Date", "Invoice_Number", "Vendor_Name", "Vendor_GSTIN", 
                      "Taxable_Value", "Total_Invoice_Value", "Has_PO"],
            "context": """
            Purchase Register Context - Consider ALL columns together:
            - If you see "Amount" + separate tax columns (CGST, SGST, IGST) → "Amount" is likely Taxable_Value
            - If you see "Amount" + "Total Amount" → "Amount" is Taxable_Value, "Total Amount" is Total_Invoice_Value
            - If you see only "Amount" or "Total" without tax breakdown → it's likely Total_Invoice_Value
            - If you see "Basic Amount" + tax columns → "Basic Amount" is Taxable_Value
            - If you see "Net Amount" or "Final Amount" → it's usually Total_Invoice_Value
            - GST columns: CGST, SGST, IGST, UTGST, CESS should NOT be mapped to standard fields
            - Look for invoice identifiers, dates, vendor information
            """
        },
        "tds": {
            "fields": ["Payment_Date", "Vendor_Name", "Amount_Paid", "TDS_Section", "TDS_Deducted"],
            "context": """
            TDS Ledger Context - Consider ALL columns together:
            - Amount_Paid is the gross amount paid to vendor (before TDS deduction)
            - TDS_Deducted is the tax deducted at source
            - If you see "Gross Amount" + "TDS Amount" → Gross is Amount_Paid
            - If you see "Payment Amount" → it's likely Amount_Paid
            - Look for section codes (194A, 194C, etc.) for TDS_Section
            - Payment dates are transaction dates, not invoice dates
            """
        },
        "gstr2b": {
            "fields": ["Invoice_Date", "Invoice_Number", "Vendor_GSTIN", "Total_Invoice_Value", "Vendor_Name"],
            "context": """
            GSTR-2B Context - Consider ALL columns together:
            - This is supplier invoice data from government portal
            - If you see "Invoice Value" alone → it's likely Total_Invoice_Value
            - If you see "Taxable Value" + tax columns → Total_Invoice_Value needs calculation
            - GSTIN format: 15-digit alphanumeric
            - Invoice numbers should be unique identifiers
            """
        },
        "gstr3b": {
            "fields": ["Return_Period", "ITC_Available", "ITC_Claimed", "Tax_Paid_Cash"],
            "context": """
            GSTR-3B Context - Consider ALL columns together:
            - Return summary data, not transaction-level
            - ITC = Input Tax Credit
            - Look for period information (month/quarter)
            - Tax payment methods: Cash, Credit
            """
        },
        "vendor_master": {
            "fields": ["Vendor_Code", "Vendor_Name", "Vendor_GSTIN", "Vendor_PAN", 
                      "Vendor_Address", "Vendor_Bank_Account"],
            "context": """
            Vendor Master Context - Consider ALL columns together:
            - Master data for vendor information
            - Vendor_Code is internal unique identifier
            - PAN format: 10-digit alphanumeric
            - GSTIN format: 15-digit alphanumeric
            - Look for contact and banking information
            """
        },
        "sales_register": {
            "fields": ["Invoice_Date", "Invoice_Number", "Customer_Name", "Sales_Invoice_Value"],
            "context": """
            Sales Register Context - Consider ALL columns together:
            - Customer-facing invoice data
            - Similar to purchase register but for sales
            - If you see "Amount" with tax columns → Amount is taxable value not Sales_Invoice_Value
            - If you see "Amount" without "Tax" → Amount is likely Sales_Invoice_Value
            """
        }
    }
    
    doc_info = doc_type_contexts.get(doc_type, {"fields": [], "context": ""})
    relevant_fields = doc_info["fields"]
    business_context = doc_info["context"]
    
    prompt = f"""You are an expert in Indian accounting and GST compliance. Analyze ALL columns together to make context-aware direct mappings.

Document Type: {doc_type}

{business_context}

Standard Fields to Map:
"""
    
    for field in relevant_fields:
        prompt += f"- {field}: {FIELD_DESCRIPTION_MAP.get(field, 'No description')}\n"
    
    prompt += f"""

ALL AVAILABLE COLUMNS IN FILE (analyze these together):
{chr(10).join([f"- {col}" for col in columns])}

Sample Data (first 3 rows to understand data patterns):
"""
    
    if sample_data is not None and not sample_data.empty:
        sample_dict = sample_data.head(3).to_dict(orient='records')
        prompt += json.dumps(sample_dict, indent=2, default=str)
    
    prompt += """

CRITICAL INSTRUCTIONS - CONTEXT-AWARE MAPPING:
1. ANALYZE ALL COLUMNS TOGETHER - The meaning of each column depends on what other columns exist
2. Use business context to make intelligent decisions:
   - If "Amount" exists with tax columns → "Amount" is likely taxable value
   - If "Amount" exists alone → "Amount" might be total value
   - If "Total Amount" and "Amount" both exist → "Total Amount" is likely the total invoice value
3. Look for patterns in column names and sample data
4. Consider the document type's business purpose
5. Only map columns you are confident about based on the FULL context
6. DO NOT suggest calculations - only direct mappings
7. If context suggests a column could be multiple things, choose the most likely based on other columns

MAPPING DECISION PROCESS:
For each potential mapping, ask:
- What other columns exist that provide context?
- What would this column typically contain given the document type?
- Does the sample data support this mapping?
- Are there other columns that would conflict with this mapping?

Return JSON format:
{
  "direct_mappings": {
    "Standard_Field_Name": "Actual_Column_Name"
  },
  "confidence": {
    "Standard_Field_Name": "high|medium|low"
  },
  "reasoning": {
    "Standard_Field_Name": "Why this mapping was chosen considering all columns"
  }
}

Return ONLY the JSON response."""
    
    try:
        response = await acompletion(
            model="groq/llama3-70b-8192",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            max_tokens=800
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        print(f"Context-aware direct mapping failed: {e}")
        return {"direct_mappings": {}, "confidence": {}, "reasoning": {}}

@retry(stop=stop_after_attempt(3), wait=wait_random_exponential(min=1, max=4))
async def formula_generation(columns: list, doc_type: str, missing_fields: list, sample_data: pd.DataFrame = None) -> dict:
    """
    Stage 2: Generate formulas for missing standard fields
    """
    
    prompt = f"""You are an expert in Indian accounting and GST compliance. Generate formulas to calculate missing standard fields.

Document Type: {doc_type}

Available Columns:
{chr(10).join([f"- {col}" for col in columns])}

Missing Standard Fields to Calculate:
"""
    
    for field in missing_fields:
        prompt += f"- {field}: {FIELD_DESCRIPTION_MAP.get(field, 'No description')}\n"
    
    prompt += f"""
Sample Data (first 3 rows):
"""
    
    if sample_data is not None and not sample_data.empty:
        sample_dict = sample_data.head(3).to_dict(orient='records')
        prompt += json.dumps(sample_dict, indent=2, default=str)
    
    prompt += """

BUSINESS RULES:
- Total_Invoice_Value = Taxable_Value + CGST + SGST + IGST + UTGST + CESS + any other taxes
- If only "Amount" exists without tax breakdown, it might be Total_Invoice_Value
- If "Basic Amount" + tax columns exist, Total_Invoice_Value = Basic Amount + taxes
- GST Rate calculations: CGST + SGST = Total GST (for intra-state), IGST = Total GST (for inter-state)
- Look for discount columns that should be subtracted

INSTRUCTIONS:
1. For each missing field, determine if it can be calculated from available columns
2. Provide clear mathematical formulas
3. Specify which columns to add and which to subtract
4. Only suggest calculations you are confident about

Return JSON format:
{
  "formulas": {
    "Field_Name": {
      "can_calculate": true/false,
      "formula_description": "Human readable formula description",
      "columns_to_add": ["col1", "col2"],
      "columns_to_subtract": ["col3", "col4"],
      "confidence": "high|medium|low"
    }
  }
}

Return ONLY the JSON response."""
    
    try:
        response = await acompletion(
            model="groq/llama3-70b-8192",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            max_tokens=800
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        print(f"Formula generation failed: {e}")
        return {"formulas": {}}

def calculate_field_from_formula(df: pd.DataFrame, field_name: str, formula_info: dict) -> pd.DataFrame:
    """
    Calculate field value using the formula information from LLM
    """
    try:
        columns_to_add = formula_info.get("columns_to_add", [])
        columns_to_subtract = formula_info.get("columns_to_subtract", [])
        
        # Validate that required columns exist
        missing_add_cols = [col for col in columns_to_add if col not in df.columns]
        missing_sub_cols = [col for col in columns_to_subtract if col not in df.columns]
        
        if missing_add_cols:
            raise ValueError(f"Missing required columns for addition: {missing_add_cols}")
        
        # Filter to only existing columns
        existing_add_cols = [col for col in columns_to_add if col in df.columns]
        existing_sub_cols = [col for col in columns_to_subtract if col in df.columns]
        
        if not existing_add_cols:
            raise ValueError("No valid columns found for calculation")
        
        # Create a copy for calculation
        calc_df = df.copy()
        
        # Convert relevant columns to numeric
        all_calc_cols = existing_add_cols + existing_sub_cols
        calc_df = safe_numeric_conversion(calc_df, all_calc_cols)
        
        # Calculate the field
        total_to_add = calc_df[existing_add_cols].sum(axis=1) if existing_add_cols else 0
        total_to_subtract = calc_df[existing_sub_cols].sum(axis=1) if existing_sub_cols else 0
        
        # Perform calculation
        result = total_to_add - total_to_subtract
        
        # Ensure no negative values (business logic)
        result = result.clip(lower=0)
        
        # Add the calculated field back to original dataframe
        df[field_name] = result
        
        print(f"Successfully calculated {field_name} using formula: {formula_info.get('formula_description', '')}")
        return df
        
    except Exception as e:
        raise ValueError(f"Failed to calculate {field_name}: {str(e)}")

async def process_single_file(file: UploadFile, doc_type: str) -> FileMappingResult:
    """
    Processes one file through the enhanced two-stage mapping pipeline
    """
    try:
        # 1. Read file
        df = await read_uploaded_file(file)
        original_columns = list(df.columns)
        engineered_columns = []
        
        print(f"Processing {doc_type} with {len(original_columns)} columns")
        
        # 2. Stage 1: Context-aware direct column mapping
        direct_mapping_result = await direct_column_mapping(original_columns, doc_type, df)
        direct_mappings = direct_mapping_result.get("direct_mappings", {})
        confidence_scores = direct_mapping_result.get("confidence", {})
        mapping_reasoning = direct_mapping_result.get("reasoning", {})
        
        # Filter by confidence (only keep high and medium confidence mappings)
        filtered_mappings = {
            field: col for field, col in direct_mappings.items()
            if confidence_scores.get(field, "low") in ["high", "medium"]
        }
        
        print(f"Context-aware direct mappings found: {filtered_mappings}")
        print(f"Mapping reasoning: {mapping_reasoning}")
        
        # 3. Determine missing fields
        doc_type_fields = {
            "purchase": ["Invoice_Date", "Invoice_Number", "Vendor_Name", "Vendor_GSTIN", 
                        "Taxable_Value", "Total_Invoice_Value", "Has_PO"],
            "tds": ["Payment_Date", "Vendor_Name", "Amount_Paid", "TDS_Section", "TDS_Deducted"],
            "gstr2b": ["Invoice_Date", "Invoice_Number", "Vendor_GSTIN", "Total_Invoice_Value", "Vendor_Name"],
            "gstr3b": ["Return_Period", "ITC_Available", "ITC_Claimed", "Tax_Paid_Cash"],
            "vendor_master": ["Vendor_Code", "Vendor_Name", "Vendor_GSTIN", "Vendor_PAN", 
                             "Vendor_Address", "Vendor_Bank_Account"],
            "sales_register": ["Invoice_Date", "Invoice_Number", "Customer_Name", "Sales_Invoice_Value"]
        }
        
        required_fields = doc_type_fields.get(doc_type, [])
        missing_fields = [field for field in required_fields if field not in filtered_mappings]
        
        print(f"Missing fields: {missing_fields}")
        
        # 4. Stage 2: Generate formulas for missing fields (only if there are missing fields)
        formulas = {}
        if missing_fields:
            formula_result = await formula_generation(original_columns, doc_type, missing_fields, df)
            formulas = formula_result.get("formulas", {})
            
            print(f"Generated formulas: {formulas}")
            
            # 5. Calculate missing fields using formulas
            for field_name, formula_info in formulas.items():
                if (formula_info.get("can_calculate", False) and 
                    formula_info.get("confidence", "low") in ["high", "medium"]):
                    
                    try:
                        df = calculate_field_from_formula(df, field_name, formula_info)
                        filtered_mappings[field_name] = field_name
                        engineered_columns.append(field_name)
                        
                        print(f"Successfully calculated and added {field_name}")
                        
                    except Exception as calc_error:
                        print(f"Failed to calculate {field_name}: {calc_error}")
                        continue
        
        # 6. Final validation
        if not filtered_mappings:
            raise ValueError("No columns could be mapped or calculated")
        
        # 7. Create final mapped dataframe
        # Rename columns based on mappings
        rename_dict = {v: k for k, v in filtered_mappings.items() if v in df.columns}
        mapped_df = df.rename(columns=rename_dict)
        
        # Keep only successfully mapped columns
        final_columns = [k for k, v in filtered_mappings.items() if v in df.columns]
        mapped_df = mapped_df[final_columns]
        
        # 8. Convert numeric columns to proper numeric types for final output
        numeric_fields = ["Taxable_Value", "Total_Invoice_Value", "Amount_Paid", "TDS_Deducted", 
                         "ITC_Available", "ITC_Claimed", "Tax_Paid_Cash", "Sales_Invoice_Value"]
        
        numeric_cols_to_convert = [col for col in final_columns if col in numeric_fields]
        if numeric_cols_to_convert:
            mapped_df = safe_numeric_conversion(mapped_df, numeric_cols_to_convert)
        
        print(f"Final mapped columns: {final_columns}")
        
        return FileMappingResult(
            file_type=doc_type,
            original_columns=original_columns,
            mapped_columns=final_columns,
            sample_data=mapped_df.head(3).to_dict(orient="records"),
            engineered_columns=engineered_columns if engineered_columns else None,
            mapping_logic={
                "direct_mappings": filtered_mappings,
                "formulas_used": formulas,
                "confidence_scores": confidence_scores,
                "mapping_reasoning": mapping_reasoning
            }
        )
        
    except Exception as e:
        raise ValueError(f"Failed to process {doc_type} file: {str(e)}")

# ==================== API ENDPOINT ====================
@app.post("/upload-files/", response_model=ProcessFilesResponse)
async def upload_files(
    purchase_file: UploadFile = File(...),
    tds_file: UploadFile = File(...),
    gstr2b_file: UploadFile = File(...),
    gstr3b_file: Union[UploadFile, str, None] = File(None),
    vendor_master_file: Union[UploadFile, str, None] = File(None),
    sales_register_file: Union[UploadFile, str, None] = File(None)
):
    """
    Enhanced file processing with two-stage LLM approach:
    1. Direct column mapping (high priority)
    2. Formula generation for missing fields
    """
    try:
        # Prepare files to process
        files_to_process = [
            ("purchase", purchase_file),
            ("tds", tds_file),
            ("gstr2b", gstr2b_file)
        ]
        
        # Add optional files
        optional_files = [
            ("gstr3b", gstr3b_file),
            ("vendor_master", vendor_master_file),
            ("sales_register", sales_register_file)
        ]
        
        for doc_type, file in optional_files:
            if is_valid_upload_file(file):
                files_to_process.append((doc_type, file))
        
        # Process all files
        tasks = [process_single_file(file, doc_type) for doc_type, file in files_to_process]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle results
        successful_results = []
        error_messages = []
        
        for idx, result in enumerate(results):
            if isinstance(result, Exception):
                doc_type = files_to_process[idx][0]
                error_messages.append(f"{doc_type}: {str(result)}")
            else:
                successful_results.append(result)
        
        # Return response
        if error_messages:
            return ProcessFilesResponse(
                success=bool(successful_results),
                message="Some files failed: " + "; ".join(error_messages),
                results=successful_results
            )
        
        return ProcessFilesResponse(
            success=True,
            message="All files processed successfully with enhanced two-stage LLM mapping",
            results=successful_results
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"File processing failed: {str(e)}"
        )

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "message": "Enhanced file processing API is running"}

# ==================== RUN THE APP ====================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)