# AI Audit Copilot

**Agentic AI-powered financial audit automation that detects errors, saves time, and reduces compliance risks**

[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-2CA5E0?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

It ingests financial transaction data from multiple sources, reconciles them, and **uncovers hidden errors** in minutes — replacing hours of manual work by finance teams.

Built with **FastAPI**, **Razorpay payments**, **LLM-powered analysis**, and **automated PDF reporting**.

---

## 🚀 Key Features


- **🔐 Authentication**
  - JWT-based login/signup
  - Password reset with email (Resend integration)

- **💳 Payments**
  - Razorpay integration for subscription & pay-per-audit
  - Access control based on verified payments

- **📂 File Handling & Analysis**
  - Upload CSV/Excel files
  - Auto column mapping with LLM
  - Data type normalization & validation

- **🧠 Agentic Audit System**
  - Vendor spend analysis
  - TDS/GST reconciliation
  - Invoice quality check
  - Payment pattern analysis
  - Duplicate detection
  - Findings automatically persisted in DB

- **📊 Reporting**
  - PDF report generation via Jinja2 + WeasyPrint
  - Secure Supabase storage & public link sharing
  - Excel export of audit findings

- **📈 Dashboard APIs**
  - Audit history
  - Detailed findings
  - Export audit results

- **👨‍💻 Admin Metrics**
  - Track active users, audits, and subscriptions

---

## 🛠️ Tech Stack

- **Backend:** [FastAPI](https://fastapi.tiangolo.com/) + [SQLAlchemy](https://www.sqlalchemy.org/)  
- **Database:** PostgreSQL (via [Supabase](https://supabase.com/))  
- **Auth & Security:** JWT tokens, password hashing (bcrypt)  
- **Payments:** [Razorpay](https://razorpay.com/docs/)  
- **Emailing:** [Resend](https://resend.com/) API  
- **Reports:** [WeasyPrint](https://weasyprint.org/), [Jinja2](https://jinja.palletsprojects.com/)  
- **Data Processing:** [Pandas](https://pandas.pydata.org/), [XlsxWriter](https://xlsxwriter.readthedocs.io/)  
- **AI Agents:** Multi-agent orchestration for auditing logic  
- **Storage:** Supabase Object Storage  


## 📊 How It Works

### 1️⃣ Input
- Upload **Excel or CSV files** containing financial data (purchase registers, GSTR filings, bank statements, TDS ledgers, etc.).

### 2️⃣ Processing
- AI Audit Copilot:
  - Parses and merges datasets
  - Runs reconciliation logic & business rules
  - Applies AI-based anomaly detection
  - Summarizes findings in human-readable format

### 3️⃣ Output
- **PDF Report** — professionally formatted with detected issues & recommendations
- **JSON Response** — structured output for integration into ERPs or BI tools
- **Email Delivery** — sends report to the user’s registered email

---

## 📄 Example Use Case
Scenario: A mid-sized company uploads:

- Purchase register (Excel)

- GSTR-2B filing report (Excel)

- Vendor payment ledger (CSV)

AI Audit Copilot:

- Reconciles purchase vs GSTR data → finds GST mismatches

- Checks TDS calculations → finds underpaid TDS on two vendors

- Flags duplicate vendor payments worth ₹1.2L

- Generates PDF report + email delivery
