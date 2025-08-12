# AI Audit Copilot (Enviscale)

**AI Audit Copilot** is an enterprise-grade **AI-powered financial audit automation platform**.  
It ingests financial transaction data from multiple sources, reconciles them, and **uncovers hidden errors** in minutes — replacing hours of manual work by finance teams.

Built with **FastAPI**, **Razorpay payments**, **LLM-powered analysis**, and **automated PDF reporting**.

---

## 🚀 Key Features
- **Multi-file reconciliation** — compare & match data from multiple Excel/CSV sources.
- **Error detection** — automatically finds:
  - GST mismatches
  - TDS calculation errors
  - Duplicate transactions
  - Vendor payment anomalies
- **AI-Powered Insights** — uses LLMs to summarize patterns & anomalies in plain English.
- **Automated PDF Reports** — generates professional, shareable audit reports.
- **Secure Authentication** — JWT-based user login/signup.
- **Payment Integration** — Razorpay checkout for paid audits.
- **Email Delivery** — Sends audit reports via Resend API.
- **Dockerized Deployment** — ready for cloud hosting.

---

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

## 🛠️ Tech Stack
- **Backend**: FastAPI, SQLAlchemy, Alembic
- **Database**: PostgreSQL
- **AI**: LLMs via `litellm` (Groq API)
- **Payments**: Razorpay
- **Email**: Resend API
- **File Parsing**: Pandas
- **Reports**: Jinja2 + WeasyPrint
- **Auth**: JWT, OAuth2
- **Deployment**: Docker

---

## 📂 Project Structure
