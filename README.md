# AI Audit Copilot

**AI-powered financial audit automation that detects errors, saves time, and reduces compliance risks**

[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-2CA5E0?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

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
