# scheduler.py
import os
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
import resend

import models # Your SQLAlchemy models
from database import SessionLocal # Your DB session factory

# Load environment variables
load_dotenv()
RESEND_API_KEY = os.getenv("RESEND_API_KEY")
FRONTEND_URL = os.getenv("FRONTEND_URL")
resend.api_key = RESEND_API_KEY

def send_reminder_emails():
    """
    Finds users who haven't run an audit in 30+ days and sends them a reminder.
    """
    db = SessionLocal()
    print(f"[{datetime.now(timezone.utc)}] --- Running Monthly Reminder Job ---")

    try:
        # Find users who have an active subscription
        thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
        
        active_users = db.query(models.User).filter(
            models.User.access_valid_until > datetime.now(timezone.utc)
        ).all()

        users_to_remind = []
        for user in active_users:
            # Find the most recent audit for this user
            latest_audit = db.query(models.Audit).filter(
                models.Audit.user_id == user.id
            ).order_by(models.Audit.timestamp.desc()).first()

            # If they have no audits, or their last audit was over 30 days ago
            if not latest_audit or latest_audit.timestamp < thirty_days_ago:
                users_to_remind.append(user)

        print(f"Found {len(users_to_remind)} users to remind.")

        for user in users_to_remind:
            print(f"Sending reminder to {user.email}...")
            try:
                resend.Emails.send({
                    "from": "support@enviscale.com",
                    "to": user.email,
                    "subject": "Your Monthly Financial Health Check-in from Enviscale",
                    "html": f"""
                        <div style="font-family: Arial, sans-serif; line-height: 1.6;">
                            <h2>Time for your monthly check-in!</h2>
                            <p>Hello,</p>
                            <p>It's been a while since you last ran a diagnostic on Enviscale. Regular financial health checks are key to preventing costly errors and managing risk effectively.</p>
                            <p>Take 5 minutes today to upload your latest ledgers and get an updated view of your company's financial health.</p>
                            <p style="margin: 20px 0;">
                                <a href="{FRONTEND_URL}/audit" style="display: inline-block; padding: 12px 24px; background-color: #4f46e5; color: white; text-decoration: none; border-radius: 8px;">
                                    Run New Audit
                                </a>
                            </p>
                            <p>Stay ahead of compliance and keep your finances secure.</p>
                            <p>Thank you,<br>The Enviscale Team</p>
                        </div>
                    """
                })
                print(f"Successfully sent reminder to {user.email}.")
            except Exception as e:
                print(f"!!! FAILED to send email to {user.email}: {e}")

    finally:
        db.close()

if __name__ == "__main__":
    send_reminder_emails()