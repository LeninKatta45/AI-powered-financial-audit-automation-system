# migration_script.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, joinedload
from models import Base, Audit, AuditFinding
import sys
import json
import os

def migrate_fingerprints():
    DATABASE_URL = os.getenv("DATABASE_URL")
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    db = Session()
    
    try:
        # Eager load the audit relationship to avoid lazy loading issues
        findings = db.query(AuditFinding).options(joinedload(AuditFinding.audit)).all()
        
        for finding in findings:
            try:
                details = json.loads(finding.details)
                fingerprint_parts = [
                    finding.audit.company_name,
                    finding.issue_type,
                    details.get('vendor', ''),
                    details.get('invoice_number', ''),
                    str(details.get('amount', ''))
                ]
                finding.fingerprint = "-".join(filter(None, fingerprint_parts))
            except Exception as e:
                print(f"Error processing finding {finding.id}: {str(e)}")
                continue
        
        db.commit()
        print(f"Successfully migrated {len(findings)} fingerprints")
    except Exception as e:
        db.rollback()
        print(f"Migration failed: {str(e)}")
        sys.exit(1)
    finally:
        db.close()

if __name__ == "__main__":
    migrate_fingerprints()