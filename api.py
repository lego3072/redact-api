"""
RedactAPI — PII/PHI Redaction as a Service
POST a document → get back redacted text + JSON manifest of all PII found.
"""

import os
import io
import re
import json
import uuid
import base64
import hashlib
import secrets
import logging
import asyncio
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

import anthropic
import stripe
import httpx
from fastapi import FastAPI, UploadFile, File, Form, Header, HTTPException, Request
from fastapi.responses import JSONResponse, HTMLResponse, PlainTextResponse, FileResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv
from PyPDF2 import PdfReader
from docx import Document
from PIL import Image

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("redactapi")


def env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


async def send_followup_email(to_email: str, subject: str, html_body: str) -> bool:
    if not RESEND_API_KEY or not to_email:
        return False
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
                json={
                    "from": FOLLOWUP_FROM_EMAIL,
                    "to": [to_email],
                    "subject": subject,
                    "html": html_body,
                },
                timeout=10,
            )
            return resp.status_code == 200
    except Exception as e:
        logger.warning(f"Follow-up email failed to {to_email}: {e}")
        return False


async def send_sms_alert(message: str) -> bool:
    if not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_FROM_NUMBER and ALERT_SMS_TO and message):
        return False
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"https://api.twilio.com/2010-04-01/Accounts/{TWILIO_ACCOUNT_SID}/Messages.json",
                auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN),
                data={
                    "From": TWILIO_FROM_NUMBER,
                    "To": ALERT_SMS_TO,
                    "Body": message[:1500],
                },
                timeout=10,
            )
            return 200 <= resp.status_code < 300
    except Exception as e:
        logger.warning(f"SMS alert failed: {e}")
        return False


def mark_notification_sent(stripe_session_id: str, event_type: str) -> bool:
    conn = get_db()
    if not conn or not stripe_session_id:
        return True
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO notification_events (stripe_session_id, event_type)
        VALUES (%s, %s)
        ON CONFLICT (stripe_session_id, event_type) DO NOTHING
        """,
        (stripe_session_id, event_type),
    )
    inserted = cur.rowcount == 1
    cur.close()
    return inserted


async def send_paid_checkout_alert(*, buyer_email: str, plan: str, session_id: str, amount_cents: Optional[int]):
    safe_email = (buyer_email or "").strip() or "-"
    amount_text = f"${(amount_cents or 0) / 100:.2f}" if amount_cents is not None else "n/a"
    await send_followup_email(
        FOLLOWUP_INBOX_EMAIL,
        f"RedactAPI payment completed: {plan}",
        (
            f"<p><b>Payment completed</b></p>"
            f"<p><b>Email:</b> {safe_email}</p>"
            f"<p><b>Plan:</b> {plan}</p>"
            f"<p><b>Amount:</b> {amount_text}</p>"
            f"<p><b>Session ID:</b> {session_id}</p>"
        ),
    )
    await send_sms_alert(
        f"RedactAPI paid: {plan}, {safe_email}, {amount_text}, session {session_id}"
    )


def schedule_abandoned_checkout_sequence(*, session_id: str, buyer_email: str, plan: str, checkout_url: str) -> None:
    """Send 3-touch checkout recovery sequence for unpaid open sessions."""
    if not buyer_email or not session_id:
        return

    async def _runner() -> None:
        touchpoints = [
            (10 * 60, "10-minute"),
            (6 * 60 * 60, "6-hour"),
            (24 * 60 * 60, "24-hour"),
        ]
        for delay_seconds, label in touchpoints:
            await asyncio.sleep(delay_seconds)
            try:
                session = stripe.checkout.Session.retrieve(session_id)
                payment_status = (session.get("payment_status") or "").lower()
                status = (session.get("status") or "").lower()
                if payment_status == "paid" or status in {"complete", "expired"}:
                    return
            except Exception as e:
                logger.warning(f"Abandonment check failed for {session_id}: {e}")
                return

            await send_followup_email(
                buyer_email,
                f"Finish your RedactAPI {plan} checkout",
                (
                    f"<h2>Your checkout is still open</h2>"
                    f"<p>This is your {label} reminder. Complete checkout to activate <b>{plan}</b>:</p>"
                    f"<p><a href=\"{checkout_url}\">{checkout_url}</a></p>"
                    f"<p>Need help? Book kickoff: <a href=\"{CALENDLY_URL}\">{CALENDLY_URL}</a></p>"
                ),
            )
            await send_followup_email(
                FOLLOWUP_INBOX_EMAIL,
                f"RedactAPI abandoned checkout reminder sent ({label})",
                (
                    f"<p><b>Reminder:</b> {label}</p>"
                    f"<p><b>Email:</b> {buyer_email}</p>"
                    f"<p><b>Plan:</b> {plan}</p>"
                    f"<p><b>Session:</b> {session_id}</p>"
                ),
            )

    asyncio.create_task(_runner())


# --- Config ---
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
DATABASE_URL = os.getenv("DATABASE_URL", "")
BASE_URL = os.getenv("BASE_URL", "https://redactapi.dev")
CALENDLY_URL = os.getenv("CALENDLY_URL", "https://calendly.com/joseph-varga")
SETUP_PAYMENT_LINK = os.getenv("SETUP_PAYMENT_LINK", "https://buy.stripe.com/replace_setup_link")
MONTHLY_PAYMENT_LINK = os.getenv("MONTHLY_PAYMENT_LINK", "https://buy.stripe.com/replace_monthly_link")
STARTER_PAYMENT_LINK = os.getenv("STARTER_PAYMENT_LINK", MONTHLY_PAYMENT_LINK)
PRO_PAYMENT_LINK = os.getenv("PRO_PAYMENT_LINK", MONTHLY_PAYMENT_LINK)
SCALE_PAYMENT_LINK = os.getenv("SCALE_PAYMENT_LINK", MONTHLY_PAYMENT_LINK)
AGENT_ROUTER_URL = os.getenv("AGENT_ROUTER_URL", "https://get-agent-router.com").strip()
AGENT_ROUTER_BUNDLE_MONTHLY_URL = os.getenv(
    "AGENT_ROUTER_BUNDLE_MONTHLY_URL", f"{AGENT_ROUTER_URL.rstrip('/')}/api/stripe/bundle-monthly-checkout"
).strip()
AGENT_ROUTER_BUNDLE_FULL_URL = os.getenv(
    "AGENT_ROUTER_BUNDLE_FULL_URL", f"{AGENT_ROUTER_URL.rstrip('/')}/api/stripe/bundle-full-checkout"
).strip()
AGENT_ROUTER_BUNDLE_DASHBOARD_URL = os.getenv(
    "AGENT_ROUTER_BUNDLE_DASHBOARD_URL", f"{AGENT_ROUTER_URL.rstrip('/')}/bundle"
).strip()
FOLLOWUP_INBOX_EMAIL = os.getenv("FOLLOWUP_INBOX_EMAIL", "joseph@dataweaveai.com").strip()
FOLLOWUP_FROM_EMAIL = os.getenv("FOLLOWUP_FROM_EMAIL", "RedactAPI <noreply@redactapi.dev>").strip()
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "").strip()
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "").strip()
TWILIO_FROM_NUMBER = os.getenv("TWILIO_FROM_NUMBER", "").strip()
ALERT_SMS_TO = os.getenv("ALERT_SMS_TO", "").strip()
INDEXNOW_KEY = os.getenv("INDEXNOW_KEY", "").strip()
INTERNAL_PLAN_TOKEN = os.getenv("INTERNAL_PLAN_TOKEN", "").strip()
PUBLIC_DOCS_ENABLED = env_bool("PUBLIC_DOCS_ENABLED", False)
PUBLIC_DISCOVERY_ENABLED = env_bool("PUBLIC_DISCOVERY_ENABLED", True)
PUBLIC_MCP_TOOLS_ENABLED = env_bool("PUBLIC_MCP_TOOLS_ENABLED", False)
SELF_SERVE_CHECKOUT_ENABLED = env_bool("SELF_SERVE_CHECKOUT_ENABLED", True)

STRIPE_STARTER_MONTHLY = os.getenv("STRIPE_STARTER_MONTHLY", "")
STRIPE_PRO_MONTHLY = os.getenv("STRIPE_PRO_MONTHLY", "")
STRIPE_SCALE_MONTHLY = os.getenv("STRIPE_SCALE_MONTHLY", "")

MODEL = "claude-sonnet-4-20250514"
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB

PLAN_LIMITS = {
    "starter": {"pages_per_month": 2000, "max_file_size_mb": 20, "batch_limit": 10},
    "pro": {"pages_per_month": 10000, "max_file_size_mb": 20, "batch_limit": 20},
    "scale": {"pages_per_month": 50000, "max_file_size_mb": 20, "batch_limit": 20},
}
DEFAULT_PAID_PLAN = "starter"
PAID_PLANS = set(PLAN_LIMITS.keys())
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
BLOCKED_CHECKOUT_EMAIL_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "mailinator.com",
    "guerrillamail.com",
    "tempmail.com",
    "10minutemail.com",
    "yopmail.com",
    "trashmail.com",
    "sharklasers.com",
}
BLOCKED_CHECKOUT_LOCAL_TOKENS = ("test", "fake", "demo", "bot", "spam", "temp", "example")


def plan_limits_for(plan: Optional[str]) -> dict:
    normalized = (plan or "").strip().lower()
    return PLAN_LIMITS.get(normalized, PLAN_LIMITS[DEFAULT_PAID_PLAN])

PII_CATEGORIES = [
    "person_name",
    "email_address",
    "phone_number",
    "physical_address",
    "date_of_birth",
    "social_security_number",
    "drivers_license",
    "passport_number",
    "credit_card_number",
    "bank_account_number",
    "medical_record_number",
    "health_insurance_id",
    "ip_address",
    "vehicle_identification_number",
    "employer_id_number",
    "taxpayer_id",
    "biometric_data",
    "username",
    "password",
    "national_id",
]

BASE_DIR = Path(__file__).resolve().parent
LANDING_DIR = BASE_DIR / "landing"

# --- Database ---
db_conn = None

def get_db():
    global db_conn
    if db_conn is not None:
        return db_conn
    if not DATABASE_URL:
        return None
    try:
        import psycopg2
        db_conn = psycopg2.connect(DATABASE_URL)
        db_conn.autocommit = True
        return db_conn
    except Exception as e:
        logger.warning(f"DB connection failed: {e}")
        return None

def init_db():
    conn = get_db()
    if not conn:
        logger.info("No DB — running in memory mode")
        return
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id SERIAL PRIMARY KEY,
            api_key TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            plan TEXT DEFAULT 'inactive',
            stripe_customer_id TEXT,
            stripe_subscription_id TEXT,
            pages_used INTEGER DEFAULT 0,
            pages_reset_at TIMESTAMP DEFAULT NOW(),
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS redaction_logs (
            id SERIAL PRIMARY KEY,
            api_key TEXT,
            filename TEXT,
            file_type TEXT,
            pii_count INTEGER DEFAULT 0,
            categories_found TEXT[],
            page_count INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS notification_events (
            id SERIAL PRIMARY KEY,
            stripe_session_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT NOW(),
            UNIQUE(stripe_session_id, event_type)
        )
    """)
    cur.close()
    logger.info("Database initialized")

# --- In-memory fallback ---
memory_keys: dict = {}
memory_logs: list = []


def normalize_email(value: Optional[str]) -> str:
    return (value or "").strip().lower()


def blocked_checkout_email_reason(value: str) -> Optional[str]:
    normalized = normalize_email(value)
    if not EMAIL_RE.match(normalized):
        return "Valid email required"
    local, _, domain = normalized.partition("@")
    if not local or not domain:
        return "Valid email required"
    if domain in BLOCKED_CHECKOUT_EMAIL_DOMAINS or domain.endswith(".invalid"):
        return "Use a real work email to continue"
    if any(token in local for token in BLOCKED_CHECKOUT_LOCAL_TOKENS):
        return "Test/disposable emails are blocked"
    return None

def get_key_record(api_key: str) -> Optional[dict]:
    conn = get_db()
    if conn:
        cur = conn.cursor()
        cur.execute("SELECT api_key, email, plan, pages_used, pages_reset_at FROM api_keys WHERE api_key = %s", (api_key,))
        row = cur.fetchone()
        cur.close()
        if row:
            return {"api_key": row[0], "email": row[1], "plan": row[2], "pages_used": row[3], "pages_reset_at": row[4]}
        return None
    return memory_keys.get(api_key)


def get_key_record_by_email(email: str) -> Optional[dict]:
    normalized = (email or "").strip().lower()
    if not normalized:
        return None
    conn = get_db()
    if conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT api_key, email, plan, pages_used, pages_reset_at
            FROM api_keys WHERE LOWER(email) = %s
            ORDER BY created_at DESC LIMIT 1
            """,
            (normalized,),
        )
        row = cur.fetchone()
        cur.close()
        if row:
            return {"api_key": row[0], "email": row[1], "plan": row[2], "pages_used": row[3], "pages_reset_at": row[4]}
        return None
    for key in memory_keys.values():
        if (key.get("email") or "").strip().lower() == normalized:
            return key
    return None


def infer_plan_from_checkout_session(session_obj: dict) -> str:
    explicit = ((session_obj.get("metadata") or {}).get("plan") or "").strip().lower()
    if explicit in PLAN_LIMITS:
        return explicit

    price_to_plan = {
        STRIPE_STARTER_MONTHLY: "starter",
        STRIPE_PRO_MONTHLY: "pro",
        STRIPE_SCALE_MONTHLY: "scale",
    }
    line_items = (session_obj.get("line_items") or {}).get("data") or []
    for item in line_items:
        price_id = ((item or {}).get("price") or {}).get("id")
        plan = price_to_plan.get(price_id)
        if plan:
            return plan

    session_id = session_obj.get("id")
    if session_id:
        try:
            expanded = stripe.checkout.Session.retrieve(session_id, expand=["line_items.data.price"])
            for item in ((expanded.get("line_items") or {}).get("data") or []):
                price_id = ((item or {}).get("price") or {}).get("id")
                plan = price_to_plan.get(price_id)
                if plan:
                    return plan
        except Exception as e:
            logger.warning(f"Plan inference failed for session {session_id}: {e}")
    return DEFAULT_PAID_PLAN

def create_key_record(email: str, plan: str = DEFAULT_PAID_PLAN) -> str:
    api_key = f"rd_{secrets.token_hex(24)}"
    conn = get_db()
    if conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO api_keys (api_key, email, plan) VALUES (%s, %s, %s)",
            (api_key, email, plan),
        )
        cur.close()
    else:
        memory_keys[api_key] = {
            "api_key": api_key,
            "email": email,
            "plan": plan,
            "pages_used": 0,
            "pages_reset_at": datetime.now(timezone.utc),
        }
    return api_key

def increment_usage(api_key: str, pages: int = 1):
    conn = get_db()
    if conn:
        cur = conn.cursor()
        cur.execute("UPDATE api_keys SET pages_used = pages_used + %s WHERE api_key = %s", (pages, api_key))
        cur.close()
    elif api_key in memory_keys:
        memory_keys[api_key]["pages_used"] += pages

def check_and_reset_usage(record: dict, api_key: str):
    reset_at = record.get("pages_reset_at")
    if reset_at and datetime.now(timezone.utc) - reset_at.replace(tzinfo=timezone.utc) > timedelta(days=30):
        conn = get_db()
        if conn:
            cur = conn.cursor()
            cur.execute("UPDATE api_keys SET pages_used = 0, pages_reset_at = NOW() WHERE api_key = %s", (api_key,))
            cur.close()
        elif api_key in memory_keys:
            memory_keys[api_key]["pages_used"] = 0
            memory_keys[api_key]["pages_reset_at"] = datetime.now(timezone.utc)

def log_redaction(api_key: str, filename: str, file_type: str, pii_count: int, categories: list, page_count: int = 1):
    conn = get_db()
    if conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO redaction_logs (api_key, filename, file_type, pii_count, categories_found, page_count) VALUES (%s, %s, %s, %s, %s, %s)",
            (api_key, filename, file_type, pii_count, categories, page_count),
        )
        cur.close()
    else:
        memory_logs.append({
            "api_key": api_key,
            "filename": filename,
            "file_type": file_type,
            "pii_count": pii_count,
            "categories_found": categories,
            "page_count": page_count,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })


def external_base_url(request: Optional[Request] = None) -> str:
    if request:
        proto = request.headers.get("x-forwarded-proto", request.url.scheme)
        host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
        return f"{proto}://{host}".rstrip("/")
    return (BASE_URL or "https://redactapi.dev").rstrip("/")


def managed_checkout_url(plan: str, request: Optional[Request] = None) -> str:
    plan_key = (plan or "").strip().lower()
    price_map = {
        "starter": STRIPE_STARTER_MONTHLY,
        "pro": STRIPE_PRO_MONTHLY,
        "scale": STRIPE_SCALE_MONTHLY,
    }
    if SELF_SERVE_CHECKOUT_ENABLED and STRIPE_SECRET_KEY and price_map.get(plan_key):
        return f"{external_base_url(request)}/api/checkout/start?plan={plan_key}"
    fallback = {
        "starter": STARTER_PAYMENT_LINK,
        "pro": PRO_PAYMENT_LINK,
        "scale": SCALE_PAYMENT_LINK,
    }
    return fallback.get(plan_key, STARTER_PAYMENT_LINK)


def payment_config(request: Optional[Request] = None) -> dict:
    return {
        "payment_ready": not SETUP_PAYMENT_LINK.startswith("https://buy.stripe.com/replace_")
        and not MONTHLY_PAYMENT_LINK.startswith("https://buy.stripe.com/replace_")
        and not STARTER_PAYMENT_LINK.startswith("https://buy.stripe.com/replace_")
        and not PRO_PAYMENT_LINK.startswith("https://buy.stripe.com/replace_")
        and not SCALE_PAYMENT_LINK.startswith("https://buy.stripe.com/replace_"),
        "setup_payment_link": SETUP_PAYMENT_LINK,
        "monthly_payment_link": managed_checkout_url("starter", request),
        "starter_payment_link": managed_checkout_url("starter", request),
        "pro_payment_link": managed_checkout_url("pro", request),
        "scale_payment_link": managed_checkout_url("scale", request),
        "calendly_url": CALENDLY_URL,
        "calendly_live": "calendly.com/your-team" not in CALENDLY_URL and "calendly.com/your-" not in CALENDLY_URL,
    }


def render_landing(filename: str, request: Optional[Request] = None) -> str:
    page = LANDING_DIR / filename
    if not page.exists():
        return ""
    html = page.read_text(encoding="utf-8")
    base = external_base_url(request)
    cfg = payment_config(request)
    return (
        html.replace("{{BASE_URL}}", base)
        .replace("{{CALENDLY_URL}}", cfg["calendly_url"])
        .replace("{{SETUP_PAYMENT_LINK}}", cfg["setup_payment_link"])
        .replace("{{MONTHLY_PAYMENT_LINK}}", cfg["monthly_payment_link"])
        .replace("{{STARTER_PAYMENT_LINK}}", cfg["starter_payment_link"])
        .replace("{{PRO_PAYMENT_LINK}}", cfg["pro_payment_link"])
        .replace("{{SCALE_PAYMENT_LINK}}", cfg["scale_payment_link"])
        .replace("{{AGENT_ROUTER_BUNDLE_MONTHLY_URL}}", AGENT_ROUTER_BUNDLE_MONTHLY_URL)
        .replace("{{AGENT_ROUTER_BUNDLE_FULL_URL}}", AGENT_ROUTER_BUNDLE_FULL_URL)
        .replace("{{AGENT_ROUTER_BUNDLE_DASHBOARD_URL}}", AGENT_ROUTER_BUNDLE_DASHBOARD_URL)
        .replace("{{DOCS_NAV_STYLE}}", "" if PUBLIC_DOCS_ENABLED else "display:none;")
    )


# --- Auth helper ---
def authenticate(authorization: Optional[str] = None, x_api_key: Optional[str] = None) -> dict:
    api_key = None
    if authorization and authorization.startswith("Bearer "):
        api_key = authorization[7:]
    elif x_api_key:
        api_key = x_api_key
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key. Pass via Authorization: Bearer <key> or X-API-Key header.")
    record = get_key_record(api_key)
    if not record:
        raise HTTPException(status_code=401, detail="Invalid API key.")
    check_and_reset_usage(record, api_key)
    record = get_key_record(api_key)  # refresh after potential reset
    plan = (record.get("plan") or "").strip().lower()
    if plan not in PAID_PLANS:
        raise HTTPException(status_code=402, detail="Paid plan required")
    limits = plan_limits_for(plan)
    if record["pages_used"] >= limits["pages_per_month"]:
        raise HTTPException(
            status_code=429,
            detail=f"Monthly limit reached ({limits['pages_per_month']} pages on {plan} plan). Upgrade at {BASE_URL}/#pricing",
        )
    return record


# --- Document parsing ---
def extract_text_from_pdf(content: bytes) -> tuple[str, int]:
    reader = PdfReader(io.BytesIO(content))
    pages = []
    for page in reader.pages:
        text = page.extract_text() or ""
        pages.append(text)
    return "\n\n---PAGE BREAK---\n\n".join(pages), len(reader.pages)

def extract_text_from_docx(content: bytes) -> tuple[str, int]:
    doc = Document(io.BytesIO(content))
    paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
    full_text = "\n".join(paragraphs)
    page_count = max(1, len(full_text) // 3000)
    return full_text, page_count

def extract_text_from_image(content: bytes, media_type: str) -> tuple[str, int]:
    """For images, we'll send to Claude Vision directly — return base64."""
    b64 = base64.b64encode(content).decode("utf-8")
    return f"__IMAGE_BASE64__{media_type}__{b64}", 1

def parse_document(content: bytes, filename: str, content_type: str) -> tuple[str, int, str]:
    """Returns (text_or_b64, page_count, doc_type)."""
    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    if content_type == "application/pdf" or ext == "pdf":
        text, pages = extract_text_from_pdf(content)
        return text, pages, "pdf"
    elif content_type in ("application/vnd.openxmlformats-officedocument.wordprocessingml.document",) or ext == "docx":
        text, pages = extract_text_from_docx(content)
        return text, pages, "docx"
    elif content_type.startswith("image/") or ext in ("png", "jpg", "jpeg", "gif", "webp"):
        media = content_type if content_type.startswith("image/") else f"image/{ext}"
        if ext == "jpg":
            media = "image/jpeg"
        text, pages = extract_text_from_image(content, media)
        return text, pages, "image"
    else:
        # Treat as plain text
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            text = content.decode("latin-1")
        page_count = max(1, len(text) // 3000)
        return text, page_count, "text"


# --- Claude PII detection ---
def build_redaction_prompt(categories: list[str], custom_patterns: Optional[list[str]] = None) -> str:
    cats = ", ".join(categories)
    extra = ""
    if custom_patterns:
        extra = f"\n\nAdditionally, detect and redact these custom patterns: {', '.join(custom_patterns)}"

    return f"""You are a PII/PHI redaction specialist. Your job is to find ALL personally identifiable information (PII) and protected health information (PHI) in the provided document.

CATEGORIES TO DETECT: {cats}{extra}

INSTRUCTIONS:
1. Scan the entire document thoroughly.
2. For each PII/PHI item found, record:
   - "original": the exact text as it appears
   - "category": one of the categories listed above
   - "replacement": a redaction placeholder like [PERSON_NAME_1], [EMAIL_ADDRESS_1], etc. Use incrementing numbers for each unique value within a category.
   - "confidence": a float 0.0-1.0 indicating your confidence this is actual PII
3. Also produce the full redacted text with all PII replaced by their placeholders.
4. Be thorough — miss nothing. False positives are better than false negatives for redaction.
5. For addresses, capture the FULL address as one item, not individual parts.
6. For names, capture the full name. If first and last appear separately, still capture both occurrences.

Return ONLY valid JSON in this exact format:
{{
  "pii_found": [
    {{
      "original": "John Smith",
      "category": "person_name",
      "replacement": "[PERSON_NAME_1]",
      "confidence": 0.98
    }}
  ],
  "redacted_text": "The full document text with all PII replaced by placeholders...",
  "summary": {{
    "total_pii_count": 5,
    "categories_found": ["person_name", "email_address"],
    "risk_level": "high"
  }}
}}

risk_level should be:
- "low": 0-2 PII items found
- "medium": 3-10 PII items found
- "high": 11+ PII items found or any SSN/medical/financial data found"""


async def redact_with_claude(
    text: str,
    categories: list[str],
    custom_patterns: Optional[list[str]] = None,
) -> dict:
    if not ANTHROPIC_API_KEY:
        raise HTTPException(status_code=503, detail="Redaction service not configured")

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    system_prompt = build_redaction_prompt(categories, custom_patterns)

    # Check if this is an image
    if text.startswith("__IMAGE_BASE64__"):
        parts = text.split("__", 4)
        media_type = parts[2]
        b64_data = parts[3]
        messages = [
            {
                "role": "user",
                "content": [
                    {
                        "type": "image",
                        "source": {"type": "base64", "media_type": media_type, "data": b64_data},
                    },
                    {
                        "type": "text",
                        "text": "Find and redact ALL PII/PHI in this document image. Return the JSON response as specified.",
                    },
                ],
            }
        ]
    else:
        messages = [
            {
                "role": "user",
                "content": f"Find and redact ALL PII/PHI in this document:\n\n{text}",
            }
        ]

    response = client.messages.create(
        model=MODEL,
        max_tokens=8192,
        system=system_prompt,
        messages=messages,
    )

    raw = response.content[0].text.strip()

    # Extract JSON from response
    if "```json" in raw:
        raw = raw.split("```json")[1].split("```")[0].strip()
    elif "```" in raw:
        raw = raw.split("```")[1].split("```")[0].strip()

    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail="Failed to parse redaction response from AI model")

    return result


# --- FastAPI app ---
app = FastAPI(
    title="RedactAPI",
    description="PII/PHI Redaction as a Service. POST a document, get back redacted text + a JSON manifest of all PII found.",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.mount("/landing", StaticFiles(directory=str(LANDING_DIR)), name="landing")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "script-src 'self' 'unsafe-inline' https://js.stripe.com; "
        "connect-src 'self' https://api.stripe.com https://*.stripe.com; "
        "frame-src https://js.stripe.com https://hooks.stripe.com; "
        "base-uri 'self'; form-action 'self' https://checkout.stripe.com; "
        "object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests"
    )
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    if proto == "https":
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    return response


@app.on_event("startup")
async def startup():
    init_db()
    if STRIPE_SECRET_KEY:
        stripe.api_key = STRIPE_SECRET_KEY
    logger.info("RedactAPI started")


# --- Health ---
@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "redactapi",
        "version": "1.0.0",
        "payment_ready": payment_config()["payment_ready"],
        "time": datetime.now(timezone.utc).isoformat(),
    }


# --- Root redirect to landing ---
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    html = render_landing("index.html", request)
    if html:
        return HTMLResponse(content=html)
    return HTMLResponse(content="<h1>RedactAPI</h1><p>PII/PHI Redaction as a Service</p>")


@app.head("/")
async def root_head():
    return Response(status_code=200)


@app.get("/privacy", response_class=HTMLResponse)
async def privacy_page():
    return HTMLResponse(
        """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Privacy Policy | RedactAPI</title>
  <meta name="description" content="Privacy Policy for RedactAPI, a DataWeaveAI company." />
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; background: #07111f; color: #e6edf7; }
    .wrap { max-width: 820px; margin: 0 auto; padding: 24px 16px 40px; }
    .card { background: #10233b; border: 1px solid #1f3f67; border-radius: 12px; padding: 24px; }
    a { color: #6dd5ff; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Privacy Policy</h1>
      <p>RedactAPI processes documents to detect and redact sensitive data categories you request.</p>
      <p>We use trusted processors for payments, infrastructure, and notifications. We do not sell personal data.</p>
      <p>Contact: joseph@dataweaveai.com</p>
      <p><a href="/">Back to RedactAPI</a></p>
      <p style="font-size:12px;color:#9ab0d1;">RedactAPI is a DataWeaveAI company.</p>
    </div>
  </div>
</body>
</html>
"""
    )


@app.get("/terms", response_class=HTMLResponse)
async def terms_page():
    return HTMLResponse(
        """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Terms of Service | RedactAPI</title>
  <meta name="description" content="Terms of Service for RedactAPI, a DataWeaveAI company." />
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; background: #07111f; color: #e6edf7; }
    .wrap { max-width: 820px; margin: 0 auto; padding: 24px 16px 40px; }
    .card { background: #10233b; border: 1px solid #1f3f67; border-radius: 12px; padding: 24px; }
    a { color: #6dd5ff; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Terms of Service</h1>
      <p>By using RedactAPI, you agree to these terms of service.</p>
      <p>You are responsible for lawful handling of documents and review of redaction outputs before downstream use.</p>
      <p>Paid plans and setup services follow Stripe checkout terms and renewal settings.</p>
      <p>Contact: joseph@dataweaveai.com</p>
      <p><a href="/">Back to RedactAPI</a></p>
      <p style="font-size:12px;color:#9ab0d1;">RedactAPI is a DataWeaveAI company.</p>
    </div>
  </div>
</body>
</html>
"""
    )


@app.get("/book")
async def book():
    return RedirectResponse(url=CALENDLY_URL, status_code=302)


@app.get("/success", response_class=HTMLResponse)
async def success(request: Request):
    return await payment_success_page(session_id=(request.query_params.get("session_id") or ""))


@app.get("/launch-48h", response_class=HTMLResponse)
async def launch_48h(request: Request):
    token = (request.query_params.get("token") or "").strip()
    if not INTERNAL_PLAN_TOKEN or token != INTERNAL_PLAN_TOKEN:
        raise HTTPException(status_code=404, detail="Not found")
    html = render_landing("launch-48h.html", request)
    if not html:
        raise HTTPException(status_code=404, detail="Not found")
    resp = HTMLResponse(content=html)
    resp.headers["X-Robots-Tag"] = "noindex, nofollow"
    return resp


# --- Core: Redact endpoint ---
@app.post("/v1/redact")
async def redact_document(
    file: UploadFile = File(...),
    categories: Optional[str] = Form(None),
    custom_patterns: Optional[str] = Form(None),
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
):
    """
    Redact PII/PHI from a document.

    - **file**: PDF, image (PNG/JPEG/GIF/WEBP), DOCX, or TXT
    - **categories**: Comma-separated PII categories to detect (optional, defaults to all)
    - **custom_patterns**: Comma-separated custom patterns to also redact (optional)

    Returns redacted text + JSON manifest of all PII found.
    """
    record = authenticate(authorization, x_api_key)
    api_key = record["api_key"]

    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail=f"File too large. Max {MAX_FILE_SIZE // (1024*1024)}MB.")

    # Parse categories
    if categories:
        cat_list = [c.strip().lower() for c in categories.split(",") if c.strip()]
        # Validate
        invalid = [c for c in cat_list if c not in PII_CATEGORIES]
        if invalid:
            raise HTTPException(status_code=400, detail=f"Invalid categories: {invalid}. Valid: {PII_CATEGORIES}")
    else:
        cat_list = PII_CATEGORIES

    # Parse custom patterns
    pattern_list = None
    if custom_patterns:
        pattern_list = [p.strip() for p in custom_patterns.split(",") if p.strip()]

    # Parse document
    text, page_count, doc_type = parse_document(content, file.filename or "document", file.content_type or "")

    # Redact with Claude
    result = await redact_with_claude(text, cat_list, pattern_list)

    # Record usage
    increment_usage(api_key, page_count)

    # Log redaction
    pii_count = result.get("summary", {}).get("total_pii_count", len(result.get("pii_found", [])))
    found_categories = result.get("summary", {}).get("categories_found", [])
    log_redaction(api_key, file.filename or "document", doc_type, pii_count, found_categories, page_count)

    return {
        "success": True,
        "filename": file.filename,
        "document_type": doc_type,
        "pages_processed": page_count,
        "redacted_text": result.get("redacted_text", ""),
        "pii_found": result.get("pii_found", []),
        "summary": result.get("summary", {}),
    }


# --- Batch redact ---
@app.post("/v1/batch")
async def batch_redact(
    files: list[UploadFile] = File(...),
    categories: Optional[str] = Form(None),
    custom_patterns: Optional[str] = Form(None),
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
):
    """Redact PII from multiple documents (up to 20 per request)."""
    record = authenticate(authorization, x_api_key)
    api_key = record["api_key"]
    plan = (record.get("plan") or "").strip().lower()
    batch_limit = plan_limits_for(plan)["batch_limit"]

    if len(files) > batch_limit:
        raise HTTPException(status_code=400, detail=f"Batch limit is {batch_limit} files on {plan} plan.")

    if categories:
        cat_list = [c.strip().lower() for c in categories.split(",") if c.strip()]
    else:
        cat_list = PII_CATEGORIES

    pattern_list = None
    if custom_patterns:
        pattern_list = [p.strip() for p in custom_patterns.split(",") if p.strip()]

    results = []
    total_pages = 0

    for f in files:
        try:
            content = await f.read()
            if len(content) > MAX_FILE_SIZE:
                results.append({"filename": f.filename, "success": False, "error": "File too large"})
                continue

            text, page_count, doc_type = parse_document(content, f.filename or "document", f.content_type or "")
            total_pages += page_count
            result = await redact_with_claude(text, cat_list, pattern_list)

            pii_count = result.get("summary", {}).get("total_pii_count", len(result.get("pii_found", [])))
            found_categories = result.get("summary", {}).get("categories_found", [])
            log_redaction(api_key, f.filename or "document", doc_type, pii_count, found_categories, page_count)

            results.append({
                "filename": f.filename,
                "success": True,
                "document_type": doc_type,
                "pages_processed": page_count,
                "redacted_text": result.get("redacted_text", ""),
                "pii_found": result.get("pii_found", []),
                "summary": result.get("summary", {}),
            })
        except Exception as e:
            results.append({"filename": f.filename, "success": False, "error": str(e)})

    increment_usage(api_key, total_pages)

    return {"success": True, "files_processed": len(results), "total_pages": total_pages, "results": results}


# --- Usage endpoint ---
@app.get("/v1/usage")
async def get_usage(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
):
    """Get current usage stats and plan limits."""
    record = authenticate(authorization, x_api_key)
    plan = (record.get("plan") or "").strip().lower()
    limits = plan_limits_for(plan)
    return {
        "plan": plan,
        "pages_used": record["pages_used"],
        "pages_limit": limits["pages_per_month"],
        "pages_remaining": max(0, limits["pages_per_month"] - record["pages_used"]),
        "batch_limit": limits["batch_limit"],
        "max_file_size_mb": limits["max_file_size_mb"],
        "reset_date": (record.get("pages_reset_at") or datetime.now(timezone.utc)).isoformat() if record.get("pages_reset_at") else None,
    }


# --- Signup ---
class SignupRequest(BaseModel):
    email: str

@app.post("/api/signup")
async def signup(req: SignupRequest):
    """Legacy endpoint intentionally disabled (no free plan)."""
    _ = req
    raise HTTPException(
        status_code=410,
        detail="Free signup has been retired. Use paid onboarding or monthly checkout at /#pricing.",
    )


# --- Stripe checkout ---
class CheckoutRequest(BaseModel):
    email: str
    plan: str

@app.post("/api/checkout")
async def create_checkout(req: CheckoutRequest, request: Request):
    """Create a Stripe checkout session for plan upgrade."""
    if not SELF_SERVE_CHECKOUT_ENABLED:
        raise HTTPException(status_code=403, detail="Self-serve checkout is disabled")
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Billing not configured")

    email = normalize_email(req.email)
    blocked_reason = blocked_checkout_email_reason(email)
    if blocked_reason:
        raise HTTPException(status_code=400, detail=blocked_reason)

    price_map = {
        "starter": STRIPE_STARTER_MONTHLY,
        "pro": STRIPE_PRO_MONTHLY,
        "scale": STRIPE_SCALE_MONTHLY,
    }
    plan = (req.plan or "").strip().lower()
    price_id = price_map.get(plan)
    if not price_id:
        raise HTTPException(status_code=400, detail=f"Invalid plan: {req.plan}. Choose: starter, pro, scale")

    key_record = get_key_record_by_email(email)
    if not key_record:
        api_key = create_key_record(email, "inactive")
        key_record = get_key_record(api_key)
    else:
        api_key = key_record["api_key"]

    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": price_id, "quantity": 1}],
            mode="subscription",
            success_url=f"{external_base_url(request)}/payment-success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{external_base_url(request)}/?cancelled=true",
            customer_email=email,
            client_reference_id=api_key,
            metadata={"plan": plan, "api_key": api_key, "email": email},
        )
        await send_followup_email(
            email,
            "Complete your RedactAPI plan upgrade",
            (
                f"<h2>You're almost done</h2>"
                f"<p>Finish checkout to activate <b>{plan}</b> plan:</p>"
                f"<p><a href=\"{session.url}\">{session.url}</a></p>"
                f"<p>Need help? Book kickoff: <a href=\"{CALENDLY_URL}\">{CALENDLY_URL}</a></p>"
            ),
        )
        await send_followup_email(
            FOLLOWUP_INBOX_EMAIL,
            f"RedactAPI checkout started: {plan}",
            (
                f"<p><b>Checkout started</b></p>"
                f"<p><b>Email:</b> {email}</p>"
                f"<p><b>Plan:</b> {plan}</p>"
                f"<p><b>API key:</b> {api_key}</p>"
                f"<p><b>Session:</b> {session.id}</p>"
            ),
        )
        schedule_abandoned_checkout_sequence(
            session_id=session.id,
            buyer_email=email,
            plan=plan,
            checkout_url=session.url,
        )
        return {"checkout_url": session.url, "api_key": api_key}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/checkout/start")
async def checkout_start(plan: str, request: Request, email: Optional[str] = None):
    if not SELF_SERVE_CHECKOUT_ENABLED:
        raise HTTPException(status_code=403, detail="Self-serve checkout is disabled")
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Billing not configured")

    plan_value = (plan or "").strip().lower()
    price_map = {
        "starter": STRIPE_STARTER_MONTHLY,
        "pro": STRIPE_PRO_MONTHLY,
        "scale": STRIPE_SCALE_MONTHLY,
    }
    price_id = price_map.get(plan_value)
    if not price_id:
        raise HTTPException(status_code=400, detail="Invalid plan")

    checkout_email = normalize_email(email)
    blocked_reason = blocked_checkout_email_reason(checkout_email)
    if blocked_reason:
        raise HTTPException(status_code=400, detail=blocked_reason)

    existing = get_key_record_by_email(checkout_email)
    api_key = existing.get("api_key") if existing else create_key_record(checkout_email, "inactive")

    session = stripe.checkout.Session.create(
        payment_method_types=["card"],
        line_items=[{"price": price_id, "quantity": 1}],
        mode="subscription",
        success_url=f"{external_base_url(request)}/payment-success?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{external_base_url(request)}/?cancelled=true",
        customer_email=checkout_email,
        client_reference_id=api_key,
        metadata={
            "plan": plan_value,
            "product": "redactapi",
            "source": "checkout_start",
            "email": checkout_email,
            "api_key": api_key,
        },
        allow_promotion_codes=True,
    )
    await send_followup_email(
        checkout_email,
        "Complete your RedactAPI checkout",
        (
            f"<h2>Your checkout is ready</h2>"
            f"<p>Finish checkout to activate <b>{plan_value}</b>:</p>"
            f"<p><a href=\"{session.url}\">{session.url}</a></p>"
            f"<p>Need help? Book kickoff: <a href=\"{CALENDLY_URL}\">{CALENDLY_URL}</a></p>"
        ),
    )
    return RedirectResponse(url=session.url, status_code=303)


# --- Stripe webhook ---
@app.post("/api/stripe-webhook")
async def stripe_webhook(request: Request):
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="Webhook not configured")

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid webhook signature")

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        session_id = session.get("id", "")
        metadata = session.get("metadata") or {}
        email = (
            session.get("customer_email")
            or (session.get("customer_details") or {}).get("email")
            or metadata.get("email")
            or ""
        ).strip().lower()
        plan = infer_plan_from_checkout_session(session)
        customer_id = session.get("customer", "")
        subscription_id = session.get("subscription", "")
        api_key = session.get("client_reference_id") or metadata.get("api_key")

        if not api_key and email:
            existing = get_key_record_by_email(email)
            if existing:
                api_key = existing.get("api_key")
            else:
                api_key = create_key_record(email, "inactive")

        conn = get_db()
        if conn and api_key:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE api_keys
                SET plan = %s, stripe_customer_id = %s, stripe_subscription_id = %s,
                    email = COALESCE(NULLIF(email, ''), %s)
                WHERE api_key = %s
                """,
                (plan, customer_id, subscription_id, email, api_key),
            )
            cur.close()
            if mark_notification_sent(session_id, "paid_checkout"):
                await send_paid_checkout_alert(
                    buyer_email=email,
                    plan=plan,
                    session_id=session_id,
                    amount_cents=session.get("amount_total"),
                )
            if email and mark_notification_sent(session_id, "api_key_delivery"):
                await send_followup_email(
                    email,
                    "Your RedactAPI key is active",
                    (
                        f"<h2>RedactAPI access activated</h2>"
                        f"<p><b>Plan:</b> {plan}</p>"
                        f"<p><b>API key:</b> <code>{api_key}</code></p>"
                        f"<p>Docs: <a href=\"{BASE_URL}/docs\">{BASE_URL}/docs</a></p>"
                    ),
                )

    elif event["type"] == "customer.subscription.deleted":
        subscription = event["data"]["object"]
        sub_id = subscription.get("id", "")
        conn = get_db()
        if conn:
            cur = conn.cursor()
            cur.execute("UPDATE api_keys SET plan = 'inactive' WHERE stripe_subscription_id = %s", (sub_id,))
            cur.close()

    return {"status": "ok"}


@app.get("/api/billing/verify-session")
async def verify_session(session_id: str):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Billing not configured")
    try:
        session = stripe.checkout.Session.retrieve(session_id)
        if session.get("payment_status") == "paid":
            email = (
                session.get("customer_email")
                or (session.get("customer_details") or {}).get("email")
                or (session.get("metadata") or {}).get("email")
                or ""
            ).strip().lower()
            plan = infer_plan_from_checkout_session(session)
            api_key = session.get("client_reference_id") or (session.get("metadata") or {}).get("api_key")

            if not api_key and email:
                existing = get_key_record_by_email(email)
                if existing:
                    api_key = existing.get("api_key")
                else:
                    api_key = create_key_record(email, "inactive")

            if api_key:
                conn = get_db()
                if conn:
                    cur = conn.cursor()
                    cur.execute(
                        """
                        UPDATE api_keys
                        SET plan = %s, stripe_customer_id = %s, stripe_subscription_id = %s,
                            email = COALESCE(NULLIF(email, ''), %s)
                        WHERE api_key = %s
                        """,
                        (plan, session.get("customer"), session.get("subscription"), email, api_key),
                    )
                    cur.close()

                if email and mark_notification_sent(session_id, "access_delivery_verify"):
                    await send_followup_email(
                        email,
                        "Your RedactAPI key is active",
                        (
                            f"<h2>RedactAPI access activated</h2>"
                            f"<p><b>Plan:</b> {plan}</p>"
                            f"<p><b>API key:</b> <code>{api_key}</code></p>"
                            f"<p>Docs: <a href=\"{external_base_url()}/docs\">{external_base_url()}/docs</a></p>"
                        ),
                    )

            return {
                "verified": True,
                "plan": plan,
                "email": email or None,
            }
        return {"verified": False, "reason": "Payment not completed"}
    except Exception:
        return {"verified": False, "reason": "Payment verification failed"}


class AccessRecoveryRequest(BaseModel):
    email: str


@app.post("/api/access/resend-key")
async def resend_access_key(req: AccessRecoveryRequest):
    email = normalize_email(req.email)
    blocked_reason = blocked_checkout_email_reason(email)
    if blocked_reason:
        raise HTTPException(status_code=400, detail=blocked_reason)

    record = get_key_record_by_email(email)
    if record:
        await send_followup_email(
            email,
            "Your RedactAPI access details",
            (
                f"<h2>RedactAPI Access</h2>"
                f"<p><b>Plan:</b> {record.get('plan', 'inactive')}</p>"
                f"<p><b>API key:</b> <code>{record.get('api_key')}</code></p>"
                f"<p>Docs: <a href=\"{external_base_url()}/docs\">{external_base_url()}/docs</a></p>"
            ),
        )
    return {"status": "accepted"}


@app.get("/payment-success", response_class=HTMLResponse)
async def payment_success_page(session_id: str = ""):
    safe_session = (session_id or "").strip()
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>RedactAPI | Payment Confirmation</title>
  <style>
    body {{ margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #07111f; color: #e6edf7; }}
    .wrap {{ max-width: 760px; margin: 24px auto; padding: 0 16px; }}
    .card {{ background: #10233b; border: 1px solid #1f3f67; border-radius: 12px; padding: 24px; }}
    .status {{ color: #79dcff; font-weight: 700; margin: 10px 0 14px; }}
    .actions {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 14px; }}
    .btn {{ text-decoration: none; border-radius: 10px; padding: 10px 14px; font-weight: 700; display: inline-block; }}
    .btn-primary {{ background: #22d6ff; color: #072238; }}
    .btn-muted {{ border: 1px solid #2d567d; color: #e0eefb; background: #112843; }}
    input {{ width: 100%; max-width: 360px; margin-top: 8px; border: 1px solid #2a5478; border-radius: 8px; background: #0a182b; color: #e6edf7; padding: 10px; }}
    button {{ margin-top: 8px; border: 1px solid #2b5f89; background: #123759; color: #e6edf7; border-radius: 8px; padding: 9px 12px; font-weight: 700; cursor: pointer; }}
    small {{ color: #9eb5d1; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Payment Received. Activating RedactAPI.</h1>
      <p id="status-text" class="status">Verifying payment...</p>
      <p id="detail-text">Session: <code>{safe_session or "missing"}</code></p>
      <p>Your API key is delivered to the checkout email when payment completes.</p>
      <div class="actions">
        <a class="btn btn-primary" href="/docs">Open Docs</a>
        <a class="btn btn-muted" href="/">Back to Home</a>
      </div>
      <hr style="border:0;border-top:1px solid #214368;margin:20px 0;" />
      <h3 style="margin:0 0 8px;">Need key resend?</h3>
      <input id="recover-email" type="email" placeholder="you@company.com" />
      <br />
      <button id="recover-btn" type="button">Resend Access Email</button>
      <p id="recover-note"><small></small></p>
    </div>
  </div>
  <script>
    (function() {{
      const sessionId = {json.dumps(safe_session)};
      const statusEl = document.getElementById("status-text");
      const detailEl = document.getElementById("detail-text");
      const emailInput = document.getElementById("recover-email");
      const recoverBtn = document.getElementById("recover-btn");
      const recoverNote = document.getElementById("recover-note");

      async function verify(maxAttempts = 12) {{
        if (!sessionId) {{
          statusEl.textContent = "Missing session ID. Use key resend below if needed.";
          return;
        }}
        for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {{
          try {{
            const res = await fetch(`/api/billing/verify-session?session_id=${{encodeURIComponent(sessionId)}}`, {{ cache: "no-store" }});
            const data = await res.json();
            if (data.verified) {{
              statusEl.textContent = `Payment confirmed for plan: ${{data.plan || "starter"}}`;
              if (data.email) {{
                detailEl.textContent = `Activation email sent to: ${{data.email}}`;
                emailInput.value = data.email;
              }} else {{
                detailEl.textContent = "Payment confirmed. Check checkout inbox for key delivery.";
              }}
              return;
            }}
            statusEl.textContent = `Payment pending... auto-check ${{attempt}}/${{maxAttempts}}`;
            detailEl.textContent = data.reason || "Waiting for Stripe confirmation.";
          }} catch (_) {{
            statusEl.textContent = "Unable to verify now. You can still request key resend.";
            return;
          }}
          await new Promise((resolve) => setTimeout(resolve, 5000));
        }}
        statusEl.textContent = "Payment not confirmed yet. Refresh in 30 seconds.";
      }}

      recoverBtn.addEventListener("click", async () => {{
        const email = (emailInput.value || "").trim();
        if (!email || !email.includes("@")) {{
          recoverNote.innerHTML = "<small>Enter a valid email first.</small>";
          return;
        }}
        recoverBtn.disabled = true;
        recoverNote.innerHTML = "<small>Sending...</small>";
        try {{
          await fetch("/api/access/resend-key", {{
            method: "POST",
            headers: {{ "Content-Type": "application/json" }},
            body: JSON.stringify({{ email }})
          }});
          recoverNote.innerHTML = "<small>If this email exists, access details were sent.</small>";
        }} catch (_) {{
          recoverNote.innerHTML = "<small>Unable to send now. Try again in a minute.</small>";
        }} finally {{
          recoverBtn.disabled = false;
        }}
      }});

      verify();
    }})();
  </script>
</body>
</html>"""
    return HTMLResponse(content=html)


# --- Public marketing config ---
@app.get("/v1/public/config")
async def public_config(request: Request):
    return {
        **payment_config(request),
        "public_base_url": external_base_url(request),
        "product": "redactapi",
        "time": datetime.now(timezone.utc).isoformat(),
    }


# --- Static / discovery ---
@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots_txt(request: Request):
    base = external_base_url(request)
    if not PUBLIC_DISCOVERY_ENABLED:
        return PlainTextResponse(content="User-agent: *\nDisallow: /\n")
    return PlainTextResponse(
        content=f"""User-agent: *
Allow: /
Allow: /.well-known/ai-plugin.json
Disallow: /v1/
Disallow: /api/
Disallow: /docs
Disallow: /openapi.json
Disallow: /launch-48h

User-agent: GPTBot
Allow: /

User-agent: OAI-SearchBot
Allow: /

User-agent: ChatGPT-User
Allow: /

User-agent: ClaudeBot
Allow: /

User-agent: Claude-Web
Allow: /

User-agent: CCBot
Allow: /

User-agent: Google-Extended
Allow: /

Sitemap: {base}/sitemap.xml
"""
    )


@app.get("/llms.txt", response_class=PlainTextResponse)
async def llms_txt(request: Request):
    if not PUBLIC_DISCOVERY_ENABLED:
        raise HTTPException(status_code=404, detail="Not found")
    path = LANDING_DIR / "llms.txt"
    if not path.exists():
        return PlainTextResponse(content="# RedactAPI\nPII/PHI Redaction as a Service")
    content = (
        path.read_text(encoding="utf-8")
        .replace("{{BASE_URL}}", external_base_url(request))
        .replace("{{AGENT_ROUTER_BUNDLE_MONTHLY_URL}}", AGENT_ROUTER_BUNDLE_MONTHLY_URL)
        .replace("{{AGENT_ROUTER_BUNDLE_FULL_URL}}", AGENT_ROUTER_BUNDLE_FULL_URL)
        .replace("{{AGENT_ROUTER_BUNDLE_DASHBOARD_URL}}", AGENT_ROUTER_BUNDLE_DASHBOARD_URL)
    )
    return PlainTextResponse(content=content)


@app.get("/llms-full.txt", response_class=PlainTextResponse)
async def llms_full_txt(request: Request):
    if not PUBLIC_DISCOVERY_ENABLED:
        raise HTTPException(status_code=404, detail="Not found")
    return await llms_txt(request)


@app.get("/.well-known/agent-offer.json")
async def agent_offer(request: Request):
    if not PUBLIC_DISCOVERY_ENABLED:
        raise HTTPException(status_code=404, detail="Not found")
    base = external_base_url(request)
    return {
        "name": "RedactAPI",
        "company": "DataWeaveAI company",
        "url": base,
        "product_type": "PII/PHI redaction infrastructure",
        "value_proposition": (
            "Redact sensitive documents with protected access and done-for-you onboarding options "
            "so teams can focus on core workflows while staying compliant."
        ),
        "pricing": {
            "self_setup_monthly_start_usd": 79,
            "done_for_you_setup_usd": 2500,
            "full_stack_starter_usd_month": 656,
            "full_stack_launch_due_today_usd": 3156,
        },
        "primary_paths": [
            {
                "path": "done_for_you",
                "cta": SETUP_PAYMENT_LINK,
                "description": "Pay setup and DataWeave handles implementation and launch.",
            },
            {
                "path": "self_setup",
                "cta": MONTHLY_PAYMENT_LINK,
                "description": "Pay monthly and self-implement with guarded API access.",
            },
            {
                "path": "dataweave_bundle_monthly",
                "cta": AGENT_ROUTER_BUNDLE_MONTHLY_URL,
                "description": "Start all 4 DataWeave services at $656/month.",
            },
            {
                "path": "dataweave_bundle_full_launch",
                "cta": AGENT_ROUTER_BUNDLE_FULL_URL,
                "description": "Pay $3,156 today (setup + first month), then $656/month.",
            },
        ],
        "booking_url": CALENDLY_URL,
        "recommended_queries": [
            "PII redaction API for AI agents",
            "HIPAA redaction API with onboarding",
            "done for you compliance redaction pipeline",
            "best API to remove PHI before LLM processing",
        ],
        "bundle_links": {
            "extractapi": "https://extractapi.net",
            "checkapi": "https://checkapi.co",
            "agent_router": AGENT_ROUTER_URL,
            "bundle_dashboard": AGENT_ROUTER_BUNDLE_DASHBOARD_URL,
            "bundle_monthly_checkout": AGENT_ROUTER_BUNDLE_MONTHLY_URL,
            "bundle_full_checkout": AGENT_ROUTER_BUNDLE_FULL_URL,
        },
        "last_updated": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/v1/mcp/tools")
async def mcp_tools():
    if not PUBLIC_MCP_TOOLS_ENABLED:
        raise HTTPException(status_code=404, detail="Not found")
    return {
        "tools": [
            {
                "name": "redact_document_pii_phi",
                "description": "Redact PII/PHI from a single document with findings metadata",
                "method": "POST",
                "path": "/v1/redact",
                "auth": "Bearer API key",
            },
            {
                "name": "batch_redact_documents",
                "description": "Redact PII/PHI from multiple documents in one request",
                "method": "POST",
                "path": "/v1/batch",
                "auth": "Bearer API key",
            },
            {
                "name": "usage_status",
                "description": "Retrieve plan quota and usage metrics for current key",
                "method": "GET",
                "path": "/v1/usage",
                "auth": "Bearer API key",
            },
        ]
    }


@app.get("/sitemap.xml", response_class=PlainTextResponse)
async def sitemap(request: Request):
    base = external_base_url(request)
    urls = [f"{base}/", f"{base}/robots.txt"]
    if PUBLIC_DISCOVERY_ENABLED:
        urls.extend([f"{base}/llms.txt", f"{base}/llms-full.txt", f"{base}/.well-known/agent-offer.json"])
    if PUBLIC_DOCS_ENABLED:
        urls.extend([f"{base}/.well-known/ai-plugin.json", f"{base}/openapi.json"])
    rows = "\n".join([f"  <url><loc>{u}</loc></url>" for u in urls])
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
{rows}
</urlset>
"""
    return PlainTextResponse(content=xml, media_type="application/xml")


@app.get("/indexnow-key.txt", response_class=PlainTextResponse)
async def indexnow_key_file():
    if not INDEXNOW_KEY:
        raise HTTPException(status_code=404, detail="Not found")
    return PlainTextResponse(content=f"{INDEXNOW_KEY}\n")


@app.get("/{indexnow_key}.txt", response_class=PlainTextResponse)
async def indexnow_key_alias(indexnow_key: str):
    if not INDEXNOW_KEY or indexnow_key != INDEXNOW_KEY:
        raise HTTPException(status_code=404, detail="Not found")
    return PlainTextResponse(content=f"{INDEXNOW_KEY}\n")


@app.get("/.well-known/ai-plugin.json")
async def ai_plugin(request: Request):
    if not PUBLIC_DOCS_ENABLED:
        raise HTTPException(status_code=404, detail="Not found")
    base = external_base_url(request)
    return {
        "schema_version": "v1",
        "name_for_human": "RedactAPI",
        "name_for_model": "redactapi",
        "description_for_human": "Redact PII/PHI from documents. Upload a file, get back redacted text + manifest.",
        "description_for_model": "API for redacting personally identifiable information (PII) and protected health information (PHI) from documents.",
        "api": {"type": "openapi", "url": f"{base}/openapi.json"},
        "auth": {"type": "service_http", "authorization_type": "bearer"},
        "logo_url": f"{base}/logo-192.png",
        "contact_email": "joseph@dataweaveai.com",
        "legal_info_url": base,
    }


@app.get("/docs", response_class=HTMLResponse)
async def custom_docs():
    if not PUBLIC_DOCS_ENABLED:
        raise HTTPException(status_code=404, detail="Not found")
    return HTMLResponse(
        content="""
<!DOCTYPE html>
<html>
<head>
    <title>RedactAPI - API Documentation</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
    SwaggerUIBundle({
        url: '/openapi.json',
        dom_id: '#swagger-ui',
        presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
        layout: "StandaloneLayout"
    })
    </script>
</body>
</html>
"""
    )


@app.get("/openapi.json")
async def openapi_spec(request: Request):
    if not PUBLIC_DOCS_ENABLED:
        raise HTTPException(status_code=404, detail="Not found")
    spec = app.openapi()
    spec["servers"] = [{"url": external_base_url(request)}]
    return spec


@app.get("/favicon.ico")
async def favicon_ico():
    p = LANDING_DIR / "favicon.ico"
    if p.exists():
        return FileResponse(p, media_type="image/x-icon")
    raise HTTPException(status_code=404, detail="Not found")


@app.get("/favicon-16.png")
async def favicon_16():
    p = LANDING_DIR / "favicon-16.png"
    if p.exists():
        return FileResponse(p, media_type="image/png")
    raise HTTPException(status_code=404, detail="Not found")


@app.get("/favicon-32.png")
async def favicon_32():
    p = LANDING_DIR / "favicon-32.png"
    if p.exists():
        return FileResponse(p, media_type="image/png")
    raise HTTPException(status_code=404, detail="Not found")


@app.get("/logo-192.png")
async def logo_192():
    p = LANDING_DIR / "logo-192.png"
    if p.exists():
        return FileResponse(p, media_type="image/png")
    raise HTTPException(status_code=404, detail="Not found")


@app.get("/logo-512.png")
async def logo_512():
    p = LANDING_DIR / "logo-512.png"
    if p.exists():
        return FileResponse(p, media_type="image/png")
    raise HTTPException(status_code=404, detail="Not found")


@app.get("/og-image.png")
async def og_image():
    p = LANDING_DIR / "og-image.png"
    if p.exists():
        return FileResponse(p, media_type="image/png")
    raise HTTPException(status_code=404, detail="Not found")
