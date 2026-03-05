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
from datetime import datetime, timezone, timedelta
from typing import Optional

import anthropic
import stripe
import httpx
from fastapi import FastAPI, UploadFile, File, Form, Header, HTTPException, Request
from fastapi.responses import JSONResponse, HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from dotenv import load_dotenv
from PyPDF2 import PdfReader
from docx import Document
from PIL import Image

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("redactapi")

# --- Config ---
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
DATABASE_URL = os.getenv("DATABASE_URL", "")
BASE_URL = os.getenv("BASE_URL", "https://redactapi.dev")

STRIPE_STARTER_MONTHLY = os.getenv("STRIPE_STARTER_MONTHLY", "")
STRIPE_PRO_MONTHLY = os.getenv("STRIPE_PRO_MONTHLY", "")
STRIPE_SCALE_MONTHLY = os.getenv("STRIPE_SCALE_MONTHLY", "")

MODEL = "claude-sonnet-4-20250514"
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB

PLAN_LIMITS = {
    "free": {"pages_per_month": 50, "max_file_size_mb": 10, "batch_limit": 5},
    "starter": {"pages_per_month": 2000, "max_file_size_mb": 20, "batch_limit": 10},
    "pro": {"pages_per_month": 10000, "max_file_size_mb": 20, "batch_limit": 20},
    "scale": {"pages_per_month": 50000, "max_file_size_mb": 20, "batch_limit": 20},
}

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
            plan TEXT DEFAULT 'free',
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
    cur.close()
    logger.info("Database initialized")

# --- In-memory fallback ---
memory_keys: dict = {}
memory_logs: list = []

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

def create_key_record(email: str, plan: str = "free") -> str:
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
    plan = record.get("plan", "free")
    limits = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])
    if record["pages_used"] >= limits["pages_per_month"]:
        raise HTTPException(
            status_code=429,
            detail=f"Monthly limit reached ({limits['pages_per_month']} pages on {plan} plan). Upgrade at {BASE_URL}/docs",
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
)

app.mount("/landing", StaticFiles(directory="landing"), name="landing")


@app.on_event("startup")
async def startup():
    init_db()
    if STRIPE_SECRET_KEY:
        stripe.api_key = STRIPE_SECRET_KEY
    logger.info("RedactAPI started")


# --- Health ---
@app.get("/health")
async def health():
    return {"status": "ok", "service": "redactapi", "version": "1.0.0"}


# --- Root redirect to landing ---
@app.get("/", response_class=HTMLResponse)
async def root():
    try:
        with open("landing/index.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>RedactAPI</h1><p>PII/PHI Redaction as a Service</p>")


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
    plan = record.get("plan", "free")
    batch_limit = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])["batch_limit"]

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
    plan = record.get("plan", "free")
    limits = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])
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
    """Get a free API key."""
    email = req.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Valid email required")

    # Check if already exists
    conn = get_db()
    if conn:
        cur = conn.cursor()
        cur.execute("SELECT api_key FROM api_keys WHERE email = %s", (email,))
        existing = cur.fetchone()
        cur.close()
        if existing:
            return {"api_key": existing[0], "message": "API key already exists for this email."}

    api_key = create_key_record(email)

    # Send welcome email
    if RESEND_API_KEY:
        try:
            async with httpx.AsyncClient() as client:
                await client.post(
                    "https://api.resend.com/emails",
                    headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
                    json={
                        "from": f"RedactAPI <noreply@{BASE_URL.replace('https://', '').replace('http://', '')}>",
                        "to": [email],
                        "subject": "Your RedactAPI Key",
                        "html": f"""
                        <h2>Welcome to RedactAPI</h2>
                        <p>Your API key: <code>{api_key}</code></p>
                        <p>You have 50 free pages/month. Get started:</p>
                        <pre>curl -X POST {BASE_URL}/v1/redact \\
  -H "Authorization: Bearer {api_key}" \\
  -F "file=@document.pdf"</pre>
                        <p><a href="{BASE_URL}/docs">Full API docs →</a></p>
                        """,
                    },
                )
        except Exception as e:
            logger.warning(f"Failed to send welcome email: {e}")

    return {"api_key": api_key, "plan": "free", "pages_per_month": 50}


# --- Stripe checkout ---
class CheckoutRequest(BaseModel):
    email: str
    plan: str

@app.post("/api/checkout")
async def create_checkout(req: CheckoutRequest):
    """Create a Stripe checkout session for plan upgrade."""
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Billing not configured")

    price_map = {
        "starter": STRIPE_STARTER_MONTHLY,
        "pro": STRIPE_PRO_MONTHLY,
        "scale": STRIPE_SCALE_MONTHLY,
    }
    price_id = price_map.get(req.plan)
    if not price_id:
        raise HTTPException(status_code=400, detail=f"Invalid plan: {req.plan}. Choose: starter, pro, scale")

    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": price_id, "quantity": 1}],
            mode="subscription",
            success_url=f"{BASE_URL}/?upgraded=true",
            cancel_url=f"{BASE_URL}/?cancelled=true",
            customer_email=req.email,
            metadata={"plan": req.plan},
        )
        return {"checkout_url": session.url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
        email = session.get("customer_email", "")
        plan = session.get("metadata", {}).get("plan", "starter")
        customer_id = session.get("customer", "")
        subscription_id = session.get("subscription", "")

        conn = get_db()
        if conn and email:
            cur = conn.cursor()
            cur.execute(
                "UPDATE api_keys SET plan = %s, stripe_customer_id = %s, stripe_subscription_id = %s WHERE email = %s",
                (plan, customer_id, subscription_id, email),
            )
            cur.close()

    elif event["type"] == "customer.subscription.deleted":
        subscription = event["data"]["object"]
        sub_id = subscription.get("id", "")
        conn = get_db()
        if conn:
            cur = conn.cursor()
            cur.execute("UPDATE api_keys SET plan = 'free' WHERE stripe_subscription_id = %s", (sub_id,))
            cur.close()

    return {"status": "ok"}


# --- Static files ---
@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots_txt():
    return f"""User-agent: *
Allow: /

Sitemap: {BASE_URL}/sitemap.xml

# AI / LLM agents
User-agent: GPTBot
Allow: /

User-agent: Claude-Web
Allow: /

User-agent: Applebot-Extended
Allow: /

User-agent: anthropic-ai
Allow: /

User-agent: CCBot
Allow: /

User-agent: Google-Extended
Allow: /
"""


@app.get("/llms.txt", response_class=PlainTextResponse)
async def llms_txt():
    try:
        with open("landing/llms.txt", "r") as f:
            return PlainTextResponse(content=f.read())
    except FileNotFoundError:
        return PlainTextResponse(content="# RedactAPI\nPII/PHI Redaction as a Service")


@app.get("/.well-known/ai-plugin.json")
async def ai_plugin():
    return {
        "schema_version": "v1",
        "name_for_human": "RedactAPI",
        "name_for_model": "redactapi",
        "description_for_human": "Redact PII/PHI from documents. Upload a file, get back redacted text + manifest.",
        "description_for_model": "API for redacting personally identifiable information (PII) and protected health information (PHI) from documents. Accepts PDF, images, DOCX, TXT. Returns redacted text and a JSON manifest of all PII found with categories and confidence scores.",
        "api": {"type": "openapi", "url": f"{BASE_URL}/openapi.json"},
        "auth": {"type": "service_http", "authorization_type": "bearer"},
        "logo_url": f"{BASE_URL}/logo.png",
        "contact_email": "support@redactapi.dev",
        "legal_info_url": f"{BASE_URL}/terms",
    }


# --- OpenAPI customization ---
@app.get("/docs", response_class=HTMLResponse)
async def custom_docs():
    return HTMLResponse(content=f"""
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
        SwaggerUIBundle({{
            url: '/openapi.json',
            dom_id: '#swagger-ui',
            presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
            layout: "StandaloneLayout"
        }})
        </script>
    </body>
    </html>
    """)
