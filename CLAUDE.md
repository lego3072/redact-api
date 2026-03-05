# RedactAPI — PII/PHI Redaction as a Service

## Project Overview
API service that redacts personally identifiable information (PII) and protected health information (PHI) from documents. Built with FastAPI + Claude AI.

## Tech Stack
- **Backend**: Python 3.11, FastAPI, Pydantic
- **Frontend**: HTML/CSS/JS in `landing/`
- **AI**: Anthropic Claude API (claude-sonnet-4-20250514)
- **Payments**: Stripe (Starter/Pro/Scale tiers)
- **Email**: Resend API
- **Database**: PostgreSQL (graceful memory-mode fallback)

## Key Files
- `api.py` — Main FastAPI application
- `landing/index.html` — Landing page
- `landing/llms.txt` — LLM discovery file

## Common Commands
```bash
uvicorn api:app --host 0.0.0.0 --port 8000 --reload
```

## Environment Variables
Required in `.env`:
- `ANTHROPIC_API_KEY` — Claude AI
- `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` — Payments
- `RESEND_API_KEY` — Email
- `DATABASE_URL` — PostgreSQL
- `BASE_URL` — Application URL (https://redactapi.dev)

## API Endpoints
- `POST /v1/redact` — Redact PII from single document
- `POST /v1/batch` — Batch redaction (up to 20 files)
- `GET /v1/usage` — Usage stats and quota
- `POST /api/signup` — Get free API key
- `POST /api/checkout` — Stripe checkout for plan upgrade
- `POST /api/stripe-webhook` — Stripe webhook handler
- `GET /health` — Health check
- `GET /docs` — Swagger UI
- `GET /robots.txt` — SEO robots file
- `GET /llms.txt` — LLM discovery
- `GET /.well-known/ai-plugin.json` — OpenAI plugin manifest

## Deployment
- Docker containerized (see Dockerfile)
- Railway PaaS deployment (railway.toml)
- IMPORTANT: Dockerfile uses `${PORT}` env var for Railway compatibility
