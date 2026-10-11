# QRShield: QR Code Phishing and Scam Analyzer

Upload a QR image (or paste a link). QRShield decodes it, runs several checks and returns an
**explainable risk report**: a score from 0 to 100, plus plain-language reasons.

## Folder layout

```
qrshield/
├── backend/
│   ├── app/
│   │   ├── main.py              FastAPI routes, rate limiting
│   │   ├── config.py            settings from environment
│   │   ├── database.py          SQLite: history, feedback, API cache, stats
│   │   └── services/
│   │       ├── qr_decoder.py    OpenCV QR reading with several image passes
│   │       ├── url_analyzer.py  lexical checks (IP host, '@', punycode, keywords...)
│   │       ├── lookalike.py     brand imitation (typos, homoglyphs, brand in subdomain)
│   │       ├── domain_intel.py  WHOIS domain age and TLS certificate
│   │       ├── redirect_tracer.py  safe hop-by-hop redirect trace (SSRF-guarded)
│   │       ├── threat_intel.py  Google Safe Browsing, VirusTotal, URLhaus (optional keys)
│   │       ├── upi_parser.py    upi:// payment code analysis
│   │       ├── risk_engine.py   scoring, verdicts, advice
│   │       └── pipeline.py      runs everything and builds the report
│   ├── tests/test_analyzer.py
│   ├── requirements.txt
│   ├── .env.example
│   └── Dockerfile
└── frontend/                    React + Vite
    └── src/ (App.jsx, api.js, components/, styles.css)
```

## Run it locally

**Backend** (Python 3.10+)
```bash
cd backend
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                  # add API keys if you have them
uvicorn app.main:app --reload --port 8000
```
API docs: http://localhost:8000/docs

**Frontend** (Node 18+)
```bash
cd frontend
npm install
npm run dev
```
Open http://localhost:5173 (Vite proxies `/api` to the backend).

**Tests**
```bash
cd backend && pytest
```

## API keys (all optional)

| Variable | Where to get it |
|---|---|
| `GOOGLE_SAFE_BROWSING_KEY` | Google Cloud Console, enable the Safe Browsing API |
| `VIRUSTOTAL_API_KEY` | virustotal.com, free account (4 requests/min, results are cached 6 h) |
| `URLHAUS_AUTH_KEY` | auth.abuse.ch, free |

Without keys the app still works using URL, lookalike, domain-age, certificate and redirect checks.
Set `ENABLE_NETWORK_CHECKS=false` for a fully offline demo.

## How the score works

Each check returns findings with points. Points add up (cap 100):
**0-24 Low risk, 25-59 Suspicious, 60+ Dangerous.** A threat-feed hit alone is enough for Dangerous.
Examples: new domain (+30), brand lookalike (+22 to +40), raw IP (+25), 3+ redirects (+10), HTTP only (+10).

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/analyze/image` | multipart `file`, returns report |
| POST | `/api/analyze/url` | `{"url": "..."}`, returns report |
| GET | `/api/history`, `/api/scans/{id}` | past scans |
| POST | `/api/scans/{id}/feedback` | `{"helpful": true}` |
| GET | `/api/stats` | totals, level split, feedback, top warning signs |

## Security notes (mention these in your viva)

- **SSRF protection:** before every request and redirect hop, the hostname is resolved and rejected
  unless all addresses are public. Known gap: DNS rebinding between check and connect. In production,
  pin the resolved IP or run the tracer in an isolated egress-restricted container.
- Page bodies are never downloaded and no JavaScript is executed.
- Uploads are capped at 5 MB and 30 megapixels. Rate limit: 30 requests/min/IP.
- Wording is "risk indicators", never "definitely a scam".

## Deploy

- Backend: Render/Railway using `backend/Dockerfile`. Set `ALLOWED_ORIGINS` to your frontend URL.
- Frontend: Vercel/Netlify with `VITE_API_URL=https://your-backend-url`, build `npm run build`.
- SQLite is fine for a demo. For persistence on hosted platforms attach a disk or switch to Postgres.

## Ideas to extend

1. Train a phishing-URL classifier (Kaggle datasets) and show it next to the rule score.
2. Add a "Why is this risky?" chat box that explains the report using an LLM.
3. Evaluate on 100 labelled URLs and report precision/recall in your project report.
4. Browser camera scanning with the `BarcodeDetector` API or `jsQR`.
