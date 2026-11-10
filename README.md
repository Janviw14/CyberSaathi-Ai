# CyberSaathi AI – Identify Cyber Frauds

A beginner-friendly Flask prototype with separate pages for:
- Message checker
- URL checker
- UPI QR decoder
- Financial cyber fraud reporting guidance

## Run locally
1. Install Python 3.10 or newer.
2. Open a terminal in this project folder.
3. Create and activate a virtual environment (recommended):
   - Windows: `py -m venv .venv` then `.venv\\Scripts\\activate`
   - macOS/Linux: `python3 -m venv .venv` then `source .venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Start: `python app.py`
6. Open http://127.0.0.1:5000

## Important limitations
- Message and URL checks use transparent heuristics, not machine learning or a threat-intelligence feed. Scores are not probabilities and must be tested against legitimate and malicious samples.
- URL checker does not visit links or verify domain reputation. Do not add server-side URL fetching without SSRF protections.
- UPI QR decoding reads the encoded payment URI only. It cannot validate the payee or prove that a payment request is legitimate.
- Camera QR scanning depends on browser support for `BarcodeDetector`, camera permission and a secure context (localhost is generally permitted).
- The language selector currently translates the navigation and sends the selected language to message-checker guidance. Full translation of every page is a future improvement.
- Reporting steps and 1930 / cybercrime.gov.in are official-channel signposts; this app does not submit a complaint on the user's behalf.

## Privacy and production checklist
This prototype does not intentionally store submitted message text, URLs or QR content. Do not add logging of sensitive submissions. Before public launch, add HTTPS, CSRF protection where applicable, security headers, robust input validation, automated tests, accessible translations, production server configuration, monitoring and a privacy notice. Have the security and legal workflow independently reviewed. Never claim that a message or website is safe based only on a low-risk score.
