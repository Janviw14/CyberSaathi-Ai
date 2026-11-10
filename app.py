import re
import ipaddress
from urllib.parse import urlparse, parse_qs, unquote
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # Reject unusually large requests.

# These are transparent heuristic rules, not a trained fraud model.
MESSAGE_RULES = [
    {
        "category": "OTP / PIN / password request",
        "points": 5,
        "patterns": [
            r"\b(share|send|tell|provide|enter|reveal)\b.{0,45}\b(otp|upi pin|pin|cvv|password)\b",
            r"\b(otp|upi pin|pin|cvv|password)\b.{0,45}\b(share|send|tell|provide|enter|reveal)\b",
            r"\b(otp|pin|cvv)\b.{0,35}(शेअर|सांगा|द्या|भरा|बताएं|भेजें|साझा)",
            r"(पासवर्ड|गुप्त नंबर).{0,25}(बताएं|भेजें|शेअर|द्या)"
        ],
        "explanation": "A legitimate bank or payment provider should not ask you to disclose an OTP, UPI PIN, CVV or password."
    },
    {
        "category": "Urgency or pressure",
        "points": 2,
        "patterns": [
            r"\b(urgent|immediately|right now|today|within minutes|act now|asap|last warning|final notice)\b",
            r"(तुरंत|तात्काळ|लगेच|आत्ताच|आजच|अंतिम सूचना)"
        ],
        "explanation": "Scammers often create panic so that you act before checking the request."
    },
    {
        "category": "Account or service threat",
        "points": 3,
        "patterns": [
            r"\b(account|bank|card|upi|wallet|sim)\b.{0,55}\b(blocked|suspended|deactivated|disabled|frozen|closed)\b",
            r"\b(blocked|suspended|deactivated|disabled|frozen)\b.{0,55}\b(account|bank|card|wallet)\b",
            r"(खाते|खातं|खाता|कार्ड).{0,25}(बंद|ब्लॉक|निलंबित|गोठवले)"
        ],
        "explanation": "A threat to block an account or service can be used to pressure you into clicking or sharing details."
    },
    {
        "category": "KYC / account verification pressure",
        "points": 3,
        "patterns": [
            r"\b(kyc|know your customer)\b.{0,60}\b(update|verify|complete|expire|expired|suspend)\b",
            r"\b(update|verify|complete)\b.{0,45}\bkyc\b",
            r"(केवायसी|केवाईसी|kyc).{0,45}(अपडेट|पूर्ण|सत्यापित|बंद)"
        ],
        "explanation": "Unexpected KYC links in messages should be verified using the institution's official app or website."
    },
    {
        "category": "Unexpected prize, lottery or refund",
        "points": 2,
        "patterns": [
            r"\b(lottery|prize|reward|winner|won|cashback|free gift|refund approved)\b",
            r"(लॉटरी|बक्षीस|इनाम|विजेता|कॅशबॅक|रिफंड)"
        ],
        "explanation": "Unexpected rewards or refunds can be used as bait to collect personal or payment information."
    },
    {
        "category": "Payment / money transfer pressure",
        "points": 3,
        "patterns": [
            r"\b(transfer|send|pay|deposit)\b.{0,50}\b(money|amount|rupees|rs\.?|inr|₹|fee)\b",
            r"\b(scan|pay)\b.{0,30}\b(qr|code)\b",
            r"(पैसे|रक्कम).{0,35}(पाठवा|भरा|ट्रान्सफर|जमा)"
        ],
        "explanation": "Do not transfer money or scan a payment QR because a message tells you to."
    },
    {
        "category": "Remote access / screen sharing",
        "points": 5,
        "patterns": [
            r"\b(anydesk|teamviewer|quick support|remote access|screen sharing|screen control)\b",
            r"(रिमोट अॅक्सेस|स्क्रीन शेअर)"
        ],
        "explanation": "Unsolicited requests to install remote-access apps or share your screen are high risk."
    },
    {
        "category": "Police / legal intimidation",
        "points": 5,
        "patterns": [
            r"\b(digital arrest|arrest warrant|police case|law enforcement|fedex parcel|customs case)\b",
            r"(डिजिटल अरेस्ट|अटक वॉरंट|पोलीस केस|गिरफ्तार)"
        ],
        "explanation": "Threats of 'digital arrest' or immediate legal action are common intimidation tactics. Verify independently."
    },
    {
        "category": "Link included",
        "points": 2,
        "patterns": [r"(https?://|www\.)\S+"],
        "explanation": "A link is present. Do not open it until you independently verify the sender and domain."
    },
    {
        "category": "Request for personal / identity information",
        "points": 3,
        "patterns": [
            r"\b(aadhaar|aadhar|pan card|date of birth|bank details|card number)\b.{0,50}\b(send|share|upload|submit|verify|provide)\b",
            r"\b(send|share|upload|submit|provide)\b.{0,50}\b(aadhaar|aadhar|pan card|date of birth|bank details|card number)\b",
            r"(आधार|पॅन कार्ड|पॅन|जन्मतारीख).{0,35}(पाठवा|शेअर|अपलोड|द्या)"
        ],
        "explanation": "The message may be trying to collect personal or identity information."
    }
]

GUIDANCE = {
    "en": "Never share OTPs, UPI PINs, CVVs or passwords. Do not click unexpected links or install remote-access apps. Verify using the official app, website or phone number you find independently.",
    "hi": "OTP, UPI PIN, CVV या पासवर्ड साझा न करें। अनजान लिंक न खोलें और रिमोट-एक्सेस ऐप इंस्टॉल न करें। आधिकारिक ऐप, वेबसाइट या स्वयं खोजे गए फोन नंबर से पुष्टि करें।",
    "mr": "OTP, UPI PIN, CVV किंवा पासवर्ड शेअर करू नका. अनोळखी लिंक उघडू नका किंवा रिमोट-अॅक्सेस अॅप इन्स्टॉल करू नका. अधिकृत अॅप, वेबसाइट किंवा स्वतः शोधलेल्या फोन नंबरवरून खात्री करा."
}

def analyze_message(message, language="en"):
    found, score = [], 0
    for rule in MESSAGE_RULES:
        if any(re.search(pattern, message, re.IGNORECASE) for pattern in rule["patterns"]):
            score += rule["points"]
            found.append({"category": rule["category"], "explanation": rule["explanation"]})
    risk = "High" if score >= 8 else "Medium" if score >= 4 else "Low"
    return {
        "risk": risk, "score": score, "signals": found,
        "guidance": GUIDANCE.get(language, GUIDANCE["en"]),
        "disclaimer": "Preliminary rule-based screening only. A high score does not prove fraud, and a low score does not prove safety. When in doubt, verify independently."
    }

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy", "shorturl.at"}
SUSPICIOUS_TLDS = {".zip", ".mov", ".top", ".click", ".work", ".support", ".country", ".gq", ".tk"}

def analyze_url(raw_url):
    value = raw_url.strip()
    if not re.match(r"^https?://", value, re.IGNORECASE):
        value = "https://" + value
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower().rstrip(".")
    flags = []
    if not host or "." not in host:
        flags.append("The address does not look like a complete public domain.")
    if parsed.username or parsed.password or "@" in parsed.netloc:
        flags.append("The address contains user-info or an @ sign, which can disguise the actual destination.")
    if host in SHORTENERS:
        flags.append("This is a URL-shortening service, so the final destination is hidden.")
    try:
        ipaddress.ip_address(host)
        flags.append("The link uses a raw IP address instead of a normal domain name.")
    except ValueError:
        pass
    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        flags.append("The domain uses a less-common top-level domain that deserves extra scrutiny.")
    if host.startswith("xn--") or ".xn--" in host:
        flags.append("The domain uses internationalized/punycode characters; check carefully for look-alike characters.")
    if parsed.scheme.lower() != "https":
        flags.append("The link does not use HTTPS. Do not enter sensitive information.")
    if len(host) > 45 or host.count("-") >= 3:
        flags.append("The domain is unusually long or contains several hyphens.")
    if not flags:
        flags.append("No basic structural warning was detected. This does not establish that the website is legitimate.")
    risk = "High" if len(flags) >= 3 else "Medium" if len(flags) >= 1 and flags[0] != "No basic structural warning was detected. This does not establish that the website is legitimate." else "Low"
    return {"risk": risk, "host": host or "Unrecognised", "signals": flags,
            "guidance": "Do not enter OTPs, UPI PINs, passwords or card details from a message link. Open the official app or type the known official address yourself.",
            "disclaimer": "CyberSaathi checks URL structure only. It does not visit the link, check live reputation or guarantee that a site is safe."}

def parse_upi(uri):
    parsed = urlparse(uri)
    if parsed.scheme.lower() != "upi" or parsed.netloc.lower() != "pay":
        return {"valid": False, "error": "This QR does not contain a recognised UPI payment URI."}
    q = parse_qs(parsed.query)
    fields = {k: (v[0] if v else "") for k, v in q.items()}
    return {"valid": True, "payee_name": unquote(fields.get("pn", "")),
            "upi_id": fields.get("pa", ""), "amount": fields.get("am", ""),
            "currency": fields.get("cu", "INR"), "note": unquote(fields.get("tn", "")),
            "warning": "Decoding only displays payment details. It does not verify the recipient. Check the payee name and UPI ID in your payment app before authorising. Never enter your UPI PIN to receive money."}

@app.get("/")
def home():
    return render_template("index.html", page="message")

@app.get("/message-checker")
def message_page():
    return render_template("message.html", page="message")

@app.get("/url-checker")
def url_page():
    return render_template("url.html", page="url")

@app.get("/upi-decoder")
def upi_page():
    return render_template("upi.html", page="upi")

@app.get("/report-fraud")
def report_page():
    return render_template("report.html", page="report")

@app.post("/api/message")
def message_api():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    lang = data.get("language", "en")
    if not isinstance(text, str) or not text.strip() or len(text) > 3000:
        return jsonify(error="Enter a message between 1 and 3,000 characters."), 400
    if lang not in ("en", "hi", "mr"):
        lang = "en"
    return jsonify(analyze_message(text.strip(), lang))

@app.post("/api/url")
def url_api():
    data = request.get_json(silent=True) or {}
    value = data.get("url", "")
    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        return jsonify(error="Enter a URL up to 2,048 characters."), 400
    return jsonify(analyze_url(value))

@app.post("/api/upi")
def upi_api():
    data = request.get_json(silent=True) or {}
    uri = data.get("uri", "")
    if not isinstance(uri, str) or len(uri) > 2048:
        return jsonify(error="Invalid QR content."), 400
    return jsonify(parse_upi(uri.strip()))

@app.errorhandler(413)
def too_large(_error):
    return jsonify(error="Request is too large."), 413

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
