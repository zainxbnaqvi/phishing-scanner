from flask import Flask, render_template, request
import re
from urllib.parse import urlparse

app = Flask(__name__)

def check_phishing(url):
    """Scans the URL and returns the status, color, and red flags."""
    # Normalize the URL for the parser if the user forgot 'http'
    if not url.startswith('http'):
        url_for_parsing = 'http://' + url
    else:
        url_for_parsing = url

    parsed = urlparse(url_for_parsing)
    score = 0
    red_flags = []

    # 1. Check for IP address in the domain
    if re.search(r'\d+\.\d+\.\d+\.\d+', parsed.netloc):
        score += 3
        red_flags.append("Uses an IP address instead of a domain name.")
        
    # 2. Check for the '@' symbol trick
    if '@' in url:
        score += 3
        red_flags.append("Contains '@' symbol (often used to mask the real destination).")
    
    # 3. Check for suspicious keywords (Expanded List)
    suspicious_words = [
        'login', 'verify', 'update', 'secure', 'bank', 'account', 'signin',
        'auth', 'password', 'credential', 'support', 'billing', 'invoice',
        'wallet', 'free', 'gift', 'prize', 'urgent', 'action-required',
        'customer-service', 'admin', 'pay', 'confirm'
    ]
    found_words = [word for word in suspicious_words if word in url.lower()]
    if found_words:
        score += 2
        red_flags.append(f"Contains suspicious keywords: {', '.join(found_words)}")

    # 4. Check for URL shorteners
    shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd']
    if any(shortener in parsed.netloc.lower() for shortener in shorteners):
        score += 2
        red_flags.append("Uses a URL shortener (often used to hide malicious links).")
    
    # 5. Check URL length
    if len(url) > 75:
        score += 1
        red_flags.append("URL is unusually long (common in phishing).")
        
    # 6. Check for HTTPS
    if url.startswith('http://'):
        score += 1
        red_flags.append("Uses unencrypted HTTP instead of secure HTTPS.")

    # Determine Safety Status
    if score == 0:
        return "SAFE", "#2ecc71", red_flags
    elif score <= 2:
        return "SUSPICIOUS", "#f1c40f", red_flags
    else:
        return "PHISHING RISK", "#e74c3c", red_flags

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    if request.method == "POST":
        url = request.form.get("url_input").strip()
        if url:
            status, color, flags = check_phishing(url)
            result = {
                "url": url,
                "status": status,
                "color": color,
                "flags": flags
            }
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)