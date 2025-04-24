from flask import Flask, render_template, request
import psutil, requests, socket

app = Flask(__name__)

def get_system_info():
    return {
        "cpu": psutil.cpu_percent(),
        "ram": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage('/').percent,
        "uptime": psutil.boot_time()
    }

def basic_scan(domain):
    results = {}
    score = 100
    recommendations = []
    try:
        ip = socket.gethostbyname(domain)
        results['ip'] = ip
        response = requests.get(f"http://{domain}", timeout=5, allow_redirects=False)
        results['status'] = response.status_code
        headers = response.headers
        results['headers'] = "\n".join([f"{key}: {value}" for key, value in headers.items()])

        # Security Checks Start Here

        # 1. Check for X-Frame-Options
        if 'X-Frame-Options' not in headers:
            results['x_frame_options'] = 'Missing'
            score -= 15  # Assign weight
            recommendations.append("Consider adding the 'X-Frame-Options' header to protect against clickjacking.")
        else:
            results['x_frame_options'] = headers['X-Frame-Options']

        # 2. Check for Content-Security-Policy (CSP)
        if 'Content-Security-Policy' not in headers:
            results['content_security_policy'] = 'Missing'
            score -= 20  # Assign weight
            recommendations.append("Implement a 'Content-Security-Policy' header to mitigate XSS attacks.")
        else:
            results['content_security_policy'] = 'Present' # You can show the actual policy if needed

        # 3. Check for Strict-Transport-Security (HSTS)
        if 'Strict-Transport-Security' not in headers:
            results['strict_transport_security'] = 'Missing'
            score -= 25  # Assign higher weight
            recommendations.append("Enable 'Strict-Transport-Security' (HSTS) to enforce HTTPS.")
        else:
            results['strict_transport_security'] = headers['Strict-Transport-Security']

        # 4. Check for X-Content-Type-Options
        if 'X-Content-Type-Options' not in headers or headers['X-Content-Type-Options'] != 'nosniff':
            results['x_content_type_options'] = headers.get('X-Content-Type-Options', 'Missing or not nosniff')
            score -= 10  # Assign weight
            recommendations.append("Add 'X-Content-Type-Options: nosniff' to prevent MIME sniffing attacks.")
        else:
            results['x_content_type_options'] = 'nosniff'

        results['score'] = max(0, score) # Ensure score doesn't go below 0
        results['recommendations'] = recommendations
        return results
    except socket.gaierror:
        return {"error": f"Could not resolve domain: {domain}"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {e}"}

@app.route("/", methods=["GET", "POST"])
def index():
    result = {}
    sysinfo = get_system_info()
    if request.method == "POST":
        domain = request.form.get("domain")
        result = basic_scan(domain)
    return render_template("index.html", result=result, sysinfo=sysinfo)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)