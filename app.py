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
    try:
        ip = socket.gethostbyname(domain)
        response = requests.get(f"http://{domain}", timeout=5)
        headers = response.headers
        return {"ip": ip, "headers": headers, "status": response.status_code}
    except:
        return {"error": "Scan failed"}

@app.route("/", methods=["GET", "POST"])
def index():
    result = {}
    sysinfo = get_system_info()
    if request.method == "POST":
        domain = request.form.get("domain")
        result = basic_scan(domain)
    return render_template("index.html", result=result, sysinfo=sysinfo)

if __name__ == "__main__":
<<<<<<< HEAD
    app.run(host='0.0.0.0', port=5000, debug=True)
=======
    app.run(host='0.0.0.0', port=5000, debug=True)
>>>>>>> 65c6854864a27f4583fa48138921bf1c49434c66
