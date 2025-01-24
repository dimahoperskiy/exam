from flask import Flask, request, jsonify
from prometheus_client import Counter, generate_latest, start_http_server

app = Flask(__name__)

BLOCKED_IPS = []
BLOCKED_IP_COUNT = Counter('firewall_service_blocked_ips', 'Number of blocked IPs', ['reason'])

@app.route("/block", methods=["POST"])
def block_ip():
    data = request.json
    ip = data.get("ip")
    reason = data.get("reason")

    if ip not in BLOCKED_IPS:
        BLOCKED_IPS.append(ip)
        BLOCKED_IP_COUNT.labels(reason=reason).inc()
        return jsonify({"status": "success", "message": f"IP {ip} заблокирован"}), 200
    return jsonify({"status": "fail", "message": f"IP {ip} уже заблокирован"}), 400

@app.route("/metrics")
def metrics():
    return generate_latest(), 200

if __name__ == "__main__":
    start_http_server(8001)
    app.run(host="0.0.0.0", port=3000)