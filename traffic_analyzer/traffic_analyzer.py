import datetime
from flask import Flask, jsonify, request
import requests
from collections import defaultdict
from prometheus_client import Counter, generate_latest, start_http_server

app = Flask(__name__)

# Логи трафика
TRAFFIC_LOG = defaultdict(list)
VULNERABLE_PATHS = ["/admin", "/phpmyadmin", "/.env", "/etc/passwd"]
FIREWALL_SERVICE_URL = "http://firewall-service:3000/block"
MAX_REQUESTS = 20
MONITORING_WINDOW = 10  # в секундах

# Метрики Prometheus
TOTAL_REQUESTS = Counter('traffic_analyzer_total_requests', 'Total number of requests to traffic analyzer')
VULNERABLE_PATH_REQUESTS = Counter('traffic_analyzer_vulnerable_path_requests', 'Requests to vulnerable paths')
SUSPICIOUS_REQUESTS = Counter('traffic_analyzer_suspicious_requests', 'Number of suspicious requests detected')

@app.route("/monitor", methods=["POST"])
def monitor_traffic():
    """
    Анализирует запросы и отправляет данные в firewall_service при обнаружении угрозы.
    """
    TOTAL_REQUESTS.inc()  # Увеличиваем общий счетчик запросов
    data = request.json
    ip = data.get("ip")
    path = data.get("path")
    timestamp = datetime.datetime.now()

    # Логируем запрос
    TRAFFIC_LOG[ip].append({"path": path, "timestamp": timestamp})

    # Удаляем старые записи
    TRAFFIC_LOG[ip] = [
        entry for entry in TRAFFIC_LOG[ip]
        if (timestamp - entry["timestamp"]).total_seconds() <= MONITORING_WINDOW
    ]

    # Проверка на сканирование портов
    if len(TRAFFIC_LOG[ip]) > MAX_REQUESTS:
        SUSPICIOUS_REQUESTS.inc()  # Увеличиваем счетчик подозрительных запросов
        block_ip(ip, "Port scanning detected")
        return jsonify({"status": "alert", "message": "Port scanning detected", "ip": ip}), 403

    # Проверка на доступ к уязвимым путям
    if path in VULNERABLE_PATHS:
        VULNERABLE_PATH_REQUESTS.inc()  # Увеличиваем счетчик запросов к уязвимым путям
        block_ip(ip, f"Access to vulnerable path {path}")
        return jsonify({"status": "alert", "message": f"Access to vulnerable path {path}", "ip": ip}), 403

    return jsonify({"status": "ok", "message": "Traffic is clean"}), 200


def block_ip(ip, reason):
    """
    Отправка запроса на блокировку IP в firewall_service.
    """
    try:
        requests.post(FIREWALL_SERVICE_URL, json={"ip": ip, "reason": reason})
    except Exception as e:
        print(f"Error communicating with firewall_service: {e}")


@app.route("/metrics")
def metrics():
    """
    Возвращает метрики для Prometheus.
    """
    return generate_latest(), 200


if __name__ == "__main__":
    start_http_server(8001)  # Эндпоинт для метрик
    app.run(host="0.0.0.0", port=4000)
