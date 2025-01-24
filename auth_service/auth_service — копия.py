from flask import Flask, request, jsonify
import requests
from prometheus_client import Counter, generate_latest, start_http_server

print('STARTED')

app = Flask(__name__)

TRAFFIC_ANALYZER_URL = "http://traffic-analyzer:4000/monitor"

# Пользователи и пароли
USERS = {
    "admin": "securepass",
    "user1": "mypassword"
}

# Метрики Prometheus
TOTAL_AUTH_REQUESTS = Counter('auth_service_total_requests', 'Total number of authentication requests')
SUCCESSFUL_AUTH_REQUESTS = Counter('auth_service_successful_requests', 'Number of successful authentications')
FAILED_AUTH_REQUESTS = Counter('auth_service_failed_requests', 'Number of failed authentications')

def check_credentials(username, password):
    """
    Проверяет, соответствуют ли логин и пароль пользователю.
    """
    if username in USERS and USERS[username] == password:
        return True
    return False

@app.route("/auth", methods=["POST"])
def authenticate():
    TOTAL_AUTH_REQUESTS.inc()  # Увеличиваем общий счетчик запросов
    try:
        # Получение данных из запроса
        data = request.json
        if not data:
            FAILED_AUTH_REQUESTS.inc()  # Неудачная аутентификация
            return jsonify({"status": "fail", "message": "No JSON data received"}), 400

        username = data.get("username")
        password = data.get("password")
        ip = data.get("ip")
        path = data.get("path")

        # Проверяем обязательные поля
        if not all([username, password, ip, path]):
            FAILED_AUTH_REQUESTS.inc()  # Неудачная аутентификация
            return jsonify({"status": "fail", "message": "Missing required fields"}), 400

        # Проверка учетных данных
        if not check_credentials(username, password):
            FAILED_AUTH_REQUESTS.inc()  # Неудачная аутентификация
            return jsonify({"status": "fail", "message": "Invalid credentials"}), 401

        # Отправка данных в traffic-analyzer
        try:
            traffic_response = requests.post(
                TRAFFIC_ANALYZER_URL,
                json={"ip": ip, "path": path}
            )
            if traffic_response.status_code == 403:
                FAILED_AUTH_REQUESTS.inc()  # Неудачная аутентификация из-за подозрительного трафика
                return jsonify({
                    "status": "fail",
                    "message": "Traffic flagged as suspicious",
                    "details": traffic_response.json()
                }), 403
            elif traffic_response.status_code == 200:
                SUCCESSFUL_AUTH_REQUESTS.inc()  # Успешная аутентификация
                return jsonify({
                    "status": "success",
                    "message": "Authentication and traffic analysis successful"
                }), 200
            else:
                FAILED_AUTH_REQUESTS.inc()  # Неудачная аутентификация из-за ошибки traffic-analyzer
                return jsonify({
                    "status": "fail",
                    "message": "Unexpected response from traffic analyzer",
                    "details": traffic_response.text
                }), 500
        except Exception as e:
            FAILED_AUTH_REQUESTS.inc()  # Неудачная аутентификация из-за ошибки связи
            return jsonify({"status": "fail", "message": f"Error communicating with traffic analyzer: {str(e)}"}), 500

    except Exception as e:
        FAILED_AUTH_REQUESTS.inc()  # Неудачная аутентификация из-за ошибки сервера
        return jsonify({"status": "fail", "message": f"Error: {str(e)}"}), 500

@app.route("/metrics")
def metrics():
    return generate_latest(), 200

if __name__ == "__main__":
    print('hello world')
    start_http_server(8001)  # Эндпоинт для метрик доступен на порту 8001
    app.run(host="0.0.0.0", port=5000)
